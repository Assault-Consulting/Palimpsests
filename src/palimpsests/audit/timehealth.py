# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U1/U2 — time health: drift series and the step catalog.

Advisory analytics over header fields already present — never verdict
inputs, per the track rule. Two products, one walk:

**Drift series (U1).** Per boot, for every record that makes a wall
claim: ``d_i = (wall_i − wall_0) − (mono_i − mono_0)`` — how far the
wall clock has wandered from the monotonic clock since the boot's first
claim — plus a least-squares slope in ppm, the clock-quality
fingerprint. Two rules stated because they are easy to get wrong: drift
is only meaningful *within* one boot (``monotonic_ns`` resets), so a
series never crosses a boot boundary; and ``time_trust`` qualifies the
whole series — a boot marked UNSYNCED yields a drift figure describing
a clock nobody claimed was right, which is worth computing and worth
labelling, never worth hiding.

**Step catalog (U2).** Each discontinuity with magnitude, direction,
seq and a class: ``step`` (a jump in either direction), ``regression``
(the wall clock moved backwards — the one an auditor cares about), and
``slew`` (a gradual correction absorbed over many records: a run of
sub-threshold deltas whose sum crosses the threshold).

The step threshold is 128 ms — a stated constant with a stated reason,
not a tuned number: ntpd steps the clock outright when the offset
exceeds 128 ms and slews below it, so a wall jump of at least that size
between adjacent records is a genuine clock event, not a correction in
progress.

**The ``wall_regression_in_boot`` decision (the plan demanded one).**
The existing verifier advisory STAYS: it is the verify-time flag — no
magnitude, always on, part of the verification surface. The catalog's
``regression`` entries are the analytic refinement of the same event —
magnitude, direction, neighbours — for a consumer drawing charts. One
event, two layers, two jobs; the catalog does not emit into the
advisory stream and the advisory does not grow analytics.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from palimpsests.audit.names import time_trust_name

#: ntpd steps the clock when the offset exceeds 128 ms and slews below
#: it; a wall jump of at least this size between adjacent records is a
#: clock event, not a correction in progress.
STEP_THRESHOLD_NS = 128_000_000


@dataclass(frozen=True)
class DriftPoint:
    seq: int
    offset_ns: int  # d_i


@dataclass(frozen=True)
class BootDrift:
    boot_id: bytes
    time_trusts: tuple[str, ...]  # every trust name seen in the boot
    points: list[DriftPoint]
    slope_ppm: float | None  # None with fewer than two points


@dataclass(frozen=True)
class TimeStep:
    boot_id: bytes
    seq: int
    kind: str  # "step" | "regression" | "slew"
    delta_ns: int  # signed magnitude of the event


def _walk(reader):
    """(boot_id, seq, mono, wall, trust) per record, in file order."""
    for hb in reader._headers:
        (seq,) = struct.unpack_from("<Q", hb, 12)
        boot_id = bytes(hb[20:36])
        (mono,) = struct.unpack_from("<Q", hb, 100)
        (wall,) = struct.unpack_from("<q", hb, 108)
        trust = hb[11]
        yield boot_id, seq, mono, wall, trust


def _boots(reader):
    """Group the walk into consecutive same-boot runs (order preserved)."""
    current: bytes | None = None
    rows: list[tuple[int, int, int, int]] = []
    for boot_id, seq, mono, wall, trust in _walk(reader):
        if boot_id != current:
            if rows:
                yield current, rows
            current, rows = boot_id, []
        rows.append((seq, mono, wall, trust))
    if rows:
        yield current, rows


def drift_series(reader) -> list[BootDrift]:
    """The U1 product: per-boot drift points and a slope fingerprint."""
    out: list[BootDrift] = []
    for boot_id, rows in _boots(reader):
        trusts = tuple(
            sorted({time_trust_name(t) or str(t) for _, _, _, t in rows})
        )
        claims = [(seq, mono, wall) for seq, mono, wall, _t in rows if wall != 0]
        if not claims:
            out.append(BootDrift(boot_id, trusts, [], None))
            continue
        _seq0, mono0, wall0 = claims[0]
        points = [
            DriftPoint(seq, (wall - wall0) - (mono - mono0))
            for seq, mono, wall in claims
        ]
        slope = None
        if len(points) >= 2:
            xs = [mono - mono0 for _s, mono, _w in claims]
            ys = [p.offset_ns for p in points]
            n = len(xs)
            mx, my = sum(xs) / n, sum(ys) / n
            var = sum((x - mx) ** 2 for x in xs)
            if var > 0:
                slope = (
                    sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
                    / var
                    * 1e6
                )  # ns of drift per ns of uptime → ppm
        out.append(BootDrift(boot_id, trusts, points, slope))
    return out


def step_catalog(reader) -> list[TimeStep]:
    """The U2 product: discontinuities classed step / regression / slew."""
    out: list[TimeStep] = []
    for boot_id, rows in _boots(reader):
        claims = [(seq, mono, wall) for seq, mono, wall, _t in rows if wall != 0]
        if len(claims) < 2:
            continue
        slew_sum = 0
        slew_seq: int | None = None
        _, prev_mono, prev_wall = claims[0]
        for seq, mono, wall in claims[1:]:
            jump = (wall - prev_wall) - (mono - prev_mono)
            if wall < prev_wall:
                out.append(TimeStep(boot_id, seq, "regression", wall - prev_wall))
                slew_sum, slew_seq = 0, None
            elif abs(jump) >= STEP_THRESHOLD_NS:
                out.append(TimeStep(boot_id, seq, "step", jump))
                slew_sum, slew_seq = 0, None
            elif jump != 0:
                slew_sum += jump
                slew_seq = seq
                if abs(slew_sum) >= STEP_THRESHOLD_NS:
                    out.append(TimeStep(boot_id, slew_seq, "slew", slew_sum))
                    slew_sum, slew_seq = 0, None
            prev_mono, prev_wall = mono, wall
    return out
