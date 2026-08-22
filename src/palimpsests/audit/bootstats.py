# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U3 — per-boot statistics: the operational shape of a chain.

The record-health trio's third product, per the track rule: advisory
analytics over what is already in the headers, never verdict inputs.

Each ``BootStats`` *contains* its ``BootView`` — one structure per
boot, no joining two lists by ``boot_id`` — and adds what an operator
or an assessor actually asks: how long did it run, how densely was it
anchored, how did sessions behave.

**Anchor cadence is first-class, not a derived number,** because it
converts directly into the tier argument: a record's "existed by" claim
can never be narrower than the gap between the anchor writes around it,
so ``widest_anchor_gap_ns`` IS the honest answer to "how wide would
your existed-by brackets be" — including the two edge gaps (boot start
to first anchor, last anchor to boot end), where the bracket is widest
exactly when nobody was looking.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from palimpsests.audit.pala.codec import RT_ANCHOR, RT_SPAN_END, RT_SPAN_START
from palimpsests.audit.reader import BootView
from statistics import median


@dataclass(frozen=True)
class AnchorCadence:
    count: int
    #: gaps between consecutive anchor events in this boot, INCLUDING the
    #: edge gaps (boot start → first anchor, last anchor → boot end),
    #: measured on the monotonic clock. Empty when the boot has no anchor.
    gaps_ns: list[int]
    widest_anchor_gap_ns: int | None  # the tier-C bracket width


@dataclass(frozen=True)
class SpanStats:
    closed: int
    open: int  # visibly unclosed — §3.1 evidence, not error
    open_rate: float | None  # None with zero spans
    median_duration_ns: int | None  # over closed spans only


@dataclass(frozen=True)
class BootStats:
    view: BootView
    uptime_ns: int  # monotonic span of the boot's records
    anchors: AnchorCadence
    spans: SpanStats


def _per_boot_rows(reader):
    """Consecutive same-boot runs of (seq, mono, record_type, span_id)."""
    current: bytes | None = None
    rows: list[tuple[int, int, int, bytes]] = []
    for hb in reader._headers:
        boot_id = bytes(hb[20:36])
        (seq,) = struct.unpack_from("<Q", hb, 12)
        (rtype,) = struct.unpack_from("<H", hb, 8)
        (mono,) = struct.unpack_from("<Q", hb, 100)
        span_id = bytes(hb[68:84])
        if boot_id != current:
            if rows:
                yield current, rows
            current, rows = boot_id, []
        rows.append((seq, mono, rtype, span_id))
    if rows:
        yield current, rows


def boot_statistics(reader) -> list[BootStats]:
    """Per-boot operational statistics, one entry per ``reader.boots()``."""
    views = {v.boot_id: v for v in reader.boots()}
    out: list[BootStats] = []
    for boot_id, rows in _per_boot_rows(reader):
        view = views.get(boot_id)
        if view is None:  # a boot the reader's own view did not surface
            continue
        monos = [mono for _s, mono, _t, _sp in rows]
        uptime = max(monos) - min(monos)

        anchor_monos = [m for _s, m, t, _sp in rows if t == RT_ANCHOR]
        if anchor_monos:
            fence = [min(monos), *anchor_monos, max(monos)]
            gaps = [b - a for a, b in zip(fence, fence[1:], strict=False)]
            cadence = AnchorCadence(
                count=len(anchor_monos), gaps_ns=gaps,
                widest_anchor_gap_ns=max(gaps),
            )
        else:
            cadence = AnchorCadence(count=0, gaps_ns=[], widest_anchor_gap_ns=None)

        starts: dict[bytes, int] = {}
        durations: list[int] = []
        open_count = 0
        for _seq, mono, rtype, span_id in rows:
            if rtype == RT_SPAN_START:
                starts[span_id] = mono
            elif rtype == RT_SPAN_END and span_id in starts:
                durations.append(mono - starts.pop(span_id))
        open_count = len(starts)
        total = open_count + len(durations)
        spans = SpanStats(
            closed=len(durations),
            open=open_count,
            open_rate=(open_count / total) if total else None,
            median_duration_ns=int(median(durations)) if durations else None,
        )
        out.append(BootStats(view=view, uptime_ns=uptime, anchors=cadence, spans=spans))
    return out
