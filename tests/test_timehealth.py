# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U1/U2: drift within a boot, steps by class, boundaries never crossed."""
from __future__ import annotations

import pytest
from palimpsests.audit.pala.codec import (
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    TIME_UNSYNCED,
    ZERO32,
    Header,
    record_hash,
)
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.timehealth import (
    STEP_THRESHOLD_NS,
    drift_series,
    step_catalog,
)

BOOT_A = b"\x0a" * 16
BOOT_B = b"\x0b" * 16
MS = 1_000_000
S = 1_000_000_000


def _write(tmp_path, rows):
    """rows: (record_type, boot_id, mono, wall). seq is positional."""
    headers, prev = [], ZERO32
    for seq, (rtype, boot, mono, wall) in enumerate(rows):
        hb = Header(
            record_type=rtype, seq=seq, boot_id=boot, prev_hash=prev,
            time_trust=TIME_UNSYNCED, monotonic_ns=mono, wall_clock_ns=wall,
        ).encode()
        headers.append(hb)
        prev = record_hash(hb)
    path = tmp_path / "t.pala"
    path.write_bytes(b"".join(headers))
    return path


def test_drift_slope_and_boot_isolation(tmp_path):
    # boot A: wall runs 100 ppm fast; boot B: perfect clock.
    rows = [(RT_GENESIS, BOOT_A, 0, 10 * S)]
    for i in range(1, 5):
        mono = i * S
        rows.append((RT_EVENT, BOOT_A, mono, 10 * S + mono + mono // 10_000))
    rows.append((RT_BOOT, BOOT_B, 0, 20 * S))
    rows.append((RT_EVENT, BOOT_B, S, 21 * S))
    path = _write(tmp_path, rows)

    with AuditReader.open(path) as reader:
        series = drift_series(reader)
    assert [s.boot_id for s in series] == [BOOT_A, BOOT_B]
    a, b = series
    assert a.slope_ppm == pytest.approx(100.0, rel=0.01)
    assert b.slope_ppm == pytest.approx(0.0, abs=0.01)
    assert a.points[0].offset_ns == 0  # baseline is the boot's own first claim
    assert "UNSYNCED" in a.time_trusts  # labelled, never hidden


def test_step_catalog_classes(tmp_path):
    rows = [
        (RT_GENESIS, BOOT_A, 0, 10 * S),
        (RT_EVENT, BOOT_A, 1 * S, 11 * S + 500 * MS),  # +500ms jump → step
        (RT_EVENT, BOOT_A, 2 * S, 11 * S),  # wall moved BACK → regression
    ]
    # a slew: forty +5ms corrections, each far below the threshold,
    # summing to +200ms — one slew entry, not forty
    wall = 11 * S
    for i in range(40):
        mono = (3 + i) * S
        wall += S + 5 * MS
        rows.append((RT_EVENT, BOOT_A, mono, wall))
    path = _write(tmp_path, rows)

    with AuditReader.open(path) as reader:
        steps = step_catalog(reader)
    kinds = [s.kind for s in steps]
    assert kinds == ["step", "regression", "slew"]
    step, regression, slew = steps
    assert step.delta_ns == 500 * MS
    assert regression.delta_ns < 0  # signed: backwards
    assert abs(slew.delta_ns) >= STEP_THRESHOLD_NS
    assert slew.seq > regression.seq > step.seq


def test_no_wall_claims_yields_empty_but_labelled_series(tmp_path):
    rows = [
        (RT_GENESIS, BOOT_A, 0, 0),
        (RT_EVENT, BOOT_A, S, 0),
    ]
    path = _write(tmp_path, rows)
    with AuditReader.open(path) as reader:
        series = drift_series(reader)
        assert step_catalog(reader) == []
    (only,) = series
    assert only.points == [] and only.slope_ppm is None
