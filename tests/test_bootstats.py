# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U3: one structure per boot; the anchor bracket is first-class."""
from __future__ import annotations

from palimpsests.audit.bootstats import boot_statistics
from palimpsests.audit.pala.codec import (
    RT_ANCHOR,
    RT_EVENT,
    RT_GENESIS,
    RT_SPAN_END,
    RT_SPAN_START,
    ZERO16,
    ZERO32,
    Header,
    record_hash,
)
from palimpsests.audit.reader import AuditReader

BOOT = b"\x0a" * 16
SPAN_1 = b"\x01" * 16
SPAN_2 = b"\x02" * 16
S = 1_000_000_000


def _write(tmp_path, rows):
    headers, prev = [], ZERO32
    for seq, (rtype, mono, span) in enumerate(rows):
        hb = Header(
            record_type=rtype, seq=seq, boot_id=BOOT, prev_hash=prev,
            span_id=span, monotonic_ns=mono,
        ).encode()
        headers.append(hb)
        prev = record_hash(hb)
    path = tmp_path / "t.pala"
    path.write_bytes(b"".join(headers))
    return path


def test_uptime_anchors_and_spans(tmp_path):
    rows = [
        (RT_GENESIS, 0, ZERO16),
        (RT_SPAN_START, 1 * S, SPAN_1),
        (RT_ANCHOR, 2 * S, ZERO16),      # edge gap start→anchor: 2s
        (RT_SPAN_END, 3 * S, SPAN_1),    # closed span: 2s
        (RT_SPAN_START, 4 * S, SPAN_2),  # stays open — the evidence
        (RT_ANCHOR, 5 * S, ZERO16),      # anchor→anchor: 3s
        (RT_EVENT, 10 * S, ZERO16),      # edge gap anchor→end: 5s ← widest
    ]
    path = _write(tmp_path, rows)
    with AuditReader.open(path) as reader:
        (stats,) = boot_statistics(reader)

    assert stats.view.boot_id == BOOT
    assert stats.view.record_count == 7  # the contained BootView, no join
    assert stats.uptime_ns == 10 * S

    assert stats.anchors.count == 2
    assert stats.anchors.gaps_ns == [2 * S, 3 * S, 5 * S]  # edges included
    assert stats.anchors.widest_anchor_gap_ns == 5 * S  # the tier bracket

    assert stats.spans.closed == 1 and stats.spans.open == 1
    assert stats.spans.open_rate == 0.5
    assert stats.spans.median_duration_ns == 2 * S


def test_no_anchors_is_an_honest_none_not_zero(tmp_path):
    rows = [(RT_GENESIS, 0, ZERO16), (RT_EVENT, 1 * S, ZERO16)]
    path = _write(tmp_path, rows)
    with AuditReader.open(path) as reader:
        (stats,) = boot_statistics(reader)
    assert stats.anchors.count == 0
    assert stats.anchors.widest_anchor_gap_ns is None  # unbounded, not 0
    assert stats.spans.open_rate is None  # no spans at all
