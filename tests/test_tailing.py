# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""TailingReader: the live event stream, and live ≡ batch.

Drives ``_drain()`` directly — the deterministic pump the blocking
``events()`` loop wraps — so the reasons a tail moves (growth, a pending
partial, a torn-tail resume, a rollback) are each exercised without threads
or real sleeps. ``snapshot()`` is asserted equal to opening the same bytes
with ``AuditReader``: live and batch share one verifier, so they must agree.
"""

from __future__ import annotations

from itertools import islice
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.tailing import TailingReader


def _kinds(events):
    return [e.kind for e in events]


def _start(log) -> PalaWriter:
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    return w


# --------------------------------------------------------------------------- #
# Growth, anchor_seen, and live ≡ batch
# --------------------------------------------------------------------------- #


def test_growth_streams_records(tmp_path):
    log = tmp_path / "grow.pala"
    w = _start(log)
    tr = TailingReader(log)
    first = tr._drain()
    assert _kinds(first) == ["record", "record"]  # genesis, boot
    assert [e.seq for e in first] == [0, 1]

    span = w.session_start("s")
    w.prefix_copy(8, span_id=span)
    second = tr._drain()
    assert [e.seq for e in second if e.kind == "record"] == [2, 3]
    w.close()
    tr.close()


def test_anchor_seen_on_anchor_record(tmp_path):
    log = tmp_path / "anch.pala"
    w = _start(log)
    w.anchor()
    events = TailingReader(log)._drain()
    assert "anchor_seen" in _kinds(events)
    anchor_ev = next(e for e in events if e.kind == "anchor_seen")
    assert anchor_ev.record.type_name == "ANCHOR"
    w.close()


def test_snapshot_equals_batch(tmp_path):
    log = tmp_path / "snap.pala"
    w = _start(log)
    span = w.session_start("s")
    w.prefix_copy(16, span_id=span)
    w.session_end(span)
    w.anchor()
    w.close()

    tr = TailingReader(log)
    tr._drain()
    snap = tr.snapshot()
    batch = AuditReader.open(log).verify()
    assert snap.chain == batch.chain
    assert snap.chain.chain_ok is True
    tr.close()


def test_events_generator_yields_records(tmp_path):
    log = tmp_path / "gen.pala"
    w = _start(log)
    w.close()
    tr = TailingReader(log, poll_interval=0)
    got = list(islice(tr.events(), 2))  # genesis, boot
    assert _kinds(got) == ["record", "record"]
    tr.close()


# --------------------------------------------------------------------------- #
# Pending tail and the torn-tail diagnosis
# --------------------------------------------------------------------------- #


def test_pending_tail_then_truncated_diagnosis(tmp_path):
    log = tmp_path / "torn.pala"
    w = _start(log)
    w.close()
    tr = TailingReader(log, torn_grace=0)
    tr._drain()  # consume the two complete records

    # Append a partial record: a live writer caught mid-write.
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)

    assert "pending_tail" in _kinds(tr._drain())
    # It stops growing; with torn_grace=0 the next assessment diagnoses it.
    assert "diagnosis" in _kinds(tr._drain())


# --------------------------------------------------------------------------- #
# Shrink: a resume (recoverable) vs a rollback (the real alarm)
# --------------------------------------------------------------------------- #


def test_shrink_within_pending_recovers(tmp_path):
    log = tmp_path / "resume.pala"
    w = _start(log)
    w.session_start("s")  # a complete record, span left open
    w.close()
    tr = TailingReader(log, torn_grace=99)
    tr._drain()  # verify genesis, boot, span_start

    # A torn partial record at the tail, then a resume that truncates it.
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)
    assert "pending_tail" in _kinds(tr._drain())

    w2 = PalaWriter.open_existing(log)  # truncates the 24 torn bytes on open
    assert "shrunk" in _kinds(tr._drain())

    w2.boot()
    w2.recovery_truncated_tail()
    w2.close()
    after = tr._drain()
    assert "recovered" in _kinds(after)
    # The verifier was never invalidated: the verified prefix still checks.
    assert tr.snapshot().chain.chain_ok is True
    tr.close()


def test_shrink_below_verified_is_rollback(tmp_path):
    log = tmp_path / "roll.pala"
    w = _start(log)
    span = w.session_start("s")
    w.session_end(span)
    w.close()
    tr = TailingReader(log, torn_grace=99)
    tr._drain()  # verify all four records

    # Rewrite the file shorter than the verified head — history changed.
    data = log.read_bytes()
    log.write_bytes(data[: len(data) // 2])

    events = tr._drain()
    diag = next(e for e in events if e.kind == "diagnosis")
    assert "replaced_or_rolled_back" in diag.detail
    tr.close()
