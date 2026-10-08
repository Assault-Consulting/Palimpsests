# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The writer keeps the derived root from seq 0 — across resume, rotation,
and the deletion of old segments, which is the case it exists for.

The expected value is always computed independently: merkle_root over
the record hashes of every record ever written, read back from the
files while they still exist.
"""
from __future__ import annotations

import json
import os
import pytest
from palimpsests.audit import pala
from palimpsests.audit.pala.merkle import merkle_root
from palimpsests.audit.pala_writer import FrontierUnavailable, PalaWriter, RotationPolicy


def _hashes(*paths) -> list[bytes]:
    out: list[bytes] = []
    for p in paths:
        out += [pala.record_hash(h) for h, _ in pala.iter_records(open(p, "rb").read())]
    return out


def test_a_new_chain_states_the_root_over_everything_it_wrote(tmp_path):
    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    w.boot()
    for _ in range(25):
        w.prefix_warm(token_count=1)
    root = w.chain_root()
    w.close()
    assert root == merkle_root(_hashes(p))


def test_resuming_a_whole_chain_continues_the_root(tmp_path):
    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    for _ in range(9):
        w.prefix_warm(token_count=1)
    w.close()
    w2 = PalaWriter.open_existing(p)
    w2.boot()
    for _ in range(7):
        w2.prefix_warm(token_count=1)
    root = w2.chain_root()
    w2.close()
    assert root == merkle_root(_hashes(p))


def test_a_torn_tail_is_not_counted(tmp_path):
    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    w.prefix_warm(token_count=1)
    w.close()
    with open(p, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)
    w2 = PalaWriter.open_existing(p)
    w2.boot()
    w2.recovery_truncated_tail()
    root = w2.chain_root()
    w2.close()
    assert root == merkle_root(_hashes(p))


def _rotated(tmp_path, records=22, per_segment=4):
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=per_segment))
    w.genesis()
    for _ in range(records - 1):
        w.prefix_warm(token_count=1)
    w.close()
    segs = [base] + sorted(tmp_path.glob("w.pala.0*"))
    # A record count that does not divide evenly leaves the last segment
    # open and non-empty, as a running writer's always is.
    assert segs[-1].stat().st_size > 0
    return base, segs, tmp_path / "w.pala.segments.json"


def test_every_closed_segment_records_the_root_up_to_its_end(tmp_path):
    _, segs, manifest = _rotated(tmp_path)
    entries = json.loads(manifest.read_text())["segments"]
    everything = _hashes(*segs)
    assert len(entries) >= 3
    for e in entries:
        assert e["root"] == merkle_root(everything[: e["last_seq"] + 1]).hex()


def test_resuming_a_later_segment_continues_from_the_recorded_frontier(tmp_path):
    base, segs, _ = _rotated(tmp_path)
    w = PalaWriter.open_existing(segs[-1], rotation=RotationPolicy(max_records=4))
    w.boot()
    w.prefix_warm(token_count=1)
    root = w.chain_root()
    w.close()
    segs = [base] + sorted(tmp_path.glob("w.pala.0*"))
    assert root == merkle_root(_hashes(*segs))


def test_after_old_segments_are_deleted_the_root_still_covers_them(tmp_path):
    # The case the frontier exists for: a retention policy deletes the
    # oldest segments, and the writer still states the root over every
    # record since seq 0 — records that no longer exist anywhere.
    base, segs, _ = _rotated(tmp_path, records=32, per_segment=5)
    everything = _hashes(*segs)  # read while every segment still exists
    for old in segs[:-1]:
        os.remove(old)
    w = PalaWriter.open_existing(segs[-1], rotation=RotationPolicy(max_records=5))
    w.boot()
    w.prefix_warm(token_count=1)
    root = w.chain_root()
    w.close()
    # what was appended after the deletion: the BOOT and the one event,
    # now at the end of the surviving segment (or in a new one, if the
    # policy rotated on the way)
    appended = (_hashes(*[s for s in sorted(tmp_path.glob("w.pala*")) if s.suffix != ".json"]))
    assert root == merkle_root(everything + appended[-2:])


def test_a_later_segment_without_a_recorded_frontier_refuses(tmp_path):
    _, segs, manifest = _rotated(tmp_path)
    mf = json.loads(manifest.read_text())
    for e in mf["segments"]:
        e.pop("frontier", None)
        e.pop("root", None)
    manifest.write_text(json.dumps(mf))
    w = PalaWriter.open_existing(segs[-1])
    with pytest.raises(FrontierUnavailable, match="predates recorded frontiers"):
        w.chain_root()
    w.boot()  # still a working writer; only the root is withheld
    w.close()


def test_a_later_segment_with_no_manifest_refuses(tmp_path):
    _, segs, manifest = _rotated(tmp_path)
    manifest.unlink()
    w = PalaWriter.open_existing(segs[-1])
    with pytest.raises(FrontierUnavailable, match="no readable"):
        w.chain_root()
    w.close()


def test_a_frontier_that_does_not_fit_the_segment_is_refused(tmp_path):
    from palimpsests.audit.pala.frontier import MerkleFrontier

    _, segs, manifest = _rotated(tmp_path)
    mf = json.loads(manifest.read_text())
    wrong = MerkleFrontier.from_record_hashes([b"\x00" * 32] * 3)  # covers 3, not first_seq
    mf["segments"][-1]["frontier"] = wrong.to_bytes().hex()
    manifest.write_text(json.dumps(mf))
    w = PalaWriter.open_existing(segs[-1])
    with pytest.raises(FrontierUnavailable, match="covers 3 records"):
        w.chain_root()
    w.close()


# --- the deferred path: a whole chain resumed without hashing it ---------- #

def test_resume_does_not_hash_a_whole_chain_until_the_root_is_needed(tmp_path, monkeypatch):
    import palimpsests.audit.pala_writer as pw

    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    for _ in range(50):
        w.prefix_warm(token_count=1)
    w.close()
    calls = {"n": 0}
    real = pw.record_hash

    def counting(b):
        calls["n"] += 1
        return real(b)

    monkeypatch.setattr(pw, "record_hash", counting)
    w2 = PalaWriter.open_existing(p)
    # resuming a 51-record chain hashed one header (the last, for its head)
    assert calls["n"] == 1
    w2.boot()
    root = w2.chain_root()  # now it is built
    w2.close()
    monkeypatch.setattr(pw, "record_hash", real)
    assert root == merkle_root(_hashes(p))


def test_the_pending_buffer_is_bounded_and_the_root_stays_right(tmp_path, monkeypatch):
    import palimpsests.audit.pala_writer as pw

    monkeypatch.setattr(pw, "_FRONTIER_PENDING_LIMIT", 3)
    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    w.prefix_warm(token_count=1)
    w.close()
    w2 = PalaWriter.open_existing(p)
    w2.boot()
    for _ in range(10):
        w2.prefix_warm(token_count=1)
        assert len(w2._frontier_pending) < 3
    root = w2.chain_root()
    w2.close()
    assert root == merkle_root(_hashes(p))


def test_rotating_right_after_a_resume_records_the_right_root(tmp_path):
    base = tmp_path / "w.pala"
    w = PalaWriter(base)
    w.genesis()
    for _ in range(6):
        w.prefix_warm(token_count=1)
    w.close()
    w2 = PalaWriter.open_existing(base, rotation=RotationPolicy(max_records=10))
    w2.boot()
    for _ in range(5):
        w2.prefix_warm(token_count=1)  # crosses max_records: rotates
    w2.close()
    entries = json.loads((tmp_path / "w.pala.segments.json").read_text())["segments"]
    everything = _hashes(base, *sorted(tmp_path.glob("w.pala.0*")))
    assert entries[0]["root"] == merkle_root(everything[: entries[0]["last_seq"] + 1]).hex()
