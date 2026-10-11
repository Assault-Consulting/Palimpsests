# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The writer declares every cut in the chain: SEGMENT_CONTINUATION (r6, kind 11).

Expected values are computed independently of the writer — record hashes
read back from the files, roots from merkle_root — never from the
writer's own state.
"""
from __future__ import annotations

import json
import logging
import os
import pytest
import struct
from palimpsests.audit import pala
from palimpsests.audit.pala.merkle import merkle_root, verify_consistency
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy

KIND, DETAIL, PRED, INDEX, RETENTION, ROOT = 0x0001, 0x0004, 0x0012, 0x0013, 0x0014, 0x0015


def _records(*paths):
    out = []
    for p in paths:
        out += list(pala.iter_records(p.read_bytes()))
    return out


def _continuation(path):
    """The decoded continuation fields of a segment's first record, or None."""
    hb, body = next(iter(pala.iter_records(path.read_bytes())))
    tlvs = dict(pala.decode_tlvs(body)) if body else {}
    if struct.unpack("<H", tlvs.get(KIND, b"\x00\x00"))[0] != 11:
        return None
    return {
        "prev_hash": pala.Header.decode(hb).prev_hash,
        "key_id": pala.Header.decode(hb).key_id,
        "seq": pala.Header.decode(hb).seq,
        "detail": tlvs.get(DETAIL, b"").decode(),
        "pred": tlvs[PRED],
        "index": struct.unpack("<I", tlvs[INDEX])[0],
        "retention": struct.unpack("<Q", tlvs[RETENTION])[0],
        "root": tlvs[ROOT],
    }


def _rotated(tmp_path, records=14, policy=None):
    policy = policy or RotationPolicy(max_records=4, retention_s=15_552_000)
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=policy)
    w.genesis()
    for _ in range(records - 1):
        w.prefix_warm(token_count=1)
    w.close()
    segs = [base] + sorted(tmp_path.glob("w.pala.0*"))
    return base, segs, json.loads((tmp_path / "w.pala.segments.json").read_text())


def test_every_segment_after_the_first_declares_what_precedes_it(tmp_path):
    _, segs, manifest = _rotated(tmp_path)
    everything = [pala.record_hash(h) for h, _ in _records(*segs)]
    assert _continuation(segs[0]) is None  # the GENESIS segment declares nothing
    for i, seg in enumerate(segs[1:], start=1):
        c = _continuation(seg)
        closed = manifest["segments"][i - 1]
        assert c is not None, seg
        assert c["pred"] == c["prev_hash"] == bytes.fromhex(closed["head"])
        assert c["index"] == i  # consecutive, the GENESIS segment being 0
        assert c["retention"] == 15_552_000
        assert c["detail"] == "max_records=4"
        assert c["key_id"] == 0  # cleartext by rule
        # the root of every record before it, from record 0 — computed here
        # from the files, not taken from the writer
        assert c["root"] == merkle_root(everything[: c["seq"]])
        assert c["root"].hex() == closed["root"]


def test_the_declared_root_proves_the_prefix_against_any_later_root(tmp_path):
    from palimpsests.audit.pala.merkle import consistency_proof

    _, segs, _ = _rotated(tmp_path)
    everything = [pala.record_hash(h) for h, _ in _records(*segs)]
    c = _continuation(segs[2])
    proof = consistency_proof(everything, c["seq"])
    assert verify_consistency(c["seq"], len(everything), c["root"], merkle_root(everything), proof)


def test_a_manual_cut_declares_itself_and_returns_the_closed_head(tmp_path):
    a, b = tmp_path / "a.pala", tmp_path / "b.pala"
    w = PalaWriter(a)
    w.genesis()
    w.prefix_warm(token_count=1)
    closed_head = w.head
    assert w.rotate(b) == closed_head  # the head a caller anchors
    w.prefix_warm(token_count=1)
    w.close()
    c = _continuation(b)
    assert c["pred"] == closed_head and c["index"] == 1
    assert c["retention"] == 0 and c["detail"] == ""  # no policy declared
    combined = a.read_bytes() + b.read_bytes()
    assert pala.verify_headers([h for h, _ in pala.iter_records(combined)]).chain_ok


def test_a_resumed_writer_knows_its_segment_and_numbers_the_next_one(tmp_path):
    policy = RotationPolicy(max_records=4)
    _, segs, _ = _rotated(tmp_path, records=10, policy=policy)
    last = segs[-1]
    before = _continuation(last)["index"]
    w = PalaWriter.open_existing(last, rotation=policy)
    w.boot()
    for _ in range(4):
        w.prefix_warm(token_count=1)
    w.close()
    newest = sorted(tmp_path.glob("w.pala.0*"))[-1]
    assert _continuation(newest)["index"] > before


def test_after_deletion_a_new_segment_never_takes_an_old_name(tmp_path):
    policy = RotationPolicy(max_records=3)
    _, segs, manifest = _rotated(tmp_path, records=12, policy=policy)
    used = {e["file"] for e in manifest["segments"]} | {s.name for s in segs}
    for old in segs[:-1]:
        os.remove(old)
    w = PalaWriter.open_existing(segs[-1], rotation=policy)
    w.boot()
    for _ in range(6):
        w.prefix_warm(token_count=1)
    w.close()
    fresh = {s.name for s in tmp_path.glob("w.pala.0*")} - {segs[-1].name}
    assert fresh and not (fresh & used)


def test_a_crash_between_manifest_and_successor_is_folded_back(tmp_path, monkeypatch, caplog):
    policy = RotationPolicy(max_records=3)
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=policy)
    w.genesis()
    w.prefix_warm(token_count=1)

    real_replace = os.replace
    calls = {"n": 0}

    def crash(src, dst, *a, **k):
        # the manifest is itself written atomically through os.replace; let
        # that one land, and lose power on the next — the successor's rename
        calls["n"] += 1
        if calls["n"] == 1:
            return real_replace(src, dst, *a, **k)
        raise OSError("power lost between manifest and rename")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        w.prefix_warm(token_count=1)  # third record: the cut starts and dies
    monkeypatch.setattr(os, "replace", real_replace)
    w._fh.close()
    w._xlock.release()

    manifest = tmp_path / "w.pala.segments.json"
    assert json.loads(manifest.read_text())["segments"][-1]["file"] == "w.pala"
    assert not (tmp_path / "w.pala.00001").exists()

    with caplog.at_level(logging.WARNING, logger="palimpsests.audit"):
        resumed = PalaWriter.open_existing(base, rotation=policy)
    assert "folded back" in caplog.text
    assert not manifest.exists()  # the only entry was the unfinished cut
    resumed.boot()  # writing continues in the same file; the next cut is whole
    resumed.prefix_warm(token_count=1)
    resumed.close()
    nxt = tmp_path / "w.pala.00001"
    assert nxt.exists() and _continuation(nxt)["index"] == 1
    combined = base.read_bytes() + nxt.read_bytes()
    assert pala.verify_headers([h for h, _ in pala.iter_records(combined)]).chain_ok


def test_a_cut_that_cannot_know_the_root_declares_nothing_and_says_so(tmp_path, caplog):
    a, b, c = tmp_path / "a.pala", tmp_path / "b.pala", tmp_path / "c.pala"
    w = PalaWriter(a)
    w.genesis()
    w.rotate(b)  # manual cut: no manifest, so no recorded frontier for b
    w.close()
    resumed = PalaWriter.open_existing(b)  # cannot know the root over a's records
    resumed.boot()
    with caplog.at_level(logging.WARNING, logger="palimpsests.audit"):
        resumed.rotate(c)
    resumed.close()
    assert "no SEGMENT_CONTINUATION" in caplog.text
    assert c.stat().st_size == 0  # nothing declared rather than a guess


def test_outcome_4_is_accepted_and_5_is_not(tmp_path):
    from palimpsests.audit.pala_writer import OUTCOME_UNOBSERVED

    w = PalaWriter(tmp_path / "c.pala")
    w.genesis()
    call = w.tool_call("shell.exec")
    w.tool_result(1, call, OUTCOME_UNOBSERVED)
    with pytest.raises(ValueError):
        w.tool_result(1, call, 5)
    w.close()
