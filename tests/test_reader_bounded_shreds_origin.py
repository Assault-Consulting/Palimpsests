# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U23 — ``shredded_targets()`` and the origin methods without the full decode.

Both used to walk ``_decoded_records()``: on a cold reader, one call cost
the whole chain. The bounded versions must give **exactly** the answers
the full walk gave, so each is checked here against that walk, written
out as a reference over ``records()``, on chains built to hit its edges:
load / unload / reload, an EVENT that sets origin by its header digest
alone, a header that does not decode, a seq that goes backwards, shreds
that resolve, mismatch, miss and repeat, and the published companion
vectors (an encrypted body and a KEY_SHRED among them).
"""
from __future__ import annotations

import json
import struct
from palimpsests.audit.pala.codec import (
    RT_EVENT,
    RT_KEY_SHRED,
    TLV_ORIGIN_MODEL_DIGEST,
    TLV_SHRED_KEY_ID,
)
from palimpsests.audit.pala_writer import (
    KIND_KV_SAVE,
    KIND_MODEL_LOAD,
    KIND_MODEL_UNLOAD,
    SHRED_TARGET_SEQS,
    PalaWriter,
)
from palimpsests.audit.reader import AuditReader, OriginState, _has_model_digest, _origin_of
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


# --- the full-decode walks, as they were — the reference ----------------------


def _origin_reference(records, seq):
    current, last_was_unload = None, False
    for dr in records:
        if dr.header is None:
            continue
        if dr.seq > seq:
            break
        if dr.record_type != RT_EVENT:
            continue
        if dr.kind == KIND_MODEL_UNLOAD:
            current, last_was_unload = None, True
        elif dr.kind == KIND_MODEL_LOAD or _has_model_digest(dr.header):
            current, last_was_unload = _origin_of(dr), False
    return OriginState(current, last_was_unload)


def _shredded_reference(records):
    by_seq = {dr.seq: dr for dr in records}
    shredded = {}
    for dr in by_seq.values():
        if dr.record_type != RT_KEY_SHRED or dr.body_tlvs is None:
            continue
        raw = dict(dr.body_tlvs).get(SHRED_TARGET_SEQS)
        if raw is None or len(raw) % 8 != 0:
            continue
        shred_key = None
        for t, v in dr.header.tlvs if dr.header else []:
            if t == TLV_SHRED_KEY_ID and len(v) == 4:
                (shred_key,) = struct.unpack("<I", v)
                break
        for off in range(0, len(raw), 8):
            (t_seq,) = struct.unpack_from("<Q", raw, off)
            target = by_seq.get(t_seq)
            if target is None:
                continue
            key = target.header.key_id if target.header is not None else None
            if shred_key is None or key == shred_key:
                shredded[t_seq] = dr.seq
    return shredded


# --- chains -------------------------------------------------------------------


def _offsets(data: bytes) -> list[int]:
    offs, at = [], 0
    while (at := data.find(b"PALA", at)) != -1:
        offs.append(at)
        at += 4
    return offs


def _origin_chain(tmp_path: Path) -> Path:
    log = tmp_path / "origin.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.kv_save(b"\x01" * 32)  # an EVENT that sets nothing
    w.model_load(b"\x11" * 32, b"\x22" * 32, role="engine.native", detail="first")
    w.incident_candidate(1, 2, detail="between")
    w.model_unload(detail="gone")
    w.kv_save(b"\x02" * 32)
    # an EVENT whose header carries an origin model digest, kind not MODEL_LOAD
    w._emit(
        RT_EVENT,
        tlvs=w._origin("engine.native", (TLV_ORIGIN_MODEL_DIGEST, b"\x33" * 32)),
        body=w._event_body(KIND_KV_SAVE, blob_digest=b"\x03" * 32),
    )
    w.model_load(b"\x44" * 32, b"\x55" * 32, role="engine.native", detail="second")
    w.anchor()
    w.close()
    return log


def _shred_chain(tmp_path: Path) -> Path:
    log = tmp_path / "shred.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.kv_save(b"\x11" * 32)
    a = w.seq - 1
    w.kv_save(b"\x12" * 32)
    b = w.seq - 1
    w.key_shred(0, target_seqs=[a, 4242])  # resolves a; misses 4242
    w.key_shred(9, target_seqs=[b])  # key mismatch: b is cleartext, key 0
    w.key_shred(0, target_seqs=[a, b])  # a re-shred of a, and b at last
    w.key_shred(0)  # no targets at all
    w.close()
    return log


def _vectors_chain(tmp_path: Path) -> Path:
    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    p = tmp_path / "vectors.pala"
    p.write_bytes(blob)
    return p


def _with_undecodable_load(tmp_path: Path) -> Path:
    """The first MODEL_LOAD's header made undecodable: the walk skips it."""
    (tmp_path / "u").mkdir()
    path = _origin_chain(tmp_path / "u")
    data = bytearray(path.read_bytes())
    at = _offsets(bytes(data))[3]
    data[at + 4 : at + 6] = (2).to_bytes(2, "little")
    out = tmp_path / "undecodable.pala"
    out.write_bytes(bytes(data))
    return out


def _with_seq_going_back(tmp_path: Path) -> Path:
    """The MODEL_UNLOAD's bytes repeated at the end: a lower seq after a
    higher one, so "stop at the first seq past the question" is not "stop
    at the first position past it"."""
    (tmp_path / "b").mkdir()
    path = _origin_chain(tmp_path / "b")
    data = path.read_bytes()
    offs = _offsets(data)
    unload = data[offs[5] : offs[6]]
    out = tmp_path / "backwards.pala"
    out.write_bytes(data + unload)
    return out


def _all_chains(tmp_path: Path) -> list[Path]:
    return [
        _origin_chain(tmp_path),
        _shred_chain(tmp_path),
        _vectors_chain(tmp_path),
        _with_undecodable_load(tmp_path),
        _with_seq_going_back(tmp_path),
    ]


# --- 1. the same answers -------------------------------------------------------


def test_origin_answers_equal_the_full_walk_at_every_seq(tmp_path):
    for path in _all_chains(tmp_path):
        with AuditReader.open(path) as full:
            records = list(full.records())
        top = max(r.seq for r in records)
        with AuditReader.open(path) as r:
            for seq in range(-1, top + 3):
                expected = _origin_reference(records, seq)
                assert r.origin_state_at(seq) == expected, (path.name, seq)
                assert r.origin_at(seq) == expected.origin
                assert r.unloaded_at(seq) == expected.unloaded


def test_shredded_targets_equal_the_full_walk(tmp_path):
    for path in _all_chains(tmp_path):
        with AuditReader.open(path) as full:
            expected = _shredded_reference(list(full.records()))
        with AuditReader.open(path) as r:
            assert r.shredded_targets() == expected, path.name


def test_the_shred_chain_resolves_as_specified(tmp_path):
    """Not only equal to the reference: equal to what the semantics say."""
    with AuditReader.open(_shred_chain(tmp_path)) as r:
        # a re-shredded by the later KEY_SHRED (seq 6); b resolved only there
        assert r.shredded_targets() == {2: 6, 3: 6}


def test_the_origin_chain_moves_through_its_states(tmp_path):
    with AuditReader.open(_origin_chain(tmp_path)) as r:
        assert r.origin_state_at(2) == OriginState(None, False)  # never declared
        assert r.origin_state_at(4).origin.detail == "first"
        assert r.origin_state_at(5) == OriginState(None, True)  # unloaded
        assert r.origin_state_at(7).origin.model_digest == b"\x33" * 32
        assert r.origin_state_at(8).origin.detail == "second"


def test_answers_agree_on_a_warm_reader_too(tmp_path):
    path = _origin_chain(tmp_path)
    with AuditReader.open(path) as cold, AuditReader.open(path) as warm:
        list(warm.records())
        for seq in range(0, 10):
            assert cold.origin_state_at(seq) == warm.origin_state_at(seq)
        assert cold.shredded_targets() == warm.shredded_targets()


# --- 2. no materialisation ------------------------------------------------------


def test_a_cold_reader_never_fills_the_full_cache(tmp_path):
    for path in _all_chains(tmp_path):
        with AuditReader.open(path) as r:
            r.origin_state_at(10_000)
            r.shredded_targets()
            assert r._decoded is None, path.name


def test_only_the_records_the_answer_needs_are_decoded(tmp_path):
    """Shreds decode the KEY_SHRED records; origin decodes the one record
    that set the state asked about. Nothing else."""
    with AuditReader.open(_shred_chain(tmp_path)) as r:
        r.shredded_targets()
        shreds = {i for i in range(r.record_count) if r._headers.record_type_at(i) == RT_KEY_SHRED}
        assert set(r._partial) == shreds
    with AuditReader.open(_origin_chain(tmp_path)) as r:
        r.origin_state_at(4)
        assert set(r._partial) == {3}


def test_shredded_targets_is_computed_once_and_handed_out_fresh(tmp_path):
    with AuditReader.open(_shred_chain(tmp_path)) as r:
        first = r.shredded_targets()
        first[999] = 999
        assert 999 not in r.shredded_targets()
