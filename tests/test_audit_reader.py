# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""AuditReader facade: verification, the diagnosis table, and the views.

Covers the design sketch §12 "Facade" row: verify() on the vectors equals
the canonical verifier's answer; the tri-state without an anchor; the
diagnosis derivation table one test per row (7); spans (an unclosed span is
visible), boots (two boots on a resume chain, recovery_seq set), and
origin_at across load/unload.
"""

from __future__ import annotations

import json
from palimpsests.audit.anchors import ChainedAnchorSource, FileAnchor, ManualAnchor
from palimpsests.audit.pala import iter_records, record_hash, verify_headers
from palimpsests.audit.pala.codec import RT_EVENT, RT_GENESIS, ZERO32, Header
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from pathlib import Path

VECTORS_PATH = Path(__file__).parent.parent / "docs/specs/pala-1/test-vectors.json"


def _container(path) -> bytes:
    return path.read_bytes()


def _headers(data: bytes):
    return [hb for hb, _ in iter_records(data)]


def _vector_bytes():
    vectors = json.loads(VECTORS_PATH.read_text())
    return b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in vectors["records"]
    ), vectors


def _good_chain(tmp_path):
    log = tmp_path / "good.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.model_load(model_digest=bytes(range(32)), config_digest=bytes(range(1, 33)))
    span = w.session_start("s1")
    w.prefix_copy(64, span_id=span)
    w.session_end(span)
    w.model_unload()
    head = w.anchor()
    w.close()
    return log, head


# --------------------------------------------------------------------------- #
# Facade — matches the canonical verifier; tri-state without an anchor
# --------------------------------------------------------------------------- #


def test_verify_matches_canonical_on_vectors():
    data, vectors = _vector_bytes()
    r = AuditReader.from_bytes(data)
    v = r.verify()
    assert v.chain == verify_headers(_headers(data))
    assert v.chain.chain_ok is True
    assert v.chain.head.hex() == vectors["chain_head"]


def test_tristate_without_anchor_is_none(tmp_path):
    log, _ = _good_chain(tmp_path)
    r = AuditReader.open(log)
    v = r.verify()
    assert v.complete_to_anchor is None  # not checked — never rendered as passing
    assert v.diagnosis is None
    r.close()


def test_matching_anchor_completes(tmp_path):
    log, head = _good_chain(tmp_path)
    r = AuditReader.open(log, anchor=ManualAnchor(head.hex()))
    v = r.verify()
    assert v.complete_to_anchor is True
    assert [(a.source_kind, a.outcome) for a in v.anchor_attempts] == [("manual", "answered")]
    assert v.diagnosis is None
    r.close()


def test_chained_anchor_attempts_trace(tmp_path):
    log, head = _good_chain(tmp_path)
    missing = tmp_path / "nope.head"
    chain = ChainedAnchorSource([FileAnchor(missing), ManualAnchor(head.hex())])
    r = AuditReader.open(log, anchor=chain)
    v = r.verify()
    assert [a.outcome for a in v.anchor_attempts] == ["absent", "answered"]
    assert v.complete_to_anchor is True
    r.close()


# --------------------------------------------------------------------------- #
# Diagnosis derivation — one test per row (first match wins)
# --------------------------------------------------------------------------- #


def test_diagnosis_truncated_tail(tmp_path):
    log, _ = _good_chain(tmp_path)
    data = _container(log)
    r = AuditReader.from_bytes(data[:-3])  # chop the final record mid-body
    assert r.verify().diagnosis.pattern == "truncated_tail"


def test_diagnosis_prefix_absent(tmp_path):
    log, _ = _good_chain(tmp_path)
    recs = list(iter_records(_container(log)))
    # Drop the GENESIS record: the container now starts with BOOT (bodies kept
    # so nothing looks truncated).
    without_genesis = b"".join(hb + body for hb, body in recs[1:])
    r = AuditReader.from_bytes(without_genesis)
    assert r.verify().diagnosis.pattern == "prefix_absent"


def test_diagnosis_seq_gap(tmp_path):
    log, _ = _good_chain(tmp_path)
    recs = list(iter_records(_container(log)))
    # Drop a middle record entirely: seq jumps (gap wins over the break it also causes).
    kept = recs[:3] + recs[4:]
    data = b"".join(hb + body for hb, body in kept)
    assert AuditReader.from_bytes(data).verify().diagnosis.pattern == "seq_gap"


def test_diagnosis_chain_break(tmp_path):
    log, _ = _good_chain(tmp_path)
    recs = list(iter_records(_container(log)))
    # Flip a prev_hash byte in a middle record: a break with no gap.
    hb = bytearray(recs[3][0])
    hb[40] ^= 0x01
    recs[3] = (bytes(hb), recs[3][1])
    data = b"".join(h + b for h, b in recs)
    assert AuditReader.from_bytes(data).verify().diagnosis.pattern == "chain_break"


def test_diagnosis_record_violation():
    # A genesis, then an EVENT that violates §5 (UNKNOWN time but a wall clock).
    g = Header(record_type=RT_GENESIS, seq=0, boot_id=b"\x01" * 16, prev_hash=ZERO32).encode()
    bad = Header(
        record_type=RT_EVENT,
        seq=1,
        boot_id=b"\x01" * 16,
        prev_hash=record_hash(g),
        time_trust=0,  # UNKNOWN
        wall_clock_ns=5,  # but a confident timestamp → violation
    ).encode()
    data = g + bad
    diag = AuditReader.from_bytes(data).verify().diagnosis
    assert diag.pattern == "record_violation"
    assert diag.at_seq == 1


def test_diagnosis_unanchored_tail(tmp_path):
    log, _ = _good_chain(tmp_path)
    hdrs = _headers(_container(log))
    # Anchor the head of an earlier record: names an in-chain record, not the head.
    earlier = record_hash(hdrs[-3])
    r = AuditReader.open(log, anchor=ManualAnchor(earlier.hex()))
    v = r.verify()
    assert v.diagnosis.pattern == "unanchored_tail"
    assert v.anchor_lag == 2
    r.close()


def test_diagnosis_replaced_or_rolled_back(tmp_path):
    log, _ = _good_chain(tmp_path)
    r = AuditReader.open(log, anchor=ManualAnchor("ab" * 32))  # a head not in the chain
    v = r.verify()
    assert v.diagnosis.pattern == "replaced_or_rolled_back"
    assert v.anchor_lag is None
    r.close()


# --------------------------------------------------------------------------- #
# Views — spans, boots, origin
# --------------------------------------------------------------------------- #


def test_spans_unclosed_visible(tmp_path):
    log = tmp_path / "open.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.session_start("s-open")  # never ended
    w.close()
    spans = AuditReader.open(log).spans()
    assert len(spans) == 1
    assert spans[0].end_seq is None  # visibly unclosed, not an error


def test_boots_resume_recovery_seq(tmp_path):
    log = tmp_path / "resume.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.session_start("s1")
    w.close()
    # Append a torn partial record, then resume: open_existing truncates it.
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)
    w2 = PalaWriter.open_existing(log)
    w2.boot()
    w2.recovery_truncated_tail()
    w2.close()

    boots = AuditReader.open(log).boots()
    assert len(boots) == 2
    assert boots[1].recovery_seq is not None


def test_origin_at_across_load_unload(tmp_path):
    log, _ = _good_chain(tmp_path)
    r = AuditReader.open(log)
    recs = list(r.records())
    load_seq = next(d.seq for d in recs if d.kind_name == "MODEL_LOAD")
    unload_seq = next(d.seq for d in recs if d.kind_name == "MODEL_UNLOAD")

    at_load = r.origin_at(load_seq)
    assert at_load is not None
    assert at_load.model_digest == bytes(range(32))
    assert at_load.since_seq == load_seq

    assert r.origin_at(load_seq - 1) is None  # before any load
    assert r.origin_at(unload_seq) is None  # unload cleared it
    r.close()


def test_records_decode_kind_names(tmp_path):
    log, _ = _good_chain(tmp_path)
    names = [d.kind_name for d in AuditReader.open(log).records() if d.kind_name]
    assert "MODEL_LOAD" in names
    assert "PREFIX_COPY" in names
    assert "MODEL_UNLOAD" in names
