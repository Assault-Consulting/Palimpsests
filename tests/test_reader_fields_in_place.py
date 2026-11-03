# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U28 and U29 — an agent's log, verified and filtered without decoding it.

Measured by Auditor on 0.13.1: ``verify()`` on a million records of tool
loops decoded and kept every record (32.5 s, 2.47 GB), because every
TOOL_RESULT references its call; and a filter by kind could only decode.
References are now read in place on a cold reader, and the filter fields
have an accessor of their own. Both must answer exactly as the decoded
path does — these tests compare them on every record they build.
"""
from __future__ import annotations

import struct
from palimpsests.audit.pala import vectors
from palimpsests.audit.pala.codec import RT_EVENT, encode_tlvs
from palimpsests.audit.pala_writer import (
    DISP_ACKNOWLEDGED,
    OUTCOME_ERROR,
    OUTCOME_OK,
    PalaWriter,
)
from palimpsests.audit.profiles.inference import (
    EVT_KIND,
    EVT_OUTCOME,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    EVT_SOURCE,
    KIND_TOOL_RESULT,
)
from palimpsests.audit.reader import AuditReader, RecordFields

OPERATOR = b"\x07" * 16


def _tool_loops(path, n):
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        for i in range(n):
            seq, h = w.tool_call("read", args_digest=b"\x01" * 32, return_seq=True)
            w.tool_result(seq, h, OUTCOME_OK if i % 3 else OUTCOME_ERROR,
                          result_digest=b"\x02" * 32)
    return path


def _odd_chain(path):
    """Every reference outcome, and bodies at the edges of the decode rules."""
    with PalaWriter(path) as w:
        w.genesis()
        boot = w.boot()
        seq, call = w.tool_call("read", return_seq=True)
        w.tool_result(seq, call, OUTCOME_OK)                      # resolves
        w.tool_result(999_999, call, OUTCOME_OK)                  # unresolved
        w.tool_result(seq, b"\x00" * 32, OUTCOME_OK)              # hash mismatch
        w.tool_result(1, boot, OUTCOME_OK)                        # target not a call
        w.oversight_ack(1, boot, DISP_ACKNOWLEDGED, OPERATOR)     # target not a candidate
        cand = w.incident_candidate(1, 2)
        w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
        role = w._origin("engine.native")
        k9 = (EVT_KIND, struct.pack("<H", KIND_TOOL_RESULT))
        # the reference appears twice: the decoded path keeps the last
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([
            k9, (EVT_REF_SEQ, struct.pack("<Q", 999_998)), (EVT_REF_HASH, call),
            (EVT_REF_SEQ, struct.pack("<Q", seq)), (EVT_OUTCOME, struct.pack("<H", 1)),
            (EVT_SOURCE, struct.pack("<H", 1)), (EVT_SOURCE, struct.pack("<H", 0))]))
        # EVT_KIND not first; a one-byte EVT_OUTCOME, then a real one
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([
            (EVT_OUTCOME, b"\x01"), k9, (EVT_OUTCOME, struct.pack("<H", 4))]))
        # a malformed body: a TLV overrunning it — no kind, by the decode rules
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([k9]) + b"\x08\x00\xff\x00")
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([(EVT_KIND, struct.pack("<H", 4242))]))
    return path


def _all_chains(tmp_path):
    yield _tool_loops(tmp_path / "loops.pala", 50)
    yield _odd_chain(tmp_path / "odd.pala")
    for name in ("core", "inference"):
        p = tmp_path / f"{name}.pala"
        data = vectors.load(name)
        p.write_bytes(b"".join(
            bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex") or "")
            for r in data["records"]))
        yield p


def test_verify_on_an_agents_log_decodes_nothing(tmp_path):
    with AuditReader.open(_tool_loops(tmp_path / "t.pala", 500)) as r:
        ver = r.verify()
        assert ver.chain.chain_ok
        assert [i.code for i in ver.advisory.items] == ["anchor_never_written"]
        assert r._partial == {} and r._decoded is None


def test_cold_and_warm_readers_give_the_same_advisories(tmp_path):
    """The in-place path (cold) against the decoded path (warm), item by item."""
    for chain in _all_chains(tmp_path):
        with AuditReader.open(chain) as cold, AuditReader.open(chain) as warm:
            list(warm.records())  # the full decode: the referential pass takes its old path
            got = cold.verify().advisory.items
            assert got == warm.verify().advisory.items, chain.name
            if chain.name == "odd.pala":
                codes = {i.code for i in got}
                assert {"reference_unresolved", "reference_hash_mismatch",
                        "tool_target_not_a_call", "ack_target_not_a_candidate"} <= codes


def test_record_fields_equal_the_decoded_record_everywhere(tmp_path):
    for chain in _all_chains(tmp_path):
        with AuditReader.open(chain) as r:
            fields = [r.record_fields_at(i) for i in range(r.record_count)]
            assert r._partial == {}  # read in place, nothing kept
            for i, f in enumerate(fields):
                d = r.record_at(i)
                assert f == RecordFields(d.kind, d.kind_name, d.source, d.source_name,
                                         d.outcome, d.outcome_name), (chain.name, i)


def test_record_fields_index_rules(tmp_path):
    import pytest

    with AuditReader.open(_tool_loops(tmp_path / "t.pala", 1)) as r:
        with pytest.raises(IndexError):
            r.record_fields_at(r.record_count)
        with pytest.raises(IndexError):
            r.record_fields_at(-1)
        with pytest.raises(TypeError):
            r.record_fields_at(True)
        assert r.record_fields_at(3).outcome_name == "error"  # the first result
