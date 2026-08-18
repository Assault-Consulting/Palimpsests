# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r3 tool-loop writer methods emit exactly the profile §3.1/§4 shapes.

Same two-layer discipline as the oversight tests: the envelope is the
core's (verified via the production verifier), and the r3 body TLVs must
decode to the documented tag set — cross-checked against the published
companion vectors so the writer and the vectors cannot drift apart
silently.
"""
from __future__ import annotations

import json
import pytest
import struct
from hashlib import sha256
from palimpsests.audit.pala import decode_tlvs, iter_records, verify_headers
from palimpsests.audit.pala_writer import (
    EVT_KIND,
    EVT_OUTCOME,
    EVT_PAYLOAD_DIGEST,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    EVT_TOKEN_COUNT,
    EVT_TOOL_NAME,
    KIND_GUARD_TOOL_LOOP_LIMIT,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
    OUTCOME_CANCELLED,
    OUTCOME_OK,
    PalaWriter,
    canonical_tool_args_digest,
)
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _tool_chain(tmp_path):
    log = tmp_path / "tools.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        call = w.tool_call(
            "web.search",
            args_digest=canonical_tool_args_digest({"query": "pala-1"}),
        )
        call_seq = w.seq - 1
        w.tool_result(
            call_seq, call, OUTCOME_OK, result_digest=sha256(b'{"hits":3}').digest()
        )
        w.guard_tool_loop_limit(8, call_seq=call_seq, call_hash=call)
    return log.read_bytes(), call, call_seq


def _bodies(blob):
    out = {}
    for i, (_hb, body) in enumerate(iter_records(blob)):
        if body:
            out[i] = dict(decode_tlvs(body))
    return out


def test_tool_records_verify_and_decode_to_the_profile_shapes(tmp_path):
    blob, call_hash, call_seq = _tool_chain(tmp_path)
    headers = [hb for hb, _ in iter_records(blob)]
    res = verify_headers(headers)
    assert res.chain_ok is True and res.violations == []

    bodies = _bodies(blob)
    call = bodies[2]
    assert struct.unpack("<H", call[EVT_KIND])[0] == KIND_TOOL_CALL
    assert call[EVT_TOOL_NAME] == b"web.search"
    assert len(call[EVT_PAYLOAD_DIGEST]) == 32

    result = bodies[3]
    assert struct.unpack("<H", result[EVT_KIND])[0] == KIND_TOOL_RESULT
    assert struct.unpack("<Q", result[EVT_REF_SEQ])[0] == call_seq == 2
    assert result[EVT_REF_HASH] == call_hash
    assert struct.unpack("<H", result[EVT_OUTCOME])[0] == OUTCOME_OK

    limit = bodies[4]
    assert struct.unpack("<H", limit[EVT_KIND])[0] == KIND_GUARD_TOOL_LOOP_LIMIT
    assert struct.unpack("<I", limit[EVT_TOKEN_COUNT])[0] == 8
    assert limit[EVT_REF_HASH] == call_hash


def test_writer_tag_set_matches_the_published_vectors(tmp_path):
    """The vectors and the writer describe the same wire shapes."""
    blob, _, _ = _tool_chain(tmp_path)
    bodies = _bodies(blob)
    v = json.loads(VECTORS.read_text())

    def tags_of(seq):
        rec = next(r for r in v["records"] if r["seq"] == seq)
        return set(dict(decode_tlvs(bytes.fromhex(rec["body_hex"]))))

    assert set(bodies[2]) == tags_of(8)  # TOOL_CALL
    assert set(bodies[3]) == tags_of(9)  # TOOL_RESULT
    assert set(bodies[4]) == tags_of(10)  # GUARD_TOOL_LOOP_LIMIT
    # and the kind numbers agree with the published semantics block
    assert v["semantics"]["8"]["kind"] == KIND_TOOL_CALL
    assert v["semantics"]["9"]["kind"] == KIND_TOOL_RESULT
    assert v["semantics"]["10"]["kind"] == KIND_GUARD_TOOL_LOOP_LIMIT


def test_canonical_args_digest_is_order_independent_and_bytes_passthrough():
    a = canonical_tool_args_digest({"b": 1, "a": [2, 3]})
    b = canonical_tool_args_digest({"a": [2, 3], "b": 1})
    assert a == b and len(a) == 32
    raw = b'{"pre":"canonical"}'
    assert canonical_tool_args_digest(raw) == sha256(raw).digest()
    assert canonical_tool_args_digest({"x": 1}) != canonical_tool_args_digest({"x": 2})


def test_format_validation_is_the_writer_contract(tmp_path):
    log = tmp_path / "v.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        with pytest.raises(ValueError):
            w.tool_call("x" * 65)  # name is an identifier, 1..64 bytes
        with pytest.raises(ValueError):
            w.tool_call("")
        with pytest.raises(ValueError):
            w.tool_call("ok", args_digest=b"\x00" * 31)
        call = w.tool_call("ok")
        with pytest.raises(ValueError):
            w.tool_result(2, call, 4)  # outcome outside 0..3
        with pytest.raises(ValueError):
            w.tool_result(2, b"\x00" * 31, OUTCOME_OK)
        with pytest.raises(ValueError):
            w.guard_tool_loop_limit(8, call_seq=2)  # ref pair split
        # cancelled needs no digest — abandonment has no result payload
        w.tool_result(w.seq - 1, call, OUTCOME_CANCELLED)


def test_tool_events_carry_the_session_span(tmp_path):
    log = tmp_path / "span.pala"
    span = bytes(range(16))
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.tool_call("t", span_id=span)
    blob = log.read_bytes()
    hb = [h for h, _ in iter_records(blob)][2]
    assert hb[68:84] == span  # span_id field, per the core layout
