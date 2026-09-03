# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r5 source mark and the ingestion surface, end to end.

Two properties carry the revision: the default is expressed by absence
(a wire-parsed record's bytes are identical to r4 output), and a
client-reported record is forever distinguishable (``EVT_SOURCE = 1``)
while binding by seq+hash exactly as wire-parsed pairs do.
"""
from __future__ import annotations

import pytest
import struct

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit.pala import decode_tlvs, iter_records  # noqa: E402
from palimpsests.audit.pala_writer import (  # noqa: E402
    EVT_SOURCE,
    OUTCOME_OK,
    SOURCE_REPORTED_BY_CLIENT,
    PalaWriter,
)
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402


def _plain_chat(**kwargs):
    yield ChatChunk(delta="just text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def _last_body_tlvs(path):
    _, body = list(iter_records(path.read_bytes()))[-1]
    return dict(decode_tlvs(body))


# ─── writer: absence is the default, presence is the report ──────────────


def test_wire_parsed_default_emits_no_source_tag(tmp_path):
    p = tmp_path / "wire.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        call = w.tool_call("t")
        w.tool_result(w.seq - 1, call, OUTCOME_OK)
    tlvs = _last_body_tlvs(p)
    assert EVT_SOURCE not in tlvs  # r4-byte-identical by construction


def test_reported_source_round_trips(tmp_path):
    p = tmp_path / "rep.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        call = w.tool_call("t", source=SOURCE_REPORTED_BY_CLIENT)
        w.tool_result(
            w.seq - 1, call, OUTCOME_OK, source=SOURCE_REPORTED_BY_CLIENT
        )
    tlvs = _last_body_tlvs(p)
    assert struct.unpack("<H", tlvs[EVT_SOURCE])[0] == SOURCE_REPORTED_BY_CLIENT


def test_invalid_source_is_refused(tmp_path):
    p = tmp_path / "bad.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        with pytest.raises(ValueError):
            w.tool_call("t", source=7)


# ─── the ingestion surface ───────────────────────────────────────────────


def _audited_app(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter as PW
    from palimpsests.providers.native.audit import NativeAudit

    log = tmp_path / "ingest.pala"
    audit = NativeAudit(PW(log))
    app = create_app(chat_fn=_plain_chat, models_fn=lambda: [], audit=audit)
    return log, audit, TestClient(app)


def test_reported_pair_lands_marked_and_bound(tmp_path):
    from palimpsests.audit.reader import AuditReader

    log, audit, client = _audited_app(tmp_path)
    r1 = client.post(
        "/v1/pala/events",
        json={
            "events": [
                {
                    "type": "tool_call",
                    "id": "c1",
                    "name": "shell.exec",
                    "arguments": {"cmd": "ls"},
                }
            ]
        },
    )
    assert r1.status_code == 200
    call_entry = r1.json()["results"][0]
    assert call_entry["id"] == "c1" and "record_hash" in call_entry

    # The result arrives in a later request — the pending map spans them.
    r2 = client.post(
        "/v1/pala/events",
        json={
            "events": [
                {
                    "type": "tool_result",
                    "call_id": "c1",
                    "outcome": "ok",
                    "content": "file-a\nfile-b",
                }
            ]
        },
    )
    assert r2.status_code == 200
    assert "record_hash" in r2.json()["results"][0]
    audit.writer.close()

    with AuditReader.open(log) as reader:
        ver = reader.verify()
        marked = [
            dr
            for dr in reader.records()
            if dr.kind_name in ("TOOL_CALL", "TOOL_RESULT")
        ]
    assert ver.chain.chain_ok is True
    assert len(marked) == 2
    for dr in marked:
        tlvs = dict(dr.body_tlvs)
        assert struct.unpack("<H", tlvs[EVT_SOURCE])[0] == SOURCE_REPORTED_BY_CLIENT
    # the reported result resolved to its reported call: no dangling refs
    codes = {i.code for i in ver.advisory.items}
    assert "reference_unresolved" not in codes
    assert "reference_hash_mismatch" not in codes


def test_unknown_call_id_is_a_per_event_error(tmp_path):
    log, audit, client = _audited_app(tmp_path)
    before = audit.writer.seq
    r = client.post(
        "/v1/pala/events",
        json={"events": [{"type": "tool_result", "call_id": "ghost"}]},
    )
    assert r.status_code == 200
    assert r.json()["results"][0]["error"] == "unknown call_id"
    assert audit.writer.seq == before  # nothing was written
    audit.writer.close()


def test_ingestion_without_audit_is_503():
    client = TestClient(create_app(chat_fn=_plain_chat, models_fn=lambda: []))
    r = client.post("/v1/pala/events", json={"events": [{"type": "tool_call"}]})
    assert r.status_code == 503


def test_ingestion_sits_behind_the_bearer(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter as PW
    from palimpsests.providers.native.audit import NativeAudit

    audit = NativeAudit(PW(tmp_path / "auth.pala"))
    app = create_app(
        chat_fn=_plain_chat, models_fn=lambda: [], audit=audit, api_key="sk-x"
    )
    client = TestClient(app)
    assert client.post("/v1/pala/events", json={"events": []}).status_code == 401
    ok = client.post(
        "/v1/pala/events",
        json={"events": [{"type": "tool_call", "id": "a", "name": "t"}]},
        headers={"Authorization": "Bearer sk-x"},
    )
    assert ok.status_code == 200
    audit.writer.close()
