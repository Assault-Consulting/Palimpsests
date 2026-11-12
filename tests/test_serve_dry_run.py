# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""R1 (0.15), part 2 — a dry run of the ingestion path.

A check of an integration must not write a test call onto the audit chain:
the chain is append-only, and a call nobody made would stay in it. With
``X-Palimpsests-Dry-Run: 1`` a request passes the real bearer check and the
real ingestion code, the reply says what would have been recorded, and the
chain, the pending calls and the accepted counters stay as they were.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

KEY = "sk-dry"
AUTH = {"Authorization": f"Bearer {KEY}"}
DRY = {**AUTH, "X-Palimpsests-Dry-Run": "1"}
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "otel"


def _chat(**kwargs):
    yield ChatChunk(delta="text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


@pytest.fixture
def served(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "serve.pala"))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit,
                                   api_key=KEY))
    yield client, audit
    audit.writer.close()


def _state(client, audit):
    s = client.get("/v1/pala/status", headers=AUTH).json()
    return audit.writer.seq, audit.writer.head_hex, s["pending_calls"]


def _hook(event, **extra):
    return {"hook_event_name": event, "tool_name": "Read", "tool_use_id": "doctor-1",
            "tool_input": {"file_path": "x"}, "session_id": "s", **extra}


def test_a_dry_event_says_what_it_would_record_and_records_nothing(served):
    client, audit = served
    before = _state(client, audit)
    r = client.post("/v1/pala/events", headers=DRY, json={"events": [
        {"type": "tool_call", "id": "d1", "name": "read", "arguments": {"p": 1}},
        {"type": "tool_result", "call_id": "d1", "outcome": "ok", "content": "x"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["dry_run"] is True
    assert body["would_record"] == [
        {"record": "TOOL_CALL", "tool": "read", "source": "reported-by-client",
         "payload_digest": True},
        {"record": "TOOL_RESULT", "outcome": "ok", "source": "reported-by-client",
         "payload_digest": True},
    ]
    assert all("seq" not in x and "record_hash" not in x for x in body["results"])
    assert _state(client, audit) == before  # chain and pending calls untouched
    events = client.get("/v1/pala/status", headers=AUTH).json()["ingest"]["/v1/pala/events"]
    assert events["dry_run"] == 1 and events["accepted"] == 0


@pytest.mark.parametrize(("route", "outcome"), [
    ("/v1/pala/hooks/claude", "ok"),            # Claude Code reports failures apart
    ("/v1/pala/hooks/codex", "unobserved"),     # Codex cannot tell a failure
])
def test_a_dry_hook_runs_the_clients_own_outcome_rule(served, route, outcome):
    client, audit = served
    before = _state(client, audit)
    pre = client.post(route, headers=DRY, json=_hook("PreToolUse")).json()
    assert [w["record"] for w in pre["would_record"]] == ["TOOL_CALL"]
    # The Pre above wrote nothing, so the Post finds no call and says it would
    # record both — exactly what the real route does for a result with no call.
    post = client.post(route, headers=DRY,
                       json=_hook("PostToolUse", tool_response={"ok": 1})).json()
    assert [w["record"] for w in post["would_record"]] == ["TOOL_CALL", "TOOL_RESULT"]
    assert post["would_record"][1]["outcome"] == outcome
    assert post["reply"] == {}  # what the agent itself would have been sent
    assert _state(client, audit) == before


def test_a_dry_result_leaves_a_really_pending_call_pending(served):
    client, audit = served
    call = {"events": [{"type": "tool_call", "id": "real", "name": "read"}]}
    assert client.post("/v1/pala/events", headers=AUTH, json=call).status_code == 200
    before = _state(client, audit)
    assert before[2] == 1
    result = {"events": [{"type": "tool_result", "call_id": "real", "outcome": "ok"}]}
    dry = client.post("/v1/pala/events", headers=DRY, json=result).json()
    assert [w["record"] for w in dry["would_record"]] == ["TOOL_RESULT"]
    assert _state(client, audit) == before  # still pending: the dry run took a copy
    real = client.post("/v1/pala/events", headers=AUTH, json=result).json()
    assert "record_hash" in real["results"][0]  # and the real result still lands
    assert _state(client, audit)[2] == 0


def test_a_dry_run_goes_through_the_real_bearer_check(served):
    client, audit = served
    r = client.post("/v1/pala/hooks/claude", json=_hook("PreToolUse"),
                    headers={"X-Palimpsests-Dry-Run": "1"})
    assert r.status_code == 401
    claude = client.get("/v1/pala/status",
                        headers=AUTH).json()["ingest"]["/v1/pala/hooks/claude"]
    assert claude["refused"]["empty_bearer"] == 1 and claude["dry_run"] == 0


def test_a_dry_run_is_refused_for_the_same_reasons_as_a_real_one(served):
    client, audit = served
    before = _state(client, audit)
    bad = client.post("/v1/pala/hooks/claude", headers=DRY,
                      json={"hook_event_name": "PreToolUse"})
    assert bad.status_code == 400 and bad.json()["would_record"] == []
    assert client.post("/v1/pala/events", headers=DRY, json={"events": []}).status_code == 400
    assert _state(client, audit) == before


def _otel_export() -> bytes:
    """A real framework's OTLP/protobuf export, recorded once (pydantic-ai)."""
    import base64
    import gzip

    lines = (FIXTURES / "pydantic-ai-2.57.0.otlp.pb.gz.b64").read_text().splitlines()
    return gzip.decompress(base64.b64decode("".join(ln for ln in lines if not ln.startswith("#"))))


def test_a_dry_trace_export_says_what_it_would_record(served):
    pytest.importorskip("opentelemetry.proto")
    client, audit = served
    export = _otel_export()
    proto = {"Content-Type": "application/x-protobuf"}
    before = _state(client, audit)
    r = client.post("/v1/traces", content=export, headers={**DRY, **proto})
    assert r.status_code == 200
    body = r.json()  # a dry run answers in JSON whatever the request's encoding
    assert body["dry_run"] is True
    kinds = [w["record"] for w in body["would_record"]]
    assert kinds and kinds.count("TOOL_CALL") == kinds.count("TOOL_RESULT")
    assert _state(client, audit) == before
    # the same export, for real, records what the dry run said it would
    assert client.post("/v1/traces", content=export, headers={**AUTH, **proto}).status_code == 200
    assert audit.writer.seq - before[0] == len(kinds)


def test_without_the_header_nothing_changes(served):
    client, audit = served
    r = client.post("/v1/pala/hooks/claude", headers=AUTH, json=_hook("PreToolUse"))
    assert r.status_code == 200 and r.json() == {}
    assert json.loads(r.content) == {} and _state(client, audit)[2] == 1
