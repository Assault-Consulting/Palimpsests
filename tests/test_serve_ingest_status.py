# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""R1 (0.15) — the serve says what reached it.

A client whose reports are refused, or never sent, looks normal from its
own side. Measured: Claude Code sent 4 of 26 hook posts with an empty
bearer (run R1); OpenCode without the key got 401 and the tool ran
(OpenCode run 3); Codex skipped untrusted hooks without a word (run R2).
``GET /v1/pala/status`` counts, per ingestion route, what was accepted,
what the bearer check refused (empty apart from wrong), and what was
rejected otherwise — and writes nothing to the chain.
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

KEY = "sk-status"
AUTH = {"Authorization": f"Bearer {KEY}"}
CALL = {"events": [{"type": "tool_call", "id": "c1", "name": "read"}]}
HOOK = {"hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": "x"}, "tool_use_id": "t1", "session_id": "s"}


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


def _status(client):
    r = client.get("/v1/pala/status", headers=AUTH)
    assert r.status_code == 200
    return r.json()


def test_refusals_are_counted_by_kind_and_route(served):
    client, _ = served
    assert client.post("/v1/pala/hooks/claude", json=HOOK).status_code == 401
    assert client.post("/v1/pala/hooks/claude", json=HOOK,
                       headers={"Authorization": "Bearer"}).status_code == 401
    assert client.post("/v1/pala/events", json=CALL,
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    s = _status(client)
    assert s["format"] == "pala-serve-status/1" and s["auth_required"] is True
    claude = s["ingest"]["/v1/pala/hooks/claude"]
    assert claude["refused"] == {"empty_bearer": 2, "wrong_bearer": 0}
    assert claude["accepted"] == 0 and claude["last_refused_ns"] is not None
    events = s["ingest"]["/v1/pala/events"]
    assert events["refused"] == {"empty_bearer": 0, "wrong_bearer": 1}


def test_accepted_and_rejected_reports_are_counted(served):
    client, _ = served
    assert client.post("/v1/pala/events", json=CALL, headers=AUTH).status_code == 200
    assert client.post("/v1/pala/events", json=[], headers=AUTH).status_code == 422
    events = _status(client)["ingest"]["/v1/pala/events"]
    assert events["accepted"] == 1 and events["rejected"] == 1
    assert events["last_accepted_ns"] is not None
    assert _status(client)["pending_calls"] == 1  # a call with no result yet


def test_status_reads_the_chain_and_writes_nothing(served):
    client, audit = served
    client.post("/v1/pala/events", json=CALL, headers=AUTH)
    before = (audit.writer.seq, audit.writer.head_hex)
    s = _status(client)
    _status(client)
    assert (audit.writer.seq, audit.writer.head_hex) == before
    assert s["chain"] == {"records": before[0], "head": before[1]}


def test_status_is_behind_the_bearer_and_is_not_itself_counted(served):
    client, _ = served
    assert client.get("/v1/pala/status").status_code == 401
    s = _status(client)
    assert all(e["refused"] == {"empty_bearer": 0, "wrong_bearer": 0}
               for e in s["ingest"].values())


def test_a_serve_without_a_key_says_so(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "open.pala"))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit))
    try:
        s = client.get("/v1/pala/status").json()
        assert s["auth_required"] is False
        assert set(s["ingest"]) == {"/v1/pala/hooks/claude", "/v1/pala/hooks/codex",
                                    "/v1/pala/events", "/v1/traces"}
    finally:
        audit.writer.close()
