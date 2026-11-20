# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The public part of the serve's HTTP surface, held to its document.

``docs/SERVE-SURFACE.md`` gives the reporting routes, the bearer check,
the dry run, the status and the doctor's JSON the class *public*. Every
integration this project ships posts to them, and until 0.15 nothing said
what of them could be relied on. Each test here is a sentence of that
document; objects are open, so the tests ask for the keys the document
names and do not forbid others.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.audit.reader import AuditReader  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

DOC = (Path(__file__).resolve().parent.parent / "docs" / "SERVE-SURFACE.md").read_text(
    encoding="utf-8")
KEY = "sk-surface"
AUTH = {"Authorization": f"Bearer {KEY}"}
DRY = {**AUTH, "X-Palimpsests-Dry-Run": "1"}
REPORTING = ("/v1/pala/events", "/v1/pala/hooks/claude", "/v1/pala/hooks/codex", "/v1/traces")
PRE = {"hook_event_name": "PreToolUse", "tool_name": "Read",
       "tool_input": {"file_path": "x"}, "tool_use_id": "t1", "session_id": "s"}


def _chat(**kwargs):
    yield ChatChunk(delta="text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


@pytest.fixture
def served(tmp_path):
    log = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(log))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit,
                                   api_key=KEY))
    yield client, audit, log
    audit.writer.close()


def _post(client, path, body, headers=AUTH):
    return client.post(path, json=body, headers=headers)


def _records(audit, log):
    with AuditReader.open(log) as reader:
        return list(reader.records())


# -- the routes and their classes --------------------------------------------

def test_every_documented_route_is_served_and_no_reporting_route_is_undocumented(served):
    client, _, _ = served
    served_paths = {r.path for r in client.app.routes if r.path.startswith("/v1/")}
    documented = {"/v1/pala/events", "/v1/pala/hooks/claude", "/v1/pala/hooks/codex",
                  "/v1/pala/status", "/v1/traces", "/v1/chat/completions", "/v1/models"}
    assert served_paths == documented
    for path in documented:
        assert f"`POST {path}`" in DOC or f"`GET {path}`" in DOC
    assert "**public** (since 0.15)" in DOC and "**provisional** (since 0.15)" in DOC
    assert "**compatibility**" in DOC


# -- authentication -----------------------------------------------------------

@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer"},
                                     {"Authorization": "Bearer wrong"},
                                     {"Authorization": KEY}])
@pytest.mark.parametrize("path", [*REPORTING, "/v1/pala/status", "/v1/models"])
def test_every_route_refuses_without_the_key_in_one_shape(served, path, headers):
    client, audit, _ = served
    before = audit.writer.seq
    call = client.get if path in ("/v1/pala/status", "/v1/models") else client.post
    r = call(path, headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_key"
    assert r.json()["error"]["type"] == "invalid_request_error"
    # a reporting route records its first refusal of the run, once (r9);
    # any other route writes nothing
    assert audit.writer.seq == before + (1 if path in REPORTING else 0)
    assert call(path, headers=headers).status_code == 401
    assert audit.writer.seq == before + (1 if path in REPORTING else 0)


def test_without_a_key_the_serve_says_so(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "open.pala"))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit))
    try:
        assert client.get("/v1/pala/status").json()["auth_required"] is False
    finally:
        audit.writer.close()


# -- POST /v1/pala/events -----------------------------------------------------

def test_a_call_and_its_result_are_one_record_each(served):
    client, audit, log = served
    r = _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "c1", "name": "read_file", "arguments": {"path": "a"}},
        {"type": "tool_result", "call_id": "c1", "outcome": "ok", "content": "text"},
    ]})
    assert r.status_code == 200
    call, result = r.json()["results"]
    assert call["id"] == "c1" and isinstance(call["seq"], int)
    assert len(bytes.fromhex(call["record_hash"])) == 32
    assert result["id"] == "c1" and len(bytes.fromhex(result["record_hash"])) == 32
    tools = [d for d in _records(audit, log) if d.source is not None]
    assert [d.source_name for d in tools] == ["reported-by-client"] * 2
    assert [d.kind_name for d in tools] == ["TOOL_CALL", "TOOL_RESULT"]
    assert tools[0].seq == call["seq"] and tools[1].outcome_name == "ok"


def test_an_outcome_not_stated_is_unobserved_not_ok(served):
    client, audit, log = served
    _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "c1", "name": "t"},
        {"type": "tool_result", "call_id": "c1"}]})
    result = [d for d in _records(audit, log) if d.outcome is not None][-1]
    assert result.outcome_name == "unobserved"


@pytest.mark.parametrize("outcome", ["ok", "error", "timeout", "cancelled", "unobserved"])
def test_the_five_outcomes_are_the_documented_ones(served, outcome):
    client, audit, log = served
    r = _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "c", "name": "t"},
        {"type": "tool_result", "call_id": "c", "outcome": outcome}]})
    assert "error" not in r.json()["results"][1]
    assert f"`{outcome}`" in DOC
    result = [d for d in _records(audit, log) if d.outcome is not None][-1]
    assert result.outcome_name == outcome


def test_a_batch_is_not_all_or_nothing(served):
    """One entry per event, in order; an event that could not be recorded
    has ``error``, and the events around it are recorded all the same."""
    client, audit, _ = served
    before = audit.writer.seq
    r = _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "a", "name": "t"},
        {"type": "tool_result", "call_id": "never-reported"},
        {"type": "tool_result", "call_id": "a", "outcome": "splendid"},
        {"type": "no_such_type"},
        "not an object",
        {"type": "tool_call", "name": "no id"},
        {"type": "tool_call", "id": "b", "name": "t", "args_digest": "ab" * 32},
    ]})
    assert r.status_code == 200
    results = r.json()["results"]
    assert len(results) == 7
    assert ["error" in x for x in results] == [False, True, True, True, True, True, False]
    assert audit.writer.seq == before + 2
    # the call whose result named no known outcome stays open
    assert client.get("/v1/pala/status", headers=AUTH).json()["pending_calls"] == 2


@pytest.mark.parametrize("body", [{}, {"events": []}, {"events": "x"}, {"events": {"a": 1}}])
def test_events_that_are_not_a_non_empty_list_are_400(served, body):
    client, audit, _ = served
    before = audit.writer.seq
    r = _post(client, "/v1/pala/events", body)
    assert r.status_code == 400 and "message" in r.json()["error"]
    # no tool event; the rejection itself is noted once per route (profile r9)
    assert audit.writer.seq == before + 1
    assert _post(client, "/v1/pala/events", body).status_code == 400
    assert audit.writer.seq == before + 1


def test_a_digest_given_is_used_as_given_and_nothing_else_is_stored(served):
    client, audit, log = served
    secret = "the argument that must not be on the chain"
    _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "c", "name": "t", "arguments": {"q": secret}},
        {"type": "tool_result", "call_id": "c", "content": secret}]})
    audit.writer.close()
    assert secret.encode() not in log.read_bytes()


# -- the hook routes ----------------------------------------------------------

@pytest.mark.parametrize("route", ["/v1/pala/hooks/claude", "/v1/pala/hooks/codex"])
def test_a_hook_reply_never_carries_a_decision(served, route):
    client, audit, _ = served
    before = audit.writer.seq
    post = {**PRE, "hook_event_name": "PostToolUse", "tool_response": {"ok": True}}
    for body in (PRE, PRE, post, post, {"hook_event_name": "UserPromptSubmit"},
                 {"hook_event_name": "SessionStart"}):
        r = _post(client, route, body)
        assert (r.status_code, r.json()) == (200, {})
    assert audit.writer.seq == before + 2  # delivered twice, recorded once; others not at all


def test_what_a_post_means_depends_on_the_agent(served):
    client, audit, log = served
    for route, call_id in (("/v1/pala/hooks/claude", "a"), ("/v1/pala/hooks/codex", "b")):
        _post(client, route, {**PRE, "tool_use_id": call_id})
        _post(client, route, {**PRE, "tool_use_id": call_id,
                              "hook_event_name": "PostToolUse", "tool_response": "r"})
    _post(client, "/v1/pala/hooks/claude", {**PRE, "tool_use_id": "c"})
    _post(client, "/v1/pala/hooks/claude", {**PRE, "tool_use_id": "c",
                                            "hook_event_name": "PostToolUseFailure",
                                            "error": "boom"})
    outcomes = [d.outcome_name for d in _records(audit, log)
                if d.outcome is not None]
    assert outcomes == ["ok", "unobserved", "error"]


def test_what_the_hook_routes_refuse(served):
    client, audit, _ = served
    before = audit.writer.seq
    assert _post(client, "/v1/pala/hooks/claude",
                 {"hook_event_name": "PreToolUse"}).status_code == 400
    assert _post(client, "/v1/pala/hooks/codex",
                 {**PRE, "hook_event_name": "PostToolUseFailure"}).status_code == 400
    assert client.post("/v1/pala/hooks/claude", content=b"[1]", headers={
        **AUTH, "content-type": "application/json"}).status_code in (400, 422)
    # no tool event; one REPORTS_REFUSED per route for its first rejection (r9)
    assert audit.writer.seq == before + 2


# -- the dry run --------------------------------------------------------------

def test_a_dry_run_says_what_would_be_recorded_and_writes_nothing(served):
    client, audit, _ = served
    before = (audit.writer.seq, client.get("/v1/pala/status", headers=AUTH).json())
    r = _post(client, "/v1/pala/events", {"events": [
        {"type": "tool_call", "id": "c1", "name": "read_file", "arguments": {}},
        {"type": "tool_result", "call_id": "c1", "outcome": "ok"}]}, DRY)
    body = r.json()
    assert body["dry_run"] is True
    call, result = body["would_record"]
    assert call == {"record": "TOOL_CALL", "tool": "read_file",
                    "source": "reported-by-client", "payload_digest": True}
    assert (result["record"], result["outcome"], result["source"]) == (
        "TOOL_RESULT", "ok", "reported-by-client")
    assert all("seq" not in x and "record_hash" not in x for x in body["results"])

    hook = _post(client, "/v1/pala/hooks/claude", PRE, DRY).json()
    assert hook["dry_run"] is True and hook["reply"] == {}
    assert hook["would_record"][0]["record"] == "TOOL_CALL"

    after = client.get("/v1/pala/status", headers=AUTH).json()
    assert audit.writer.seq == before[0]
    assert after["pending_calls"] == before[1]["pending_calls"] == 0
    assert after["ingest"]["/v1/pala/events"]["accepted"] == 0
    assert after["ingest"]["/v1/pala/events"]["dry_run"] == 1
    assert after["chain"] == before[1]["chain"]


def test_a_dry_run_still_needs_the_key(served):
    client, _, _ = served
    r = client.post("/v1/pala/events", json={"events": [{"type": "tool_call"}]},
                    headers={"X-Palimpsests-Dry-Run": "1"})
    assert r.status_code == 401


# -- the status ---------------------------------------------------------------

def test_the_status_has_the_documented_shape(served):
    client, audit, _ = served
    _post(client, "/v1/pala/events", {"events": [{"type": "tool_call", "id": "c",
                                                  "name": "t"}]})
    s = client.get("/v1/pala/status", headers=AUTH).json()
    assert s["format"] == "pala-serve-status/1" and s["auth_required"] is True
    assert set(s["ingest"]) == set(REPORTING)
    for entry in s["ingest"].values():
        assert {"accepted", "refused", "rejected", "dry_run", "last_accepted_ns",
                "last_refused_ns"} <= set(entry)
        assert {"empty_bearer", "wrong_bearer"} <= set(entry["refused"])
    assert s["pending_calls"] == 1
    assert s["chain"]["records"] == audit.writer.seq
    assert s["chain"]["head"] == audit.writer.head_hex
    assert s["chain"]["durability"] == "record"
    example = json.loads(DOC.split("```json", 4)[4].split("```", 1)[0])
    assert set(example) == set(s), "the document's example names another set of keys"


def test_reading_the_status_writes_nothing(served):
    client, audit, _ = served
    before = audit.writer.seq
    for _ in range(3):
        client.get("/v1/pala/status", headers=AUTH)
    assert audit.writer.seq == before


def test_a_serve_without_a_chain_says_so_on_every_reporting_route():
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], api_key=KEY))
    assert client.get("/v1/pala/status", headers=AUTH).json()["chain"] is None
    bodies = {"/v1/pala/events": {"events": [{"type": "tool_call", "id": "c", "name": "t"}]},
              "/v1/pala/hooks/claude": PRE, "/v1/pala/hooks/codex": PRE,
              "/v1/traces": {"resourceSpans": []}}
    for route, body in bodies.items():
        assert _post(client, route, body).status_code == 503, route


# -- the doctor's JSON --------------------------------------------------------

def test_the_doctors_json_has_the_documented_shape():
    from palimpsests import doctor

    findings = [doctor.Finding(doctor.OK, "serve_reachable", "it answered"),
                doctor.Finding(doctor.FAIL, "serve_key_refused", "refused", "set the key")]
    out = doctor.to_json("claude-code", findings)
    assert out["format"] == "pala-doctor/1" and out["integration"] == "claude-code"
    assert out["ok"] is False and doctor.exit_code(findings) == 1
    assert [set(f) for f in out["findings"]] == [{"level", "code", "message", "fix"}] * 2
    assert (doctor.OK, doctor.WARN, doctor.FAIL) == ("ok", "warn", "fail")
    assert doctor.to_json("x", findings[:1])["ok"] is True
    assert doctor.exit_code([doctor.Finding(doctor.WARN, "w", "m")]) == 0
