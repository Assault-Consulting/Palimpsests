# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A deeply nested payload costs the digest, never the record of the call.

The defect: the canonicalizer recursed once per level, so a tool argument
or result nested past about a thousand levels raised ``RecursionError``.
The digest helper caught ``ValueError`` only. On the hook route a deep
``tool_input`` left nothing on the chain; a deep ``tool_response`` left a
call without its result, and one no longer closed as cancelled at the stop.
What a tool returns comes from outside — a page, an API, a file — so the
party controlling it could remove the record of the call that fetched it.

The rule (inference profile §11): a value nested deeper than 128 arrays and
objects has no canonical form; the event is recorded without a digest.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.canonical_json import MAX_DEPTH, canonical_json
from palimpsests.audit.pala_writer import (
    PalaWriter,
    _tool_payload_digest,
    canonical_config_digest,
    canonical_tool_args_digest,
)
from palimpsests.audit.reader import AuditReader

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.agent_hooks import HookIngest  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402
from palimpsests.server.tool_calls import parse_tool_calls  # noqa: E402

DIGEST = 0x000D  # EVT_PAYLOAD_DIGEST
DEPTHS = (MAX_DEPTH + 1, 1200, 3000)  # one past the rule; past the old stack; well past


def _text(depth: int, *, array: bool = True) -> str:
    """JSON text nested ``depth`` containers deep, built without recursion."""
    if array:
        return "[" * depth + "]" * depth
    return '{"k":' * depth + "0" + "}" * depth


def _value(depth: int, *, array: bool = True):
    return json.loads(_text(depth, array=array))


def _tools(log):
    with AuditReader.open(log) as reader:
        ver = reader.verify()
        assert ver.chain.chain_ok and reader.is_consistent()
        codes = {i.code for i in ver.advisory.items}
        recs = [d for d in reader.records() if d.kind_name in ("TOOL_CALL", "TOOL_RESULT")]
    assert not codes & {"reference_hash_mismatch", "reference_unresolved",
                        "tool_call_without_result"}, codes
    return recs


def _has_digest(record) -> bool:
    return DIGEST in dict(record.body_tlvs)


# -- the rule ------------------------------------------------------------------

def test_the_limit_is_128_containers_and_one_more_has_no_form():
    assert MAX_DEPTH == 128
    for array in (True, False):
        assert canonical_json(_value(MAX_DEPTH, array=array)) == _text(
            MAX_DEPTH, array=array).encode()
        with pytest.raises(ValueError, match="nested deeper than 128"):
            canonical_json(_value(MAX_DEPTH + 1, array=array))
    # a scalar is not a level: 128 containers around a number is still 128
    assert canonical_json(json.loads("[" * 128 + "1" + "]" * 128))
    # mixed nesting counts both kinds
    mixed = json.loads('[{"k":' * 64 + "1" + "}]" * 64)
    assert canonical_json(mixed)
    with pytest.raises(ValueError):
        canonical_json([mixed])
    # width is not depth
    assert canonical_json([[i] for i in range(10_000)])


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("array", [True, False])
def test_a_deep_value_is_refused_by_name_never_by_the_stack(depth, array):
    value = _value(depth, array=array)
    with pytest.raises(ValueError):
        canonical_json(value)
    with pytest.raises(ValueError):
        canonical_tool_args_digest(value)
    with pytest.raises(ValueError):
        canonical_config_digest({"sampling": value})
    assert _tool_payload_digest(value) is None
    assert _tool_payload_digest({"q": value}) is None


def test_the_helper_survives_a_stack_error_whatever_raised_it(monkeypatch):
    import palimpsests.audit.pala_writer as pw

    def boom(_value):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(pw, "canonical_tool_args_digest", boom)
    assert pw._tool_payload_digest({"a": 1}) is None


def test_a_value_at_the_limit_is_still_digested():
    assert len(_tool_payload_digest(_value(MAX_DEPTH))) == 32
    # one level is spent on the arguments object itself
    assert _tool_payload_digest({"q": _value(MAX_DEPTH - 1)}) is not None
    assert _tool_payload_digest({"q": _value(MAX_DEPTH)}) is None


# -- the hook routes -----------------------------------------------------------

def _hook_body(event, call_id, field, depth):
    return ('{"hook_event_name":"%s","tool_name":"WebFetch","tool_use_id":"%s",'
            '"session_id":"s","%s":{"page":%s}}' % (event, call_id, field, _text(depth)))


@pytest.mark.parametrize("route", ["/v1/pala/hooks/claude", "/v1/pala/hooks/codex"])
@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_hook_payload_leaves_the_pair_on_the_chain(tmp_path, route, depth):
    log = tmp_path / "h.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    client = TestClient(app)
    post = {"headers": {"Content-Type": "application/json"}}
    # deep arguments, plain result
    assert client.post(route, content=_hook_body("PreToolUse", "a", "tool_input", depth),
                       **post).status_code == 200
    assert client.post(route, content=json.dumps({
        "hook_event_name": "PostToolUse", "tool_name": "WebFetch", "tool_use_id": "a",
        "session_id": "s", "tool_response": "ok"}), **post).status_code == 200
    # plain arguments, deep result — what a fetched page can do
    assert client.post(route, content=json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_use_id": "b",
        "session_id": "s", "tool_input": {"url": "u"}}), **post).status_code == 200
    assert client.post(route, content=_hook_body("PostToolUse", "b", "tool_response", depth),
                       **post).status_code == 200
    # a result whose call was never seen, deep on both sides
    both = _hook_body("PostToolUse", "c", "tool_input", depth)[:-1] + (
        ',"tool_response":%s}' % _text(depth))
    assert client.post(route, content=both, **post).status_code == 200
    app.state.cancel_pending()
    audit.writer.close()
    recs = _tools(log)
    assert [d.kind_name for d in recs] == ["TOOL_CALL", "TOOL_RESULT"] * 3
    assert [_has_digest(d) for d in recs] == [False, True, True, False, False, False]
    assert all(d.outcome_name != "cancelled" for d in recs if d.kind_name == "TOOL_RESULT")


def test_a_call_leaves_pending_only_when_its_result_is_written(tmp_path):
    """Whatever fails between reading the call and writing its result, the
    call is still there to be closed as cancelled at the stop."""
    log = tmp_path / "h.pala"
    audit = NativeAudit(PalaWriter(log))
    pending: dict = {}
    ingest = HookIngest(audit, pending, client="claude")
    ingest.handle({"hook_event_name": "PreToolUse", "tool_name": "T", "tool_use_id": "x",
                   "tool_input": {}})
    real = audit.tool_result
    calls = []

    def failing(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("disk refused the write")
        return real(*a, **k)

    audit.tool_result = failing
    with pytest.raises(OSError):
        ingest.handle({"hook_event_name": "PostToolUse", "tool_name": "T",
                       "tool_use_id": "x", "tool_response": "r"})
    assert len(pending) == 1  # not lost
    # the client's retry lands
    assert ingest.handle({"hook_event_name": "PostToolUse", "tool_name": "T",
                          "tool_use_id": "x", "tool_response": "r"})[0] == 200
    assert not pending
    audit.writer.close()
    assert [d.kind_name for d in _tools(log)] == ["TOOL_CALL", "TOOL_RESULT"]


# -- the events route ----------------------------------------------------------

@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_argument_on_the_events_route_is_recorded_without_a_digest(tmp_path, depth):
    log = tmp_path / "e.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    client = TestClient(app)
    body = ('{"events":[{"type":"tool_call","id":"c","name":"t","arguments":{"a":%s}},'
            '{"type":"tool_result","call_id":"c","outcome":"ok","content":"r"}]}'
            % _text(depth))
    r = client.post("/v1/pala/events", content=body,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 200 and not [x for x in r.json()["results"] if "error" in x]
    audit.writer.close()
    recs = _tools(log)
    assert [(d.kind_name, _has_digest(d)) for d in recs] == [
        ("TOOL_CALL", False), ("TOOL_RESULT", True)]


def test_a_result_event_refused_for_its_digest_leaves_the_call_open(tmp_path):
    log = tmp_path / "e.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    client = TestClient(app)
    client.post("/v1/pala/events", json={"events": [
        {"type": "tool_call", "id": "c", "name": "t"}]})
    bad = client.post("/v1/pala/events", json={"events": [
        {"type": "tool_result", "call_id": "c", "outcome": "ok", "result_digest": "zz"}]})
    assert "invalid event" in bad.json()["results"][0]["error"]
    good = client.post("/v1/pala/events", json={"events": [
        {"type": "tool_result", "call_id": "c", "outcome": "ok",
         "result_digest": "ab" * 32}]})
    assert "record_hash" in good.json()["results"][0]  # the corrected report lands
    audit.writer.close()
    recs = _tools(log)
    assert [d.kind_name for d in recs] == ["TOOL_CALL", "TOOL_RESULT"]
    assert recs[1].outcome_name == "ok"


# -- telemetry -----------------------------------------------------------------

def _otlp(args: str, result: str) -> str:
    def attr(key, value):
        return {"key": key, "value": {"stringValue": value}}

    span = {"traceId": "0af7651916cd43dd8448eb211c80319c", "spanId": "0000000000000001",
            "name": "execute_tool t", "startTimeUnixNano": "100",
            "endTimeUnixNano": "200", "status": {"code": 0},
            "attributes": [attr("gen_ai.operation.name", "execute_tool"),
                           attr("gen_ai.tool.name", "t"),
                           attr("gen_ai.tool.call.arguments", args),
                           attr("gen_ai.tool.call.result", result)]}
    return json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]})


@pytest.mark.parametrize("depth", (*DEPTHS, 60_000))  # the last: past the parser's own stack
def test_a_deep_span_attribute_is_recorded_without_a_digest(tmp_path, depth):
    log = tmp_path / "t.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    r = TestClient(app).post("/v1/traces", content=_otlp(_text(depth), _text(depth)),
                             headers={"Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    audit.writer.close()
    recs = _tools(log)
    assert [(d.kind_name, _has_digest(d)) for d in recs] == [
        ("TOOL_CALL", False), ("TOOL_RESULT", False)]
    assert _text(depth).encode()[:300] not in log.read_bytes()


def test_a_span_attribute_that_is_not_json_is_still_digested_as_the_string(tmp_path):
    log = tmp_path / "t.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    TestClient(app).post("/v1/traces", content=_otlp("not json [", '{"n": 1}'),
                         headers={"Content-Type": "application/json"})
    audit.writer.close()
    call, result = _tools(log)
    assert dict(call.body_tlvs)[DIGEST] == canonical_tool_args_digest("not json [")
    assert dict(result.body_tlvs)[DIGEST] == canonical_tool_args_digest({"n": 1})


def test_an_otlp_body_too_deep_to_read_is_a_400_not_a_500(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "t.pala"))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    r = TestClient(app, raise_server_exceptions=False).post(
        "/v1/traces", content=_text(60_000),
        headers={"Content-Type": "application/json"})
    assert r.status_code == 400 and "nested too deeply" in r.text
    audit.writer.close()


# -- the model's own tool calls ------------------------------------------------

@pytest.mark.parametrize("depth", (*DEPTHS, 60_000))
def test_a_deep_tool_call_in_the_models_text_does_not_break_the_parser(depth):
    text = '<tool_call>{"name": "t", "arguments": {"a": %s}}</tool_call>' % _text(depth)
    calls, _remaining = parse_tool_calls(text)  # no exception is the point
    for call in calls:
        assert _tool_payload_digest(call.arguments) is None


# -- past the parser -----------------------------------------------------------

@pytest.mark.parametrize("route, body", [
    ("/v1/pala/hooks/claude", '{"hook_event_name":"PreToolUse","tool_name":"T",'
                              '"tool_use_id":"x","tool_input":%s}'),
    ("/v1/pala/hooks/codex", '{"hook_event_name":"PreToolUse","tool_name":"T",'
                             '"tool_use_id":"x","tool_input":%s}'),
    ("/v1/pala/events", '{"events":[{"type":"tool_call","id":"c","name":"t",'
                        '"arguments":%s}]}'),
])
def test_a_body_too_deep_for_the_parser_is_rejected_and_counted(tmp_path, route, body):
    """Past some tens of thousands of levels the JSON parser itself gives up.
    Nothing can be recorded of a body that cannot be read; it is answered
    4xx, never 500, and the status counts it as rejected."""
    audit = NativeAudit(PalaWriter(tmp_path / "p.pala"))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.post(route, content=body % _text(60_000),
                    headers={"Content-Type": "application/json"})
    assert 400 <= r.status_code < 500
    assert client.get("/v1/pala/status").json()["ingest"][route]["rejected"] == 1
    audit.writer.close()
