# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A digest stands for one value, or there is none.

Measured before these rules: ``{"id": 2**53}`` and ``{"id": 2**53 + 1}``
had the same ``EVT_PAYLOAD_DIGEST`` — RFC 8785 writes every number as a
double — so a transfer to one account and to its neighbour were one
digest. And ``{"a": 1, "a": 2}`` had the digest of ``{"a": 2}``: the
repetition was gone before the canonicalizer saw the value, and a reader
that keeps the first value reads another call.

RFC 8785 takes its input from I-JSON (RFC 7493), which rules both out.
An emitter does not choose what a model or a tool sends, so the event is
recorded — without a digest (inference profile §11).
"""
from __future__ import annotations

import hashlib
import json
import pytest
import shutil
import subprocess
import sys
from palimpsests.audit.canonical_json import (
    MAX_SAFE_INTEGER,
    DuplicateKeys,
    canonical_json,
    has_duplicate_keys,
    loads,
)
from palimpsests.audit.pala_writer import (
    PalaWriter,
    _tool_payload_digest,
    canonical_config_digest,
    canonical_tool_args_digest,
)
from palimpsests.audit.reader import AuditReader
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402
from palimpsests.server.tool_calls import parse_tool_calls  # noqa: E402

PROFILES = Path(__file__).resolve().parent.parent / "docs" / "specs" / "pala-1" / "profiles"
VECTORS = PROFILES / "payload-digest-vectors.json"
DIGEST = 0x000D
JSON = {"Content-Type": "application/json"}
BIG = '{"account": 9007199254740993}'
DUP = '{"amount": 1, "amount": 1000}'


# -- integers ------------------------------------------------------------------

def test_the_two_integers_that_were_one_digest_now_have_none():
    assert MAX_SAFE_INTEGER == 2 ** 53 - 1
    for n in (2 ** 53, 2 ** 53 + 1, -(2 ** 53), 12345678901234567890, 2 ** 64, 10 ** 400):
        with pytest.raises(ValueError, match="integer beyond"):
            canonical_json({"id": n})
        assert _tool_payload_digest({"id": n}) is None
        assert _tool_payload_digest([1, {"deep": [n]}]) is None
    with pytest.raises(ValueError):
        canonical_tool_args_digest({"id": 2 ** 53})
    with pytest.raises(ValueError):
        canonical_config_digest({"seed": 2 ** 63})


def test_every_safe_integer_is_digested_and_is_itself():
    for n in (0, 1, -1, 2 ** 31, 2 ** 53 - 1, -(2 ** 53 - 1)):
        assert canonical_json(n) == str(n).encode()
    a, b = (_tool_payload_digest({"id": n}) for n in (2 ** 53 - 2, 2 ** 53 - 1))
    assert a and b and a != b


def test_a_number_written_as_a_double_is_digested_as_one():
    """The rule is about integers, which a parser reads exactly. A number
    with a fraction or an exponent is a double as it stands: RFC 8785."""
    assert canonical_json(loads("9007199254740992.0")) == b"9007199254740992"
    assert canonical_json(loads("1e20")) == b"100000000000000000000"
    assert canonical_json(2.0 ** 63) == b"9223372036854776000"
    assert canonical_json(True) == b"true"  # a bool is not an integer here


# -- repeated keys -------------------------------------------------------------

def test_loads_keeps_a_repeated_key_in_sight():
    value = loads(DUP)
    assert isinstance(value, DuplicateKeys) and value == {"amount": 1000}  # still usable
    assert json.loads(DUP) == {"amount": 1000}  # what an ordinary parser returns: no trace
    assert not isinstance(loads('{"a": 1, "b": 2}'), DuplicateKeys)
    assert type(loads('{"a": 1}')) is dict
    assert isinstance(loads('{"a": 1, "\\u0061": 2}'), DuplicateKeys)  # one key, two spellings
    nested = loads('{"x": [{"y": {"a": 1, "a": 2}}]}')
    assert not isinstance(nested, DuplicateKeys) and has_duplicate_keys(nested)
    assert not has_duplicate_keys(loads('[{"a": 1}, {"a": 2}]'))
    assert loads(b'{"a": 1}') == {"a": 1}
    with pytest.raises(ValueError):
        loads("{not json")


def test_an_object_that_repeats_a_key_has_no_digest_wherever_it_is():
    for text in (DUP, '{"a": 1, "a": 1}', '{"x": {"y": [{"a": 1, "a": 2}]}}',
                 '[1, {"a": 1, "a": 2}]'):
        value = loads(text)
        with pytest.raises(ValueError, match="more than once"):
            canonical_json(value)
        assert _tool_payload_digest(value) is None
    assert _tool_payload_digest(loads('{"amount": 1000}')) is not None


def test_has_duplicate_keys_does_not_recurse():
    deep: object = DuplicateKeys(a=1)
    for _ in range(50_000):
        deep = [deep]
    assert has_duplicate_keys(deep)


# -- the routes ----------------------------------------------------------------

@pytest.fixture
def served(tmp_path):
    log = tmp_path / "s.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    return TestClient(app), app, audit, log


def _tools(log):
    with AuditReader.open(log) as reader:
        assert reader.verify().chain.chain_ok and reader.is_consistent()
        return [(d.kind_name, DIGEST in dict(d.body_tlvs)) for d in reader.records()
                if d.kind_name in ("TOOL_CALL", "TOOL_RESULT")]


def _hook(event, call_id, **fields):
    head = json.dumps({"hook_event_name": event, "tool_name": "transfer",
                       "tool_use_id": call_id, "session_id": "s"})
    extra = "".join(f', "{k}": {v}' for k, v in fields.items())
    return head[:-1] + extra + "}"


@pytest.mark.parametrize("route", ["/v1/pala/hooks/claude", "/v1/pala/hooks/codex"])
@pytest.mark.parametrize("payload", [BIG, DUP])
def test_on_the_hook_routes_the_pair_is_recorded_without_a_digest(served, route, payload):
    client, app, audit, log = served
    # the bad value as the arguments, a plain result
    assert client.post(route, content=_hook("PreToolUse", "a", tool_input=payload),
                       headers=JSON).status_code == 200
    assert client.post(route, content=_hook("PostToolUse", "a", tool_response='"ok"'),
                       headers=JSON).status_code == 200
    # plain arguments, the bad value as the result
    assert client.post(route, content=_hook("PreToolUse", "b", tool_input='{"to": "x"}'),
                       headers=JSON).status_code == 200
    assert client.post(route, content=_hook("PostToolUse", "b", tool_response=payload),
                       headers=JSON).status_code == 200
    app.state.cancel_pending()
    audit.writer.close()
    assert _tools(log) == [("TOOL_CALL", False), ("TOOL_RESULT", True),
                           ("TOOL_CALL", True), ("TOOL_RESULT", False)]


@pytest.mark.parametrize("route", ["/v1/pala/hooks/claude", "/v1/pala/hooks/codex"])
def test_a_hook_report_that_itself_repeats_a_key_is_rejected(served, route):
    """Two tool names: there is no one call to record."""
    client, app, audit, log = served
    body = ('{"hook_event_name": "PreToolUse", "tool_name": "read", "tool_name": "delete", '
            '"tool_use_id": "x", "tool_input": {}}')
    assert json.loads(body)["tool_name"] == "delete"  # what a last-wins parser would record
    r = client.post(route, content=body, headers=JSON)
    assert r.status_code == 400 and "repeats a key" in r.text
    dry = client.post(route, content=body, headers={**JSON, "X-Palimpsests-Dry-Run": "1"})
    assert dry.status_code == 400
    assert client.get("/v1/pala/status").json()["ingest"][route]["rejected"] >= 1
    app.state.cancel_pending()
    audit.writer.close()
    assert _tools(log) == []


@pytest.mark.parametrize("payload", [BIG, DUP])
def test_on_the_events_route_the_call_is_recorded_without_a_digest(served, payload):
    client, app, audit, log = served
    body = ('{"events": [{"type": "tool_call", "id": "c", "name": "transfer", "arguments": '
            + payload + '}, {"type": "tool_result", "call_id": "c", "outcome": "ok"}]}')
    r = client.post("/v1/pala/events", content=body, headers=JSON)
    assert r.status_code == 200 and all("error" not in x for x in r.json()["results"])
    audit.writer.close()
    assert _tools(log) == [("TOOL_CALL", False), ("TOOL_RESULT", False)]


def test_an_event_that_repeats_a_key_is_refused_and_its_neighbours_land(served):
    client, app, audit, log = served
    body = ('{"events": [{"type": "tool_call", "id": "a", "name": "t"}, '
            '{"type": "tool_call", "id": "b", "id": "c", "name": "t"}, '
            '{"type": "tool_result", "call_id": "a", "outcome": "ok"}]}')
    results = client.post("/v1/pala/events", content=body, headers=JSON).json()["results"]
    assert ["error" in x for x in results] == [False, True, False]
    assert "repeats a key" in results[1]["error"]
    audit.writer.close()
    assert [k for k, _ in _tools(log)] == ["TOOL_CALL", "TOOL_RESULT"]


@pytest.mark.parametrize("body, said", [
    ('{"events": [], "events": [{"type": "tool_call", "id": "a", "name": "t"}]}',
     "no key twice"),
    ("[1]", "one JSON object"),
    ('"text"', "one JSON object"),
    ("{not json", "not JSON"),
    (b"\xff\xfe", "not JSON"),
    ("", "not JSON"),
])
def test_a_report_body_that_is_not_one_object_read_one_way_is_a_400(served, body, said):
    client, app, audit, log = served
    r = client.post("/v1/pala/events", content=body, headers=JSON)
    assert r.status_code == 400 and said in r.json()["error"]["message"]
    assert r.json()["error"]["type"] == "invalid_request_error"
    audit.writer.close()
    assert _tools(log) == []


def test_a_report_needs_no_content_type_to_be_read(served):
    """The body is read here, not by the framework: a hook that posts
    JSON without naming it is still a report."""
    client, app, audit, log = served
    r = client.post("/v1/pala/events", content=json.dumps(
        {"events": [{"type": "tool_call", "id": "c", "name": "t"}]}))
    assert r.status_code == 200
    audit.writer.close()
    assert _tools(log) == [("TOOL_CALL", False)]


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


@pytest.mark.parametrize("payload", [BIG, DUP])
def test_a_span_attribute_with_no_canonical_form_is_recorded_without_a_digest(served,
                                                                              payload):
    client, app, audit, log = served
    r = client.post("/v1/traces", content=_otlp(payload, '{"ok": true}'), headers=JSON)
    assert r.status_code == 200, r.text
    audit.writer.close()
    assert _tools(log) == [("TOOL_CALL", False), ("TOOL_RESULT", True)]


def test_an_otlp_export_that_repeats_a_key_is_a_400(served):
    client, app, audit, log = served
    body = _otlp("{}", "{}").replace('"resourceSpans":', '"resourceSpans": [], "resourceSpans":')
    assert json.loads(body)["resourceSpans"]  # a last-wins parser reads the spans
    r = client.post("/v1/traces", content=body, headers=JSON)
    assert r.status_code == 400 and "repeats a key" in r.text
    audit.writer.close()
    assert _tools(log) == []


@pytest.mark.parametrize("payload", [BIG, DUP])
def test_the_models_own_tool_call_keeps_its_arguments_and_loses_only_the_digest(payload):
    text = '<tool_call>{"name": "transfer", "arguments": ' + payload + "}</tool_call>"
    calls, _rest = parse_tool_calls(text)
    assert len(calls) == 1 and calls[0].name == "transfer"
    assert calls[0].arguments == json.loads(payload)  # the tool still runs as before
    assert _tool_payload_digest(calls[0].arguments) is None


# -- the vectors ---------------------------------------------------------------

def test_the_payload_digest_vectors_hold_and_regenerate(tmp_path):
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    digested = refused = 0
    for case in doc["cases"]:
        try:
            value = loads(case["json_text"])
            canonical = canonical_json(value)
        except ValueError:
            assert case.get("digest", 0) is None and case["reason"] in doc["reasons"], case["id"]
            refused += 1
            continue
        assert canonical.hex() == case["canonical_utf8_hex"], case["id"]
        assert hashlib.sha256(canonical).hexdigest() == case["sha256"], case["id"]
        assert canonical_tool_args_digest(value).hex() == case["sha256"]
        digested += 1
    for case in doc["deep_cases"]:
        depth, kind = case["nesting"]["depth"], case["nesting"]["kind"]
        value: object = [] if kind == "array" else 0
        for _ in range(depth - 1 if kind == "array" else depth):
            value = [value] if kind == "array" else {"k": value}
        if "sha256" in case:
            assert hashlib.sha256(canonical_json(value)).hexdigest() == case["sha256"]
            digested += 1
        else:
            assert _tool_payload_digest(value) is None and case["reason"] == "nested_too_deep"
            refused += 1
    assert doc["counts"] == {"digested": digested, "no_digest": refused}
    assert digested == 22 and refused == 15
    used = {c["reason"] for c in doc["cases"] + doc["deep_cases"] if "reason" in c}
    assert used == set(doc["reasons"])  # every reason has a case

    work = tmp_path / "docs" / "specs" / "pala-1" / "profiles"
    work.mkdir(parents=True)
    shutil.copy(PROFILES / "gen_payload_digest_vectors.py", work)
    proc = subprocess.run([sys.executable, str(work / "gen_payload_digest_vectors.py")],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (work / VECTORS.name).read_bytes() == VECTORS.read_bytes()
