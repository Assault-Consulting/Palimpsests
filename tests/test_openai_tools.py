# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Function calling on the endpoint — protocol shapes and the r3 record.

The second half is the point: the endpoint is the dispatch boundary it
directly observes, so with an audit adapter injected, handing tool calls
to the client emits TOOL_CALL and the client's posted results emit
TOOL_RESULT, hash-bound — a verifiable r3 trail of the loop, on any
engine level.
"""
from __future__ import annotations

import json
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402
from palimpsests.server.tool_calls import parse_tool_calls  # noqa: E402

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "calc.multiply",
            "description": "Multiply two numbers",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]


def _tool_calling_chat(**kwargs):
    # The tools system message must have been injected by the endpoint.
    assert kwargs["messages"][0]["role"] == "system"
    assert "calc.multiply" in kwargs["messages"][0]["content"]
    yield ChatChunk(delta='<tool_call>{"name": "calc.multiply", ')
    yield ChatChunk(delta='"arguments": {"a": 6, "b": 7}}</tool_call>')
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def _plain_chat(**kwargs):
    yield ChatChunk(delta="just text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


# ─── parser unit behavior ─────────────────────────────────────────────────


def test_parser_extracts_hermes_block_and_strips_it():
    calls, rest = parse_tool_calls(
        'thinking…\n<tool_call>{"name": "t", "arguments": {"x": 1}}</tool_call>'
    )
    assert len(calls) == 1
    assert calls[0].name == "t" and calls[0].arguments == {"x": 1}
    assert "tool_call" not in rest


def test_parser_accepts_bare_json_object():
    calls, rest = parse_tool_calls('{"name": "t", "arguments": {}}')
    assert len(calls) == 1 and rest == ""


def test_parser_leaves_malformed_output_alone():
    calls, rest = parse_tool_calls("<tool_call>{not json}</tool_call>")
    assert calls == [] and "not json" in rest


# ─── endpoint protocol shapes ─────────────────────────────────────────────


def test_tool_call_response_shape():
    client = TestClient(create_app(chat_fn=_tool_calling_chat, models_fn=lambda: []))
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "6*7? use the tool"}],
            "tools": TOOLS,
        },
    )
    assert r.status_code == 200
    choice = r.json()["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    tc = choice["message"]["tool_calls"][0]
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "calc.multiply"
    assert json.loads(tc["function"]["arguments"]) == {"a": 6, "b": 7}


def test_tools_present_but_model_answers_plainly():
    client = TestClient(create_app(chat_fn=_plain_chat, models_fn=lambda: []))
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": TOOLS,
        },
    )
    choice = r.json()["choices"][0]
    assert choice["finish_reason"] == "stop"
    assert choice["message"]["content"] == "just text"
    assert "tool_calls" not in choice["message"]


def test_streaming_with_tools_emits_tool_calls_chunk():
    client = TestClient(create_app(chat_fn=_tool_calling_chat, models_fn=lambda: []))
    with client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "go"}],
            "tools": TOOLS,
            "stream": True,
        },
    ) as r:
        lines = [ln for ln in r.iter_lines() if ln.startswith("data: ")]
    assert lines[-1] == "data: [DONE]"
    events = [json.loads(ln[6:]) for ln in lines[:-1]]
    tc_events = [
        e for e in events if e["choices"][0]["delta"].get("tool_calls")
    ]
    assert len(tc_events) == 1
    assert tc_events[0]["choices"][0]["delta"]["tool_calls"][0]["index"] == 0
    assert events[-1]["choices"][0]["finish_reason"] == "tool_calls"


# ─── the r3 record: the loop, on chain, hash-bound ────────────────────────


def test_endpoint_records_the_loop_into_pala(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader
    from palimpsests.providers.native.audit import NativeAudit

    log = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(
        chat_fn=_tool_calling_chat, models_fn=lambda: [], audit=audit
    )
    client = TestClient(app)

    # Turn 1: the model asks for the tool; the endpoint hands it out.
    r1 = client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "6*7?"}],
            "tools": TOOLS,
        },
    )
    call_id = r1.json()["choices"][0]["message"]["tool_calls"][0]["id"]

    # Turn 2: the client posts the result back.
    # Same app instance keeps the pending map across requests.
    client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [
                {"role": "user", "content": "6*7?"},
                {"role": "tool", "tool_call_id": call_id, "content": "42"},
            ],
            "tools": TOOLS,
        },
    )
    audit.writer.close()

    with AuditReader.open(log) as reader:
        ver = reader.verify()
        kinds = [dr.kind_name for dr in reader.records() if dr.kind_name]
    assert ver.chain.chain_ok is True
    assert kinds.count("TOOL_CALL") >= 1
    assert kinds.count("TOOL_RESULT") >= 1
    # the result resolved to its call: no dangling-reference advisories
    codes = {i.code for i in ver.advisory.items}
    assert "reference_unresolved" not in codes
    assert "reference_hash_mismatch" not in codes
