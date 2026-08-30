# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The OpenAI-compatible surface speaks the shapes the ecosystem expects."""
from __future__ import annotations

import json
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402


def _chat_fn(**kwargs):
    assert kwargs["model"] == "demo"
    assert kwargs["messages"][0]["role"] == "user"
    yield ChatChunk(delta="Hel")
    yield ChatChunk(delta="lo")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def _client() -> TestClient:
    return TestClient(create_app(chat_fn=_chat_fn, models_fn=lambda: ["demo"]))


def test_models_lists_the_engine_models():
    r = _client().get("/v1/models")
    assert r.status_code == 200
    assert r.json()["data"][0] == {
        "id": "demo",
        "object": "model",
        "owned_by": "palimpsests",
    }


def test_non_streaming_completion_shape():
    r = _client().post(
        "/v1/chat/completions",
        json={"model": "demo", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion"
    choice = body["choices"][0]
    assert choice["message"] == {"role": "assistant", "content": "Hello"}
    assert choice["finish_reason"] == "stop"
    assert body["usage"]["total_tokens"] == 0  # honest zeros, documented


def test_streaming_is_sse_chunks_with_done_terminator():
    with _client().stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "demo",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        },
    ) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        lines = [ln for ln in r.iter_lines() if ln.startswith("data: ")]
    assert lines[-1] == "data: [DONE]"
    events = [json.loads(ln[6:]) for ln in lines[:-1]]
    assert events[0]["choices"][0]["delta"] == {"role": "assistant"}
    text = "".join(
        e["choices"][0]["delta"].get("content", "") for e in events
    )
    assert text == "Hello"
    assert events[-1]["choices"][0]["finish_reason"] == "stop"


def test_missing_model_is_a_400_in_openai_error_shape():
    r = _client().post("/v1/chat/completions", json={"messages": []})
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "invalid_request_error"


class _FakeAudit:
    """Just enough of NativeAudit for the recording seams."""

    def __init__(self):
        self.calls: list[str] = []
        self.results: list[tuple[int, int]] = []

    def tool_called(self, name, args_digest, span):
        self.calls.append(name)
        return (len(self.calls), b"h" * 32)

    def tool_result(self, seq, call_hash, outcome, result_digest, span):
        self.results.append((seq, outcome))


def _tool_chat_fn(**kwargs):
    yield ChatChunk(
        delta='<tool_call>{"name": "write", "arguments": {"path": "x"}}</tool_call>'
    )
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def test_pending_calls_cancel_on_the_atexit_seam_idempotently():
    """The #189 finding: Windows Ctrl-C can skip ASGI shutdown entirely.

    main()'s atexit closer therefore cancels via ``app.state.cancel_pending``
    right before the writer closes; double delivery must be a no-op.
    """
    from palimpsests.audit.pala_writer import OUTCOME_CANCELLED

    audit = _FakeAudit()
    app = create_app(chat_fn=_tool_chat_fn, models_fn=lambda: ["demo"], audit=audit)
    r = TestClient(app).post(
        "/v1/chat/completions",
        json={
            "model": "demo",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "write"}}],
        },
    )
    assert r.status_code == 200
    assert r.json()["choices"][0]["finish_reason"] == "tool_calls"
    assert audit.calls == ["write"]

    app.state.cancel_pending()
    assert audit.results == [(1, OUTCOME_CANCELLED)]
    app.state.cancel_pending()  # a second delivery changes nothing
    assert audit.results == [(1, OUTCOME_CANCELLED)]
