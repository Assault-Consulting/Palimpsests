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
