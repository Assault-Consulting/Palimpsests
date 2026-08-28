# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""WS-E token accounting: the engine's counters reach the usage block."""
from __future__ import annotations

from fastapi.testclient import TestClient
from palimpsests.engine.messages import ChatChunk
from palimpsests.server.openai_api import create_app


def _chat_with(prompt_tokens, completion_tokens):
    def chat_fn(**kwargs):
        yield ChatChunk(delta="hi")
        yield ChatChunk(
            done=True,
            finish_reason="stop",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    return chat_fn


def _post(app):
    return TestClient(app).post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "x"}]},
    )


def test_reported_counters_land_in_usage():
    app = create_app(chat_fn=_chat_with(7, 3), models_fn=lambda: ["m"])
    usage = _post(app).json()["usage"]
    assert usage == {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}


def test_unreporting_engines_still_give_zeros():
    app = create_app(chat_fn=_chat_with(None, None), models_fn=lambda: ["m"])
    usage = _post(app).json()["usage"]
    assert usage == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def test_the_tools_branch_carries_usage_too():
    app = create_app(chat_fn=_chat_with(5, 2), models_fn=lambda: ["m"])
    r = TestClient(app).post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "x"}],
            "tools": [{"type": "function", "function": {"name": "t", "parameters": {}}}],
        },
    )
    assert r.json()["usage"]["total_tokens"] == 7
