# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""An OpenAI-compatible endpoint over the engine — the same interface,
with an evidence trail.

``POST /v1/chat/completions`` (streaming and not) and ``GET /v1/models``,
in the request/response shapes the ecosystem already speaks, served by
whatever engine is active — so any existing client connects by changing
one base URL. Everything the engine records (sessions, operations, guard
refusals) is recorded exactly as for any other caller: compatibility is
the door; the audit trail is what is behind it.

Scope of this first version, stated rather than implied: chat and
streaming. ``tools`` in a request are accepted and echoed into scope
documentation territory — function-calling emission depends on the
model's output format and lands as its own change. ``usage`` is
reported as zeros (token accounting is engine-level work). There is no
authentication: this binds to localhost by default and is a local tool,
not an internet service — put a real gateway in front of it otherwise.

The module is import-safe without the ``serve`` extra; constructing the
app is what requires FastAPI.
"""
from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from palimpsests.engine.messages import ChatChunk

ChatFn = Callable[..., Iterator[ChatChunk]]
ModelsFn = Callable[[], Sequence[str]]


@dataclass(frozen=True)
class _Deps:
    chat_fn: ChatFn
    models_fn: ModelsFn


def _default_deps() -> _Deps:
    from palimpsests.core import chat as core_chat
    from palimpsests.core import init_app, list_models

    ctx = init_app()

    def chat_fn(**kwargs) -> Iterator[ChatChunk]:
        return core_chat(ctx, **kwargs)

    def models_fn() -> list[str]:
        return [m.name for m in list_models(ctx)]

    return _Deps(chat_fn=chat_fn, models_fn=models_fn)


def create_app(*, chat_fn: ChatFn | None = None, models_fn: ModelsFn | None = None):
    """Build the FastAPI app. Dependencies are injectable for tests."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, StreamingResponse

    deps: _Deps | None = (
        _Deps(chat_fn=chat_fn, models_fn=models_fn)
        if chat_fn is not None and models_fn is not None
        else None
    )

    app = FastAPI(title="Palimpsests", docs_url=None, redoc_url=None)

    def _deps() -> _Deps:
        nonlocal deps
        if deps is None:
            deps = _default_deps()
        return deps

    @app.get("/v1/models")
    def models():
        data = [
            {"id": name, "object": "model", "owned_by": "palimpsests"}
            for name in _deps().models_fn()
        ]
        return {"object": "list", "data": data}

    @app.post("/v1/chat/completions")
    def chat_completions(body: dict):
        model = body.get("model")
        messages = body.get("messages")
        if not model or not isinstance(messages, list) or not messages:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "'model' and a non-empty 'messages' list are required",
                        "type": "invalid_request_error",
                    }
                },
            )
        stream = bool(body.get("stream", False))
        completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
        created = int(time.time())

        chunks = _deps().chat_fn(
            model=model,
            messages=messages,
            context_size=int(body.get("max_context") or 8192),
        )

        if stream:
            return StreamingResponse(
                _sse(chunks, completion_id=completion_id, created=created, model=model),
                media_type="text/event-stream",
            )

        text_parts: list[str] = []
        finish = "stop"
        for c in chunks:
            if c.delta:
                text_parts.append(c.delta)
            if c.done and c.finish_reason:
                finish = c.finish_reason
        return {
            "id": completion_id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "".join(text_parts)},
                    "finish_reason": finish,
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
        }

    return app


def _sse(
    chunks: Iterator[ChatChunk], *, completion_id: str, created: int, model: str
) -> Iterator[str]:
    """Render engine chunks as OpenAI chat.completion.chunk SSE events."""

    def event(delta: dict, finish: str | None) -> str:
        payload = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }
        return f"data: {json.dumps(payload)}\n\n"

    yield event({"role": "assistant"}, None)
    for c in chunks:
        if c.delta:
            yield event({"content": c.delta}, None)
        if c.done:
            yield event({}, c.finish_reason or "stop")
    yield "data: [DONE]\n\n"


def main() -> None:
    """Console-script entry point: ``palimpsests-serve``."""
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(
        description="Serve the OpenAI-compatible endpoint over the active engine."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11435)
    args = parser.parse_args()
    uvicorn.run(create_app(), host=args.host, port=args.port)
