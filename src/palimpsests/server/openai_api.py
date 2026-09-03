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

Scope, stated rather than implied: chat, streaming, and function calling
in the one convention documented in ``tool_calls`` (Hermes/Qwen
``<tool_call>`` blocks). With ``tools`` present, streaming assembles the
reply first and replays it as SSE — tool_calls-shape correctness over
first-token latency, in this version. ``usage`` carries the engine's
reported counters where the level reports them (level 1 does), zeros
where it does not yet.

Visibility limitation, measured rather than assumed (smoke-run #189,
``docs/specs/pala-1/independent-runs/oleksandr/ws-e-opencode-smoke/``):
the audited tool loop — kind 8 ``TOOL_CALL`` / kind 9 ``TOOL_RESULT`` —
exists only for *structured* calls that cross this endpoint. A client
whose model narrates the call as text, and which then parses and
executes it locally, bypasses any server-side recorder by definition;
#189 pinned that as model × prompt behaviour (a heavy client system
prompt suppressed structured calling on every local model tried), not
an adapter defect. A terminal can render both modes identically — the
chain is the witness. No prose-mining here, ever: extracting "calls"
the model never committed as structure would fabricate evidence.
Accepted follow-up directions are recorded in ADR-0005.

One of them ships here as the ingestion surface (profile r5):
``POST /v1/pala/events`` lets a client that runs its loop in text
report its tool events onto the same chain — recorded as kinds 8/9
carrying ``EVT_SOURCE = reported-by-client``, an evidence-quality mark
that keeps them forever distinguishable from events this process parsed
off its own wire. The chain then proves the report happened, what it
digested, and when — never that the tool actually ran. Bearer-guarded
like every route.

Authentication is opt-in: this
binds to localhost by default and is a local tool — pass ``--api-key``
(or set ``PALIMPSESTS_SERVE_API_KEY``) the moment anything beyond your
own shell can reach the port.

The module is import-safe without the ``serve`` extra; constructing the
app is what requires FastAPI.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

from palimpsests.engine.messages import ChatChunk
from palimpsests.server.tool_calls import parse_tool_calls, tools_system_message

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


def create_app(
    *,
    chat_fn: ChatFn | None = None,
    models_fn: ModelsFn | None = None,
    audit=None,
    api_key: str | None = None,
):
    """Build the FastAPI app. Dependencies are injectable for tests.

    ``audit`` is an optional ``NativeAudit`` adapter: with it, the
    endpoint records the tool loop it mediates into a PALA-1 chain —
    ``TOOL_CALL`` when tool calls are handed to the client (the dispatch
    boundary this process directly observes), ``TOOL_RESULT`` when the
    client posts the results back, hash-bound to their calls —
    structured calls only; the module docstring states the text-mode
    visibility limit. Works on
    every engine level, because the recording boundary is the endpoint
    itself, not the engine.

    ``api_key``, when given, requires ``Authorization: Bearer <key>`` on
    every request — the serve-side answer to the level-2 exposure caveat
    in SECURITY.md.
    """
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, StreamingResponse

    if api_key is not None and not api_key:
        raise ValueError("api_key must be a non-empty string when given")

    deps: _Deps | None = (
        _Deps(chat_fn=chat_fn, models_fn=models_fn)
        if chat_fn is not None and models_fn is not None
        else None
    )

    app = FastAPI(title="Palimpsests", docs_url=None, redoc_url=None)

    if api_key is not None:
        import hmac

        # Bearer auth on every endpoint. Constant-time compare; the 401
        # body follows the OpenAI error shape so compatible clients
        # surface it instead of choking on it. This is the level-2
        # exposure mitigation from SECURITY.md, applied to serve.
        @app.middleware("http")
        async def _require_bearer(request, call_next):
            supplied = request.headers.get("authorization", "")
            expected = f"Bearer {api_key}"
            if not hmac.compare_digest(supplied, expected):
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": {
                            "message": "Incorrect API key provided.",
                            "type": "invalid_request_error",
                            "code": "invalid_api_key",
                        }
                    },
                )
            return await call_next(request)
    # Dispatched tool calls awaiting results: id -> the TOOL_CALL's
    # (seq, hash), so a later request's results bind to their calls.
    pending: dict[str, tuple[int, bytes]] = {}

    if audit is not None:
        def _cancel_pending() -> None:
            from palimpsests.audit.pala_writer import OUTCOME_CANCELLED

            if not pending:
                return
            for ref in pending.values():
                audit.tool_result(ref[0], ref[1], OUTCOME_CANCELLED, None, None)
            pending.clear()

        # Two seams on purpose: the ASGI shutdown covers well-behaved
        # exits, and main()'s atexit closer calls the same function again
        # right before the writer closes — a Windows console Ctrl-C can
        # take uvicorn down without ever delivering lifespan shutdown
        # (smoke-run #189: five pending calls, zero CANCELLED on the
        # record). Idempotent, so double delivery is a no-op.
        app.router.on_shutdown.append(_cancel_pending)
        app.state.cancel_pending = _cancel_pending

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

        tools = body.get("tools") or []
        outgoing = list(messages)
        if tools:
            outgoing = [tools_system_message(tools), *outgoing]
        if audit is not None:
            _record_tool_results(audit, messages, pending)

        chunks = _deps().chat_fn(
            model=model,
            messages=outgoing,
            context_size=int(body.get("max_context") or 8192),
        )

        if tools:
            # Parsing needs the whole reply, so with tools the response is
            # assembled first; streaming then replays it as SSE. Documented
            # trade: correctness of the tool_calls shape over first-token
            # latency, in this version.
            text_parts: list[str] = []
            finish = "stop"
            p_tok = c_tok = None
            for c in chunks:
                if c.delta:
                    text_parts.append(c.delta)
                if c.done:
                    if c.finish_reason:
                        finish = c.finish_reason
                    p_tok, c_tok = c.prompt_tokens, c.completion_tokens
            calls, remaining = parse_tool_calls("".join(text_parts))
            if not calls and audit is not None and not _structured_traffic(messages):
                # The blind zone, made visible (kind 10, r4): tools were
                # offered, no structured call came back, and the request
                # itself carried no structured tool traffic either — the
                # completion a text-mode loop leaves indistinguishable
                # from no tool use at all. Inside a visible structured
                # loop this stays silent: the loop is already on record.
                from palimpsests.audit.pala_writer import (
                    canonical_tool_names_digest,
                )

                names = [
                    (t.get("function") or {}).get("name", "")
                    for t in tools
                    if isinstance(t, dict)
                ]
                audit.tools_offered_no_call(
                    len(names), canonical_tool_names_digest(names), None
                )
            if calls and audit is not None:
                for pc in calls:
                    pending[pc.id] = audit.tool_called(
                        pc.name,
                        _args_digest(pc.arguments),
                        None,
                    )
            if stream:
                return StreamingResponse(
                    _sse_prebuilt(
                        completion_id=completion_id,
                        created=created,
                        model=model,
                        content=remaining if not calls else None,
                        tool_calls=[pc.as_openai() for pc in calls] or None,
                        finish="tool_calls" if calls else finish,
                    ),
                    media_type="text/event-stream",
                )
            message: dict = {"role": "assistant"}
            if calls:
                message["content"] = remaining or None
                message["tool_calls"] = [pc.as_openai() for pc in calls]
                finish = "tool_calls"
            else:
                message["content"] = remaining
            return {
                "id": completion_id,
                "object": "chat.completion",
                "created": created,
                "model": model,
                "choices": [
                    {"index": 0, "message": message, "finish_reason": finish}
                ],
                "usage": _usage(p_tok, c_tok),
            }

        if stream:
            return StreamingResponse(
                _sse(chunks, completion_id=completion_id, created=created, model=model),
                media_type="text/event-stream",
            )

        text_parts: list[str] = []
        finish = "stop"
        p_tok = c_tok = None
        for c in chunks:
            if c.delta:
                text_parts.append(c.delta)
            if c.done:
                if c.finish_reason:
                    finish = c.finish_reason
                p_tok, c_tok = c.prompt_tokens, c.completion_tokens
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
            "usage": _usage(p_tok, c_tok),
        }

    @app.post("/v1/pala/events")
    def ingest_events(body: dict):
        """Client-reported tool events, onto the same chain (r5).

        The constructive half of the visibility limit: each reported
        call and result lands as a kind 8/9 record carrying
        ``EVT_SOURCE = reported-by-client`` — never to be confused with
        events parsed from the wire this process mediated. Append-only
        honesty: events are processed in order and each write is final,
        so a batch with a bad entry returns per-event errors alongside
        the results that did land — there is no unwriting. Reported
        results bind to reported calls through the same pending map the
        wire path uses; a reported call left unresolved at shutdown is
        cancelled like a wire one.
        """
        if audit is None:
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "no audit chain configured on this server",
                        "type": "server_error",
                    }
                },
            )
        events = body.get("events")
        if not isinstance(events, list) or not events:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "'events' must be a non-empty list",
                        "type": "invalid_request_error",
                    }
                },
            )
        from hashlib import sha256

        from palimpsests.audit.pala_writer import (
            OUTCOME_CANCELLED,
            OUTCOME_ERROR,
            OUTCOME_OK,
            OUTCOME_TIMEOUT,
            SOURCE_REPORTED_BY_CLIENT,
        )

        outcomes = {
            "ok": OUTCOME_OK,
            "error": OUTCOME_ERROR,
            "timeout": OUTCOME_TIMEOUT,
            "cancelled": OUTCOME_CANCELLED,
        }
        results: list[dict] = []
        for ev in events:
            if not isinstance(ev, dict):
                results.append({"error": "event must be an object"})
                continue
            etype = ev.get("type")
            try:
                if etype == "tool_call":
                    call_id = str(ev["id"])
                    name = str(ev["name"])
                    if "args_digest" in ev:
                        digest = bytes.fromhex(ev["args_digest"])
                    elif "arguments" in ev:
                        digest = _args_digest(ev["arguments"])
                    else:
                        digest = None
                    seq, rh = audit.tool_called(
                        name, digest, None, source=SOURCE_REPORTED_BY_CLIENT
                    )
                    pending[call_id] = (seq, rh)
                    results.append(
                        {"id": call_id, "seq": seq, "record_hash": rh.hex()}
                    )
                elif etype == "tool_result":
                    call_id = str(ev["call_id"])
                    ref = pending.pop(call_id, None)
                    if ref is None:
                        results.append({"id": call_id, "error": "unknown call_id"})
                        continue
                    outcome = outcomes.get(str(ev.get("outcome", "ok")))
                    if outcome is None:
                        pending[call_id] = ref  # not consumed
                        results.append({"id": call_id, "error": "unknown outcome"})
                        continue
                    if "result_digest" in ev:
                        digest = bytes.fromhex(ev["result_digest"])
                    elif "content" in ev:
                        digest = sha256(str(ev["content"]).encode("utf-8")).digest()
                    else:
                        digest = None
                    rh = audit.tool_result(
                        ref[0], ref[1], outcome, digest, None,
                        source=SOURCE_REPORTED_BY_CLIENT,
                    )
                    results.append({"id": call_id, "record_hash": rh.hex()})
                else:
                    results.append({"error": f"unknown event type: {etype!r}"})
            except (KeyError, ValueError, TypeError) as exc:
                results.append({"error": f"invalid event: {exc}"})
        return {"results": results}

    return app


def _structured_traffic(messages: list) -> bool:
    """True if the request already shows a structured tool loop."""
    for m in messages:
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool" or m.get("tool_calls"):
            return True
    return False


def _usage(prompt_tokens: int | None, completion_tokens: int | None) -> dict:
    """OpenAI usage block; zeros where the engine reported nothing."""
    p, c = prompt_tokens or 0, completion_tokens or 0
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


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


def _args_digest(arguments: dict) -> bytes:
    from palimpsests.audit.pala_writer import canonical_tool_args_digest

    return canonical_tool_args_digest(arguments)


def _record_tool_results(audit, messages: list, pending: dict) -> None:
    """Bind incoming role:"tool" messages to their recorded calls."""
    from hashlib import sha256

    from palimpsests.audit.pala_writer import OUTCOME_OK

    for m in messages:
        if not isinstance(m, dict) or m.get("role") != "tool":
            continue
        ref = pending.pop(m.get("tool_call_id"), None)
        if ref is None:
            continue
        content = str(m.get("content", ""))
        audit.tool_result(
            ref[0], ref[1], OUTCOME_OK,
            sha256(content.encode("utf-8")).digest(), None,
        )
    return


def _sse_prebuilt(
    *,
    completion_id: str,
    created: int,
    model: str,
    content: str | None,
    tool_calls: list | None,
    finish: str,
) -> Iterator[str]:
    """Replay an already-assembled completion as OpenAI SSE chunks."""

    def event(delta: dict, fin: str | None) -> str:
        payload = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": fin}],
        }
        return f"data: {json.dumps(payload)}\n\n"

    yield event({"role": "assistant"}, None)
    if tool_calls:
        indexed = [{"index": i, **tc} for i, tc in enumerate(tool_calls)]
        yield event({"tool_calls": indexed}, None)
    elif content:
        yield event({"content": content}, None)
    yield event({}, finish)
    yield "data: [DONE]\n\n"


def default_audit():
    """The endpoint's own PALA-1 chain at ``<config>/serve.pala``.

    Cross-boot: an existing chain is adopted (the adapter then emits the
    BOOT link), a missing one starts at GENESIS. Returns a wired
    ``NativeAudit`` — or None if the audit stack cannot construct, so
    serving never fails on the recorder.
    """
    try:
        from palimpsests.audit.pala_writer import PalaWriter
        from palimpsests.core import default_config_dir
        from palimpsests.providers.native.audit import NativeAudit

        path = default_config_dir() / "serve.pala"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 0:
            writer = PalaWriter.open_existing(path)
        else:
            writer = PalaWriter(path)
        return NativeAudit(writer)
    except Exception:
        return None


def main() -> None:
    """Console-script entry point: ``palimpsests-serve``."""
    import argparse
    import atexit

    parser = argparse.ArgumentParser(
        description="Serve the OpenAI-compatible endpoint over the active engine."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11435)
    parser.add_argument(
        "--api-key",
        default=os.environ.get("PALIMPSESTS_SERVE_API_KEY") or None,
        help=(
            "require this bearer key on every request "
            "(default: $PALIMPSESTS_SERVE_API_KEY if set)"
        ),
    )
    parser.add_argument(
        "--print-opencode-config",
        action="store_true",
        help="print an opencode.json provider block for this endpoint and exit",
    )
    args = parser.parse_args()
    if args.print_opencode_config:
        print(_opencode_config(args.host, args.port, args.api_key))
        print(
            "# OpenCode also needs an auth.json entry for this provider id\n"
            "# (~/.local/share/opencode/auth.json):\n"
            '#   {"palimpsests": {"type": "api", "key": "'
            + (args.api_key or "sk-local")
            + '"}}\n'
            "# The key is checked by serve only when --api-key is set;\n"
            "# OpenCode requires the entry to exist either way.",
            file=sys.stderr,
        )
        return
    import uvicorn  # runtime-only: the config printer must not need it

    audit = default_audit()
    app = create_app(audit=audit, api_key=args.api_key)
    if audit is not None:

        def _close_audit() -> None:
            # Cancel-before-close, even when the ASGI shutdown never ran
            # (Windows console Ctrl-C can skip it — see create_app).
            cancel = getattr(app.state, "cancel_pending", None)
            if cancel is not None:
                cancel()
            audit.writer.close()

        atexit.register(_close_audit)
    uvicorn.run(app, host=args.host, port=args.port)


def _opencode_config(host: str, port: int, api_key: str | None) -> str:
    """The opencode.json provider block for this endpoint, as JSON text.

    Deliberately hard-wired to ``@ai-sdk/openai-compatible`` — the one
    provider package whose request shape matches what serve implements;
    "works with OpenCode" means exactly this pairing, nothing looser.
    """
    try:
        model_ids = list(_default_deps().models_fn())
    except Exception:
        model_ids = []
    if not model_ids:
        model_ids = ["MODEL_ID"]  # engine unreachable now; replace by hand
    options: dict = {"baseURL": f"http://{host}:{port}/v1"}
    if api_key:
        options["apiKey"] = api_key
    return json.dumps(
        {
            "$schema": "https://opencode.ai/config.json",
            "provider": {
                "palimpsests": {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": "Palimpsests (local, audited)",
                    "options": options,
                    "models": {m: {"name": m} for m in model_ids},
                }
            },
        },
        indent=2,
    )
