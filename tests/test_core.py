"""Tests for the orchestration layer.

These exercise core without the CLI: build an AppContext against tmp
paths and a mocked Ollama wire, then call the orchestrated functions
directly. This is why orchestration lives in core — it's testable
without argument parsing.
"""
from __future__ import annotations

import httpx
import json
import pytest
from palimpsests.audit import get_audit_log, set_audit_log
from palimpsests.core import (
    AppContext,
    chat,
    init_app,
    list_engines,
    list_models,
    select_engine,
)
from palimpsests.providers import OllamaEngine
from palimpsests.registry import EngineRegistry, set_registry

BASE = "http://localhost:11434"


def _ndjson(*objs: dict) -> bytes:
    return ("\n".join(json.dumps(o) for o in objs) + "\n").encode()


@pytest.fixture
def ctx(tmp_path, audit_log):
    """An AppContext wired to tmp paths and a real (mockable) engine.

    Uses the audit_log fixture (installs the singleton) and its own
    tmp registry so nothing touches the user's real config.
    """
    registry = EngineRegistry(tmp_path / "registry.json")
    set_registry(registry)
    engine = OllamaEngine(base_url=BASE)
    registry.register("ollama", control_level=1, installed=True)
    context = AppContext(
        config_dir=tmp_path, registry=registry, engines={"ollama": engine}
    )
    yield context
    engine.close()
    set_registry(None)


# ─── init_app ────────────────────────────────────────────────────────────


def test_init_app_creates_state(tmp_path, httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    ctx = init_app(config_dir=tmp_path)
    try:
        assert (tmp_path / "audit.db").exists()
        assert "ollama" in ctx.engines
        # ollama got registered with installed-state from the probe
        assert ctx.registry.is_installed("ollama") is True
        assert get_audit_log() is not None
    finally:
        ctx.engines["ollama"].close()
        set_audit_log(None)
        set_registry(None)


def test_init_app_marks_unavailable(tmp_path, httpx_mock):
    """A down daemon registers as not-installed, doesn't crash init."""
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    ctx = init_app(config_dir=tmp_path)
    try:
        assert ctx.registry.is_installed("ollama") is False
    finally:
        ctx.engines["ollama"].close()
        set_audit_log(None)
        set_registry(None)


# ─── list_models ─────────────────────────────────────────────────────────


def test_list_models_delegates_to_active(ctx, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/api/tags",
        json={"models": [{"name": "qwen2.5:7b", "size": 1, "details": {}}]},
    )
    models = list_models(ctx)
    assert [m.name for m in models] == ["qwen2.5:7b"]


def test_list_models_is_audited(ctx, httpx_mock):
    """The @audited decorator records the call to the audit log."""
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    list_models(ctx)
    events = get_audit_log().recent()
    assert any(e.operation == "engine.list_models" for e in events)


# ─── engine selection ────────────────────────────────────────────────────


def test_list_engines_marks_active(ctx):
    rows = list_engines(ctx)
    assert len(rows) == 1
    engine_id, level, installed, active = rows[0]
    assert engine_id == "ollama"
    assert level == 1
    assert active is True


def test_select_engine_switches_active(ctx):
    ctx.registry.register("llamacpp", control_level=2, installed=False)
    select_engine(ctx, "llamacpp")
    assert ctx.registry.active_engine_id == "llamacpp"


def test_select_engine_is_audited(ctx):
    ctx.registry.register("llamacpp", control_level=2, installed=False)
    select_engine(ctx, "llamacpp")
    events = get_audit_log().recent()
    assert any(e.operation == "engine.select" for e in events)


def test_select_unknown_engine_raises(ctx):
    with pytest.raises(KeyError):
        select_engine(ctx, "nonexistent")


# ─── chat ────────────────────────────────────────────────────────────────


def test_chat_streams_through_active_engine(ctx, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson(
            {"message": {"content": "hi"}, "done": False},
            {"message": {"content": " there"}, "done": True, "done_reason": "stop"},
        ),
    )
    chunks = list(
        chat(ctx, model="qwen2.5:7b", messages=[{"role": "user", "content": "yo"}])
    )
    assert "".join(c.delta for c in chunks) == "hi there"


def test_chat_is_audited(ctx, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    list(chat(ctx, model="m", messages=[{"role": "user", "content": "q"}]))
    events = get_audit_log().recent()
    assert any(e.operation == "model.call" for e in events)


def test_chat_applies_context_fitting(ctx, httpx_mock):
    """A conversation over budget is fitted before hitting the engine —
    the request the engine sees has fewer messages than we passed in."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    # Many large messages, tiny context budget -> eviction must happen.
    big = "x" * 400
    messages = [{"role": "user", "content": f"{i}-{big}"} for i in range(20)]
    list(chat(ctx, model="m", messages=messages, context_size=256))

    request = httpx_mock.get_request()
    sent = json.loads(request.content)["messages"]
    # Context fitting dropped some messages before the engine saw them.
    assert len(sent) < len(messages)
