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
    UNENCRYPTED_ENV,
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


@pytest.fixture(autouse=True)
def _allow_plaintext_audit(monkeypatch):
    """init_app refuses an unencrypted audit log unless told to.

    CI runners have no native SQLCipher build, so the tests here that
    build a real app context opt in explicitly. Stated in the test rather
    than softening the production default, which stays fail-closed.
    """
    monkeypatch.setenv(UNENCRYPTED_ENV, "1")


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


# ─── block-memory wiring ─────────────────────────────────────────────────

# A deterministic embedder so retrieval is exact and offline. Mirrors the
# fake used in test_block_memory: fixed-vocab axes.
_VOCAB = ["alpha", "beta", "gamma", "delta", "epsilon"]


def _fake_embed(text: str) -> list[float]:
    vec = [0.0] * len(_VOCAB)
    for word in text.lower().split():
        if word in _VOCAB:
            vec[_VOCAB.index(word)] += 1.0
    return vec + [0.1]


@pytest.fixture
def ctx_with_memory(tmp_path, audit_log):
    """AppContext whose block memory uses the deterministic fake embedder
    (no network), so we can assert on store + retrieval behavior."""
    from palimpsests.context import BlockMemory

    registry = EngineRegistry(tmp_path / "registry.json")
    set_registry(registry)
    engine = OllamaEngine(base_url=BASE)
    registry.register("ollama", control_level=1, installed=True)
    mem = BlockMemory(workspace=tmp_path, embedder=_fake_embed)
    context = AppContext(
        config_dir=tmp_path,
        registry=registry,
        engines={"ollama": engine},
        block_memory=mem,
    )
    yield context
    mem.close()
    engine.close()
    set_registry(None)


def test_chat_stores_evicted_in_block_memory(ctx_with_memory, httpx_mock):
    """When the window manager evicts, the evicted messages are stored."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    big = "x" * 400
    messages = [{"role": "user", "content": f"alpha {i} {big}"} for i in range(20)]
    list(chat(ctx_with_memory, model="m", messages=messages, context_size=256))
    # Something was evicted and therefore stored.
    assert ctx_with_memory.block_memory.count() > 0


def test_chat_recalls_relevant_block(ctx_with_memory, httpx_mock):
    """Evicted content relevant to the latest turn is recalled as a
    system message prepended to what the engine sees."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    # First user message carries a distinctive vocab word; it'll be
    # evicted. The final user turn queries with the same word.
    big = "x" * 400
    messages = [{"role": "user", "content": f"gamma secret {big}"}]
    messages += [
        {"role": "user", "content": f"beta {i} {big}"} for i in range(18)
    ]
    messages += [{"role": "user", "content": "gamma"}]
    list(chat(ctx_with_memory, model="m", messages=messages, context_size=256))

    sent = json.loads(httpx_mock.get_request().content)["messages"]
    # A recalled-context system message was prepended.
    assert sent[0]["role"] == "system"
    assert "recalled" in sent[0]["content"].lower()


def test_chat_no_eviction_skips_block_memory(ctx_with_memory, httpx_mock):
    """A short conversation evicts nothing, so block memory is never
    touched — no stored blocks, no wasted embedding calls."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    messages = [{"role": "user", "content": "hello"}]
    list(chat(ctx_with_memory, model="m", messages=messages, context_size=8192))
    assert ctx_with_memory.block_memory.count() == 0
    sent = json.loads(httpx_mock.get_request().content)["messages"]
    # No recalled-context system message injected.
    assert not any(
        m["role"] == "system" and "recalled" in m.get("content", "").lower()
        for m in sent
    )


def test_chat_without_block_memory_still_works(ctx, httpx_mock):
    """With block_memory=None (the default ctx), chat still fits and
    streams — retrieval is an enhancement, not a requirement."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "hi"}, "done": True}),
    )
    big = "x" * 400
    messages = [{"role": "user", "content": f"{i} {big}"} for i in range(20)]
    chunks = list(chat(ctx, model="m", messages=messages, context_size=256))
    assert "".join(c.delta for c in chunks) == "hi"
    # No system recall message, since there's no block memory.
    sent = json.loads(httpx_mock.get_request().content)["messages"]
    assert not any(m["role"] == "system" for m in sent)
