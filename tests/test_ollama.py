"""Tests for the Ollama level-1 adapter.

Wire-level: pytest-httpx mocks Ollama's HTTP responses so we exercise
the real request/parse/translate path without a running daemon. We
never patch the adapter's internals.
"""
from __future__ import annotations

import httpx
import pytest
from palimpsests.engine import CapabilityUnsupported, ChatResponse, EngineMemoryConfig
from palimpsests.providers import (
    EngineRequestError,
    EngineUnavailable,
    ModelNotFound,
    OllamaEngine,
)

BASE = "http://localhost:11434"


@pytest.fixture
def engine():
    eng = OllamaEngine(base_url=BASE)
    yield eng
    eng.close()


def _ndjson(*objs: dict) -> bytes:
    """Build a newline-delimited JSON stream body."""
    import json

    return ("\n".join(json.dumps(o) for o in objs) + "\n").encode()


# ─── capabilities ────────────────────────────────────────────────────────


def test_capabilities_are_level_1(engine: OllamaEngine) -> None:
    caps = engine.capabilities
    assert caps.control_level == 1
    assert caps.streaming is True
    assert caps.stateful_sessions is False
    assert caps.kv_persistence is False


def test_engine_id(engine: OllamaEngine) -> None:
    assert engine.engine_id == "ollama"


def test_open_session_refuses(engine: OllamaEngine) -> None:
    """Inherited loud refusal works on the real adapter."""
    with pytest.raises(CapabilityUnsupported):
        engine.open_session(model="anything")


# ─── list_models ─────────────────────────────────────────────────────────


def test_list_models_parses_tags(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/tags",
        json={
            "models": [
                {
                    "name": "qwen2.5:7b",
                    "size": 4700000000,
                    "details": {"quantization_level": "Q4_K_M"},
                },
                {"name": "llama3:8b", "size": 4900000000, "details": {}},
            ]
        },
    )
    models = engine.list_models()
    assert len(models) == 2
    assert models[0].name == "qwen2.5:7b"
    assert models[0].engine_id == "ollama"
    assert models[0].size_bytes == 4700000000
    assert models[0].quant == "Q4_K_M"
    assert models[1].quant is None


def test_list_models_empty(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    assert engine.list_models() == []


def test_list_models_server_error(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/tags", status_code=500, text="boom")
    with pytest.raises(EngineRequestError) as exc:
        engine.list_models()
    assert exc.value.status == 500


def test_list_models_connection_refused(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with pytest.raises(EngineUnavailable):
        engine.list_models()


# ─── chat_stream / chat ──────────────────────────────────────────────────


def test_chat_stream_yields_chunks(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson(
            {"message": {"content": "Hello"}, "done": False},
            {"message": {"content": ", world"}, "done": False},
            {"message": {"content": "!"}, "done": True, "done_reason": "stop"},
        ),
    )
    chunks = list(
        engine.chat_stream(
            model="qwen2.5:7b", messages=[{"role": "user", "content": "hi"}]
        )
    )
    assert [c.delta for c in chunks] == ["Hello", ", world", "!"]
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"
    assert chunks[0].done is False


def test_chat_accumulates(engine: OllamaEngine, httpx_mock) -> None:
    """The inherited chat() builds a whole ChatResponse from the stream."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson(
            {"message": {"content": "2+2"}, "done": False},
            {"message": {"content": "=4"}, "done": True, "done_reason": "stop"},
        ),
    )
    resp = engine.chat(model="qwen2.5:7b", messages=[{"role": "user", "content": "q"}])
    assert isinstance(resp, ChatResponse)
    assert resp.text == "2+2=4"
    assert resp.finish_reason == "stop"


def test_chat_stream_model_not_found(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/chat", status_code=404, text="not found")
    with pytest.raises(ModelNotFound) as exc:
        list(engine.chat_stream(model="ghost", messages=[]))
    assert exc.value.model == "ghost"
    assert exc.value.engine_id == "ollama"


def test_chat_stream_server_error(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/chat", status_code=500, text="kaboom")
    with pytest.raises(EngineRequestError) as exc:
        list(engine.chat_stream(model="m", messages=[]))
    assert exc.value.status == 500


def test_chat_stream_malformed_line(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/chat", content=b"not json\n")
    with pytest.raises(EngineRequestError, match="malformed"):
        list(engine.chat_stream(model="m", messages=[]))


def test_chat_stream_connection_refused(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with pytest.raises(EngineUnavailable):
        list(engine.chat_stream(model="m", messages=[]))


# ─── memory mapping ──────────────────────────────────────────────────────


def test_memory_maps_context_size(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    cfg = EngineMemoryConfig(context_size=8192, gpu_layers=20)
    list(engine.chat_stream(model="m", messages=[], memory=cfg))

    request = httpx_mock.get_request()
    import json

    body = json.loads(request.content)
    assert body["options"]["num_ctx"] == 8192
    assert body["options"]["num_gpu"] == 20


def test_memory_ignores_unsupported_fields(engine: OllamaEngine, httpx_mock) -> None:
    """KV-quant / flash attention are lower-level; level 1 ignores them
    rather than failing — capabilities already said it can't."""
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    cfg = EngineMemoryConfig(
        kv_cache_quant="q8_0", flash_attention=True, context_size=4096
    )
    list(engine.chat_stream(model="m", messages=[], memory=cfg))

    request = httpx_mock.get_request()
    import json

    body = json.loads(request.content)
    assert body["options"] == {"num_ctx": 4096}  # only the supported field
    assert "kv_cache_quant" not in body["options"]


def test_no_memory_no_options(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson({"message": {"content": "ok"}, "done": True}),
    )
    list(engine.chat_stream(model="m", messages=[]))
    request = httpx_mock.get_request()
    import json

    body = json.loads(request.content)
    assert "options" not in body


# ─── availability ────────────────────────────────────────────────────────


def test_is_available_true(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    assert engine.is_available() is True


def test_is_available_false_on_error(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    assert engine.is_available() is False


# ─── base_url override ───────────────────────────────────────────────────


def test_base_url_override(httpx_mock) -> None:
    custom = "http://ollama.internal:11434"
    httpx_mock.add_response(url=f"{custom}/api/tags", json={"models": []})
    eng = OllamaEngine(base_url=custom)
    try:
        assert eng.is_available() is True
    finally:
        eng.close()


# ─── embeddings ──────────────────────────────────────────────────────────


def test_embed_returns_vector(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/embeddings",
        json={"embedding": [0.1, 0.2, 0.3]},
    )
    vec = engine.embed(model="nomic-embed-text", text="hello")
    assert vec == [0.1, 0.2, 0.3]


def test_embed_model_not_found(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/embeddings", status_code=404, text="not found"
    )
    with pytest.raises(ModelNotFound) as exc:
        engine.embed(model="ghost", text="hello")
    assert exc.value.model == "ghost"


def test_embed_server_error(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_response(
        url=f"{BASE}/api/embeddings", status_code=500, text="boom"
    )
    with pytest.raises(EngineRequestError) as exc:
        engine.embed(model="m", text="hello")
    assert exc.value.status == 500


def test_embed_empty_response(engine: OllamaEngine, httpx_mock) -> None:
    """A 200 with no embedding is a request error, not a silent empty."""
    httpx_mock.add_response(url=f"{BASE}/api/embeddings", json={})
    with pytest.raises(EngineRequestError, match="no embedding"):
        engine.embed(model="m", text="hello")


def test_embed_connection_refused(engine: OllamaEngine, httpx_mock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with pytest.raises(EngineUnavailable):
        engine.embed(model="m", text="hello")
