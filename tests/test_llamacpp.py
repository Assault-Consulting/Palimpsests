"""Tests for the llama.cpp level-2 adapter.

Three angles, none of which needs a real llama.cpp or a GPU:

- ``memory_to_args`` is a pure function — the heart of what makes L2 a
  control level — tested by asserting the exact flag vector.
- chat/list are tested wire-level in attach mode (a real base_url) with
  pytest-httpx, exactly like the Ollama adapter.
- process lifecycle is tested separately in test_llama_process.py with a
  mocked Popen.
"""
from __future__ import annotations

import httpx
import pytest
from palimpsests.engine import (
    CapabilityUnsupported,
    ChatResponse,
    EngineMemoryConfig,
)
from palimpsests.providers import (
    EngineRequestError,
    EngineUnavailable,
    LlamaCppEngine,
    ModelNotFound,
)
from palimpsests.providers.llamacpp import memory_to_args

BASE = "http://127.0.0.1:8080"


def _sse(*chunks: str) -> bytes:
    """Build an OpenAI-style SSE body from raw data payloads."""
    return ("".join(f"data: {c}\n\n" for c in chunks)).encode()


@pytest.fixture
def engine():
    """Attach-mode engine: talks to a (mocked) already-running server, so
    no process is spawned."""
    eng = LlamaCppEngine(base_url=BASE)
    yield eng
    eng.close()


# ─── memory_to_args (the control level, as a pure function) ───────────────


def test_args_empty_for_none():
    assert memory_to_args(None) == []


def test_args_context_size():
    args = memory_to_args(EngineMemoryConfig(context_size=8192))
    assert args == ["-c", "8192"]


def test_args_gpu_layers():
    args = memory_to_args(EngineMemoryConfig(gpu_layers=35))
    assert args == ["-ngl", "35"]


def test_args_flash_attention():
    args = memory_to_args(EngineMemoryConfig(flash_attention=True))
    assert args == ["--flash-attn"]


def test_args_kv_cache_quant_sets_both_k_and_v():
    """KV-quant maps to both cache-type-k and cache-type-v; flash
    attention is required (and thus present) by EngineMemoryConfig."""
    args = memory_to_args(
        EngineMemoryConfig(kv_cache_quant="q8_0", flash_attention=True)
    )
    assert "--flash-attn" in args
    assert "--cache-type-k" in args
    assert "--cache-type-v" in args
    # both cache types carry the quant value
    assert args.count("q8_0") == 2


def test_args_no_mmap_only_when_disabled():
    # mmap on (default) → no flag
    assert "--no-mmap" not in memory_to_args(EngineMemoryConfig(use_mmap=True))
    # mmap off → the flag appears
    assert "--no-mmap" in memory_to_args(EngineMemoryConfig(use_mmap=False))


def test_args_draft_model():
    args = memory_to_args(EngineMemoryConfig(draft_model="/models/draft.gguf"))
    assert args == ["--model-draft", "/models/draft.gguf"]


def test_args_full_config_combines_all():
    args = memory_to_args(
        EngineMemoryConfig(
            context_size=4096,
            gpu_layers=20,
            flash_attention=True,
            kv_cache_quant="q4_0",
            use_mmap=False,
            draft_model="/d.gguf",
        )
    )
    # every field turned into flags
    assert "-c" in args and "4096" in args
    assert "-ngl" in args and "20" in args
    assert "--flash-attn" in args
    assert "--cache-type-k" in args and "--cache-type-v" in args
    assert "--no-mmap" in args
    assert "--model-draft" in args and "/d.gguf" in args


# ─── constructor validation ──────────────────────────────────────────────


def test_requires_exactly_one_of_model_or_url():
    with pytest.raises(ValueError, match="exactly one"):
        LlamaCppEngine()  # neither
    with pytest.raises(ValueError, match="exactly one"):
        LlamaCppEngine(model_path="/m.gguf", base_url=BASE)  # both


# ─── capabilities ─────────────────────────────────────────────────────────


def test_capabilities_are_level_2(engine: LlamaCppEngine):
    caps = engine.capabilities
    assert caps.control_level == 2
    assert caps.streaming is True
    assert caps.stateful_sessions is False


def test_engine_id(engine: LlamaCppEngine):
    assert engine.engine_id == "llamacpp"


def test_open_session_refuses(engine: LlamaCppEngine):
    """L2 is stateless like L1 — inherited loud refusal."""
    with pytest.raises(CapabilityUnsupported):
        engine.open_session(model="anything")


# ─── list_models (attach mode, wire-level) ────────────────────────────────


def test_list_models_parses_v1_models(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/models",
        json={"data": [{"id": "qwen2.5-7b-instruct"}]},
    )
    models = engine.list_models()
    assert len(models) == 1
    assert models[0].name == "qwen2.5-7b-instruct"
    assert models[0].engine_id == "llamacpp"


def test_list_models_server_error(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/v1/models", status_code=500, text="boom")
    with pytest.raises(EngineRequestError) as exc:
        engine.list_models()
    assert exc.value.status == 500


def test_list_models_connection_refused(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with pytest.raises(EngineUnavailable):
        engine.list_models()


# ─── chat_stream (attach mode, wire-level SSE) ────────────────────────────


def test_chat_stream_parses_sse(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/chat/completions",
        content=_sse(
            '{"choices":[{"delta":{"content":"Hel"}}]}',
            '{"choices":[{"delta":{"content":"lo"}}]}',
            '{"choices":[{"delta":{"content":"!"},"finish_reason":"stop"}]}',
            "[DONE]",
        ),
    )
    chunks = list(
        engine.chat_stream(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )
    )
    assert [c.delta for c in chunks] == ["Hel", "lo", "!"]
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"


def test_chat_accumulates(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/chat/completions",
        content=_sse(
            '{"choices":[{"delta":{"content":"2+2"}}]}',
            '{"choices":[{"delta":{"content":"=4"},"finish_reason":"stop"}]}',
            "[DONE]",
        ),
    )
    resp = engine.chat(model="m", messages=[{"role": "user", "content": "q"}])
    assert isinstance(resp, ChatResponse)
    assert resp.text == "2+2=4"
    assert resp.finish_reason == "stop"


def test_chat_stream_model_not_found(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/chat/completions", status_code=404, text="no model"
    )
    with pytest.raises(ModelNotFound) as exc:
        list(engine.chat_stream(model="ghost", messages=[]))
    assert exc.value.model == "ghost"


def test_chat_stream_server_error(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/chat/completions", status_code=500, text="kaboom"
    )
    with pytest.raises(EngineRequestError) as exc:
        list(engine.chat_stream(model="m", messages=[]))
    assert exc.value.status == 500


def test_chat_stream_malformed_sse(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(
        url=f"{BASE}/v1/chat/completions",
        content=b"data: not json\n\n",
    )
    with pytest.raises(EngineRequestError, match="malformed"):
        list(engine.chat_stream(model="m", messages=[]))


def test_chat_stream_connection_refused(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    with pytest.raises(EngineUnavailable):
        list(engine.chat_stream(model="m", messages=[]))


# ─── availability (attach mode) ───────────────────────────────────────────


def test_is_available_true(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/health", status_code=200)
    assert engine.is_available() is True


def test_is_available_false(engine: LlamaCppEngine, httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    assert engine.is_available() is False
