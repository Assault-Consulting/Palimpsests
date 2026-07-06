"""Tests for the inert engine contract.

Nothing here talks to a backend — these lock down the shape and the
derived behavior (chat accumulation, loud refusal, memory validation)
that every future adapter inherits.
"""
from __future__ import annotations

import pytest
from collections.abc import Iterator, Sequence
from palimpsests.engine import (
    BaseInferenceEngine,
    CapabilityUnsupported,
    ChatChunk,
    ChatResponse,
    EngineCapabilities,
    EngineMemoryConfig,
    InferenceEngine,
    Message,
    ModelInfo,
    ToolCall,
)

# ─── a minimal stateless adapter for testing the base class ──────────────


class FakeEngine(BaseInferenceEngine):
    """A level-1-style adapter that streams a fixed script of chunks."""

    def __init__(self, chunks: list[ChatChunk]) -> None:
        self._chunks = chunks
        self.last_memory: EngineMemoryConfig | None = None

    @property
    def engine_id(self) -> str:
        return "fake"

    @property
    def capabilities(self) -> EngineCapabilities:
        return EngineCapabilities(control_level=1, streaming=True)

    def list_models(self) -> Sequence[ModelInfo]:
        return [ModelInfo(name="fake-model", engine_id="fake")]

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        self.last_memory = memory
        yield from self._chunks


# ─── EngineCapabilities ──────────────────────────────────────────────────


def test_capabilities_defaults_are_conservative() -> None:
    """Only control_level is required; every capability defaults off."""
    caps = EngineCapabilities(control_level=1)
    assert caps.streaming is False
    assert caps.stateful_sessions is False
    assert caps.shared_prefix is False
    assert caps.server_side_tools is False
    assert caps.continuous_batching is False
    assert caps.kv_persistence is False


def test_capabilities_is_frozen() -> None:
    caps = EngineCapabilities(control_level=3)
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises
        caps.streaming = True  # type: ignore[misc]


# ─── EngineMemoryConfig validation ───────────────────────────────────────


def test_memory_config_defaults() -> None:
    cfg = EngineMemoryConfig()
    assert cfg.kv_cache_quant is None
    assert cfg.flash_attention is False
    assert cfg.use_mmap is True


def test_kv_quant_requires_flash_attention() -> None:
    """The one hard rule: quantized KV without flash attention is a
    performance trap, so we reject it early with a clear error."""
    with pytest.raises(ValueError, match="flash_attention"):
        EngineMemoryConfig(kv_cache_quant="q8_0", flash_attention=False)


def test_kv_quant_allowed_with_flash_attention() -> None:
    cfg = EngineMemoryConfig(kv_cache_quant="q8_0", flash_attention=True)
    assert cfg.kv_cache_quant == "q8_0"


def test_flash_attention_alone_is_fine() -> None:
    cfg = EngineMemoryConfig(flash_attention=True)
    assert cfg.flash_attention is True
    assert cfg.kv_cache_quant is None


# ─── chat() accumulates chat_stream() ────────────────────────────────────


def test_chat_accumulates_deltas() -> None:
    engine = FakeEngine(
        [
            ChatChunk(delta="Hello, "),
            ChatChunk(delta="world"),
            ChatChunk(delta="!", done=True, finish_reason="stop"),
        ]
    )
    resp = engine.chat(model="fake-model", messages=[{"role": "user", "content": "hi"}])
    assert isinstance(resp, ChatResponse)
    assert resp.text == "Hello, world!"
    assert resp.finish_reason == "stop"
    assert resp.tool_calls == ()


def test_chat_collects_tool_calls() -> None:
    tc = ToolCall(id="1", name="search", arguments='{"q":"x"}')
    engine = FakeEngine(
        [
            ChatChunk(delta="let me search"),
            ChatChunk(tool_call=tc),
            ChatChunk(done=True, finish_reason="tool_calls"),
        ]
    )
    resp = engine.chat(model="fake-model", messages=[])
    assert resp.tool_calls == (tc,)
    assert resp.finish_reason == "tool_calls"


def test_chat_passes_memory_through() -> None:
    engine = FakeEngine([ChatChunk(delta="ok", done=True)])
    cfg = EngineMemoryConfig(context_size=4096)
    engine.chat(model="fake-model", messages=[], memory=cfg)
    assert engine.last_memory is cfg


def test_chat_empty_stream_yields_empty_response() -> None:
    engine = FakeEngine([])
    resp = engine.chat(model="fake-model", messages=[])
    assert resp.text == ""
    assert resp.finish_reason is None
    assert resp.tool_calls == ()


# ─── open_session loud refusal ───────────────────────────────────────────


def test_open_session_refuses_on_non_level3() -> None:
    """A stateless engine must refuse loudly, naming itself."""
    engine = FakeEngine([])
    with pytest.raises(CapabilityUnsupported) as exc:
        engine.open_session(model="fake-model")
    assert "fake" in str(exc.value)
    assert "level-3" in str(exc.value)


# ─── protocol conformance ────────────────────────────────────────────────


def test_fake_engine_satisfies_protocol() -> None:
    """The base subclass structurally satisfies InferenceEngine."""
    engine = FakeEngine([])
    assert isinstance(engine, InferenceEngine)


def test_messages_are_frozen() -> None:
    chunk = ChatChunk(delta="x")
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises
        chunk.delta = "y"  # type: ignore[misc]
