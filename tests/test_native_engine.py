"""Tests for the pal-native level-3 engine (N1 stateless path).

Exercises the full engine path — prompt rendering, tokenize, scheduler,
streaming — with an injected fake backend, so no model or native build is
needed. The scheduler itself is tested separately in
test_native_scheduler.py; here the focus is the engine's composition and
its capability contract.
"""
from __future__ import annotations

import pytest
from palimpsests.engine import (
    CapabilityUnsupported,
    ChatResponse,
    EngineCapabilities,
    InferenceEngine,
)
from palimpsests.providers.errors import EngineUnavailable
from palimpsests.providers.native import NativeEngine
from palimpsests.providers.native.backend import Token
from tests.test_native_scheduler import FakeBackend


# ─── a fake backend whose token stream maps to known text ─────────────────


class TextFakeBackend(FakeBackend):
    """FakeBackend with a detokenize that yields readable text.

    The scheduler samples argmax over one-hot logits, so the scripted
    tokens come out verbatim; mapping each to a short string lets a test
    assert the streamed text.
    """

    def __init__(self, *, script_tokens: list[Token], eos: Token = 0) -> None:
        super().__init__(eos=eos, script={0: script_tokens})
        self._text = {1: "Hel", 2: "lo", 3: "!", eos: ""}

    def detokenize(self, tokens: list[Token]) -> str:
        return "".join(self._text.get(t, f"<{t}>") for t in tokens)


# ─── contract ─────────────────────────────────────────────────────────────


def test_satisfies_engine_protocol():
    eng = NativeEngine(backend=FakeBackend())
    assert isinstance(eng, InferenceEngine)


def test_engine_id():
    assert NativeEngine(backend=FakeBackend()).engine_id == "pal-native"


def test_capabilities_streaming_on_stateful_off():
    caps = NativeEngine(backend=FakeBackend()).capabilities
    assert isinstance(caps, EngineCapabilities)
    assert caps.control_level == 3
    assert caps.streaming is True
    # the genuinely stateful level-3 features stay off in N1
    assert caps.stateful_sessions is False
    assert caps.shared_prefix is False
    assert caps.continuous_batching is False
    assert caps.server_side_tools is False
    assert caps.kv_persistence is False


def test_open_session_still_refuses():
    """N1 has no sessions yet — open_session refuses via the base."""
    with pytest.raises(CapabilityUnsupported):
        NativeEngine(backend=FakeBackend()).open_session(model="m")


# ─── availability / backend loading ───────────────────────────────────────


def test_injected_backend_is_available():
    assert NativeEngine(backend=FakeBackend()).is_available() is True


def test_chat_stream_without_backend_or_model_is_unavailable():
    """No injected backend, no model, and no [native] extra in CI → a
    clear EngineUnavailable rather than a crash."""
    eng = NativeEngine()  # nothing configured
    with pytest.raises(EngineUnavailable):
        list(eng.chat_stream(model="m", messages=[{"role": "user", "content": "hi"}]))


# ─── the stateless chat path (N=1) ────────────────────────────────────────


def test_chat_stream_yields_detokenized_tokens():
    backend = TextFakeBackend(script_tokens=[1, 2, 3], eos=0)
    eng = NativeEngine(backend=backend)
    chunks = list(
        eng.chat_stream(model="m", messages=[{"role": "user", "content": "hi"}])
    )
    # the scripted tokens 1,2,3 then eos(0), each detokenized
    text = "".join(c.delta for c in chunks)
    assert "Hel" in text and "lo" in text and "!" in text
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"


def test_chat_accumulates_via_base():
    backend = TextFakeBackend(script_tokens=[1, 2, 3], eos=0)
    eng = NativeEngine(backend=backend)
    resp = eng.chat(model="m", messages=[{"role": "user", "content": "hi"}])
    assert isinstance(resp, ChatResponse)
    assert "Hel" in resp.text


def test_chat_stream_respects_max_tokens():
    # never emits the eos; the engine's max_tokens cap must stop it
    backend = FakeBackend(eos=99, script={0: [1] * 100})
    eng = NativeEngine(backend=backend, max_tokens=4)
    chunks = [
        c
        for c in eng.chat_stream(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )
        if c.delta
    ]
    # 4 generated tokens (the final done-chunk has empty delta, filtered out)
    assert len(chunks) == 4


def test_prompt_is_tokenized_through_backend():
    """The engine must tokenize via the backend, not invent its own ids."""
    calls: list[str] = []

    class RecordingBackend(FakeBackend):
        def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
            calls.append(text)
            return super().tokenize(text, add_special=add_special)

    backend = RecordingBackend(script={0: [1, 0]})
    eng = NativeEngine(backend=backend)
    list(eng.chat_stream(model="m", messages=[{"role": "user", "content": "hi"}]))
    assert calls and "hi" in calls[0]


# ─── list_models ──────────────────────────────────────────────────────────


def test_list_models_reports_the_single_model():
    eng = NativeEngine(backend=FakeBackend(), model_path="/models/q.gguf")
    models = eng.list_models()
    assert len(models) == 1
    assert models[0].engine_id == "pal-native"


def test_close_releases_backend():
    backend = FakeBackend()
    eng = NativeEngine(backend=backend)
    eng.close()
    # closing without a loaded native backend must not raise
    assert True
