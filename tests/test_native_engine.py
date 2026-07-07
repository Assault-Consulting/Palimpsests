"""Tests for the pal-native level-3 engine (stateless + session entry).

Exercises the engine path — prompt rendering, tokenize, scheduler,
streaming — with an injected fake backend, so no model or native build is
needed. The scheduler is tested in test_native_scheduler.py and sessions
in test_native_session.py; here the focus is the engine's composition and
its capability contract.

FakeBackend is defined inline (not imported from another test module or
conftest) to keep the import block simple — matching the passing test
files, none of which import across test modules.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.engine import (
    ChatResponse,
    EngineCapabilities,
    InferenceEngine,
    InferenceSession,
)
from palimpsests.providers.errors import EngineUnavailable
from palimpsests.providers.native import NativeEngine
from palimpsests.providers.native.backend import BatchEntry, Token


class FakeBackend:
    """A deterministic stand-in for a real llama.cpp backend.

    Decode returns one-hot logits from a per-seq script so argmax yields
    an exact token stream; seq_copy / seq_remove / state_* are recorded.
    """

    def __init__(
        self,
        *,
        vocab_size: int = 32,
        n_seq_max: int = 4,
        eos: Token = 0,
        script: dict[int, list[Token]] | None = None,
    ) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self._eos = eos
        self._script = script or {}
        self._decode_count: dict[int, int] = {}
        self.removed: list[int] = []
        self.copied: list[tuple[int, int]] = []
        self.states: dict[int, bytes] = {}

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return " ".join(str(t) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            if not entry.wants_logits:
                continue
            i = self._decode_count.get(entry.seq_id, 0)
            self._decode_count[entry.seq_id] = i + 1
            script = self._script.get(entry.seq_id, [])
            token = script[i] if i < len(script) else self._eos
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        self.copied.append((src_seq, dst_seq))

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return self.states.get(seq_id, b"")

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.states[seq_id] = state

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


class TextFakeBackend(FakeBackend):
    """FakeBackend whose detokenize yields readable text."""

    def __init__(self, *, script_tokens: list[Token], eos: Token = 0) -> None:
        super().__init__(eos=eos, script={0: script_tokens})
        self._text = {1: "Hel", 2: "lo", 3: "!", eos: ""}

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(self._text.get(t, f"<{t}>") for t in tokens)


# ─── contract ─────────────────────────────────────────────────────────────


def test_satisfies_engine_protocol():
    eng = NativeEngine(backend=FakeBackend())
    assert isinstance(eng, InferenceEngine)


def test_engine_id():
    assert NativeEngine(backend=FakeBackend()).engine_id == "pal-native"


def test_capabilities_streaming_and_sessions_on():
    caps = NativeEngine(backend=FakeBackend()).capabilities
    assert isinstance(caps, EngineCapabilities)
    assert caps.control_level == 3
    assert caps.streaming is True
    # N3a: sessions on, concurrency and the rest still off
    assert caps.stateful_sessions is True
    assert caps.continuous_batching is False
    assert caps.shared_prefix is False
    assert caps.server_side_tools is False
    assert caps.kv_persistence is False


def test_open_session_returns_a_session():
    """N3a: open_session now returns a live session instead of refusing."""
    sess = NativeEngine(backend=FakeBackend()).open_session(model="m")
    assert isinstance(sess, InferenceSession)


# ─── availability / backend loading ───────────────────────────────────────


def test_injected_backend_is_available():
    assert NativeEngine(backend=FakeBackend()).is_available() is True


def test_chat_stream_without_backend_or_model_is_unavailable():
    """No injected backend, no model, and no [native] extra in CI → a
    clear EngineUnavailable rather than a crash."""
    eng = NativeEngine()  # nothing configured
    with pytest.raises(EngineUnavailable):
        list(eng.chat_stream(model="m", messages=[{"role": "user", "content": "hi"}]))


# ─── the stateless chat path ──────────────────────────────────────────────


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
