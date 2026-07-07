"""Tests for the level-3 stateful session (N3a).

Exercises NativeSession end to end with a fake backend: the session holds
a slot across turns, later turns reuse the held KV instead of
re-prefilling, and the not-yet-implemented features (tool loop, KV
persistence) refuse loudly. Pure Python, no model — the whole session
path is CI-verified.

FakeBackend is defined inline (not imported across test modules) to keep
the import block simple, matching the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.engine import CapabilityUnsupported, InferenceSession
from palimpsests.providers.native import NativeEngine
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession


class FakeBackend:
    """Deterministic NativeBackend: scripted per-seq tokens, recorded calls.

    ``feed_lengths`` records the number of input tokens the scheduler put
    into each decode call's first step for a sequence — used to prove that
    a second turn does NOT re-prefill the whole conversation.
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
        self.first_feed_lengths: dict[int, int] = {}

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            i = self._decode_count.get(entry.seq_id, 0)
            # Record the input size of the FIRST decode of each turn — a
            # re-prefill would make this large, a KV-reuse keeps it small.
            if entry.seq_id not in self.first_feed_lengths:
                self.first_feed_lengths[entry.seq_id] = len(list(entry.tokens))
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


def _session(backend: FakeBackend, **kwargs) -> NativeSession:
    return NativeSession(backend, Scheduler(backend, max_active=1), **kwargs)


# ─── contract ─────────────────────────────────────────────────────────────


def test_open_session_returns_inference_session():
    eng = NativeEngine(backend=FakeBackend())
    sess = eng.open_session(model="m")
    assert isinstance(sess, InferenceSession)


def test_capabilities_stateful_on_batching_off():
    caps = NativeEngine(backend=FakeBackend()).capabilities
    # N3a: sessions work, concurrency does not yet
    assert caps.stateful_sessions is True
    assert caps.continuous_batching is False
    # unshipped features still off
    assert caps.shared_prefix is False
    assert caps.server_side_tools is False
    assert caps.kv_persistence is False


# ─── the session streams a turn ───────────────────────────────────────────


def test_send_streams_a_turn():
    backend = FakeBackend(eos=0, script={0: [5, 6, 7]})
    sess = _session(backend)
    chunks = list(sess.send("hello"))
    text = "".join(c.delta for c in chunks)
    assert text  # produced some detokenized output
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"


# ─── the whole point: a second turn does not re-prefill ───────────────────


def test_second_turn_reuses_kv_no_reprefill():
    # First turn generates two tokens then eos; second turn likewise.
    backend = FakeBackend(eos=0, script={0: [4, 4, 0, 8, 8, 0]})
    sess = _session(backend, system_prompt="you are a long detailed system prompt")
    list(sess.send("first user message that is fairly long"))
    first_feed = backend.first_feed_lengths[0]

    # Reset the recorder so we capture the second turn's first feed size.
    backend.first_feed_lengths.pop(0, None)
    list(sess.send("q"))
    second_feed = backend.first_feed_lengths[0]

    # The first turn feeds system prompt + user turn; the second feeds only
    # the short new turn — so the second feed must be strictly smaller.
    assert second_feed < first_feed


def test_slot_survives_between_turns_released_on_close():
    backend = FakeBackend(eos=0, script={0: [1, 0, 2, 0]})
    sess = _session(backend)
    list(sess.send("a"))
    # After a turn the slot is NOT released — nothing removed yet.
    assert backend.removed == []
    list(sess.send("b"))
    assert backend.removed == []
    # Only close releases the held sequence.
    sess.close()
    assert backend.removed == [0]


def test_close_is_idempotent():
    backend = FakeBackend(eos=0, script={0: [1, 0]})
    sess = _session(backend)
    list(sess.send("a"))
    sess.close()
    sess.close()  # must not raise or double-release
    assert backend.removed == [0]


def test_send_after_close_raises():
    backend = FakeBackend(eos=0, script={0: [1, 0]})
    sess = _session(backend)
    sess.close()
    with pytest.raises(RuntimeError):
        list(sess.send("a"))


# ─── unshipped features refuse loudly ─────────────────────────────────────


def test_append_tool_result_refuses():
    sess = _session(FakeBackend())
    with pytest.raises(CapabilityUnsupported):
        list(sess.append_tool_result("call_1", "result"))


def test_save_state_refuses():
    sess = _session(FakeBackend())
    with pytest.raises(CapabilityUnsupported):
        sess.save_state()


def test_load_state_refuses():
    sess = _session(FakeBackend())
    with pytest.raises(CapabilityUnsupported):
        sess.load_state(b"")


# ─── one session at a time in N3a ─────────────────────────────────────────


def test_only_one_session_at_a_time_n3a():
    backend = FakeBackend(n_seq_max=4)
    scheduler = Scheduler(backend, max_active=1)
    first = NativeSession(backend, scheduler)
    # A second session on the same (cap-1) scheduler cannot get a slot.
    with pytest.raises(RuntimeError):
        NativeSession(backend, scheduler)
    first.close()
