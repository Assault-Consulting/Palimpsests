"""Tests for the server-side tool loop (N5).

The point of N5: after an external tool runs, append_tool_result feeds
only the tool result into the live KV and resumes generation — the
conversation is not re-prefilled. The fake backend records the size of
each sequence's feeds, so a test can prove the tool-result feed is small
(just the result) rather than a re-read of the whole conversation.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.engine import CapabilityUnsupported
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession


class FakeBackend:
    """Deterministic NativeBackend recording every feed's first-decode size.

    ``feed_sizes`` collects, per turn, the number of input tokens in the
    first decode of that turn — so a test can compare the tool-result
    feed against the original turn feed.
    """

    def __init__(
        self,
        *,
        vocab_size: int = 64,
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
        # Every decode's batch entry sizes, in call order, per seq.
        self.feed_sizes: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            self.feed_sizes.append(len(list(entry.tokens)))
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
        pass

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return b""

    def state_set(self, seq_id: int, state: bytes) -> None:
        pass

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


def _session(backend: FakeBackend, **kwargs) -> NativeSession:
    kwargs.setdefault("stop_tokens", (0,))
    return NativeSession(backend, Scheduler(backend, max_active=1), **kwargs)


# ─── append_tool_result continues the same turn ───────────────────────────


def test_append_tool_result_streams_a_continuation():
    # First the model turn generates two tokens then a stop; then, after a
    # tool result, it generates two more then stop.
    backend = FakeBackend(eos=0, script={0: [5, 6, 0, 7, 8, 0]})
    sess = _session(backend)
    list(sess.send("use a tool please"))
    chunks = list(sess.append_tool_result("call_1", "42"))
    text = "".join(c.delta for c in chunks)
    assert text  # produced a continuation
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"


# ─── the whole point: the tool result is not a re-prefill ─────────────────


def test_tool_result_feed_is_small_not_a_reprefill():
    backend = FakeBackend(eos=0, script={0: [5, 6, 0, 7, 0]})
    sess = _session(
        backend, system_prompt="a long detailed system prompt for the agent"
    )
    # The first turn's first feed is system prompt + a long user message.
    list(sess.send("a fairly long user message asking for a tool call"))
    first_turn_feed = backend.feed_sizes[0]

    # Mark where the tool-result feeds begin.
    boundary = len(backend.feed_sizes)
    list(sess.append_tool_result("call_1", "7"))
    tool_feed = backend.feed_sizes[boundary]

    # The tool-result feed carries only the short result, not the whole
    # conversation — so it must be much smaller than the first turn's feed.
    assert tool_feed < first_turn_feed


def test_tool_loop_keeps_slot_alive_until_close():
    backend = FakeBackend(eos=0, script={0: [5, 0, 6, 0]})
    sess = _session(backend)
    list(sess.send("hi"))
    list(sess.append_tool_result("call_1", "r"))
    # nothing released while the session lives
    assert backend.removed == []
    sess.close()
    assert backend.removed == [0]


def test_append_tool_result_after_close_raises():
    backend = FakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    sess.close()
    with pytest.raises(RuntimeError):
        list(sess.append_tool_result("call_1", "r"))


# ─── persistence still refuses (N6) ───────────────────────────────────────


def test_save_state_still_refuses():
    sess = _session(FakeBackend())
    with pytest.raises(CapabilityUnsupported):
        sess.save_state()


def test_load_state_still_refuses():
    sess = _session(FakeBackend())
    with pytest.raises(CapabilityUnsupported):
        sess.load_state(b"")
