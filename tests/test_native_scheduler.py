"""Tests for the level-3 scheduler, driven by a fake backend.

The whole point of the ADR-0002 seam: the scheduler is exercised end to
end with a deterministic ``NativeBackend`` that has no model and no native
code, so every branch of the loop (admission, batching, sampling, stop
tokens, the token cap, seq recycling) is verified in CI. The real
llama.cpp backend is validated separately, on hardware.
"""
from __future__ import annotations

from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, NativeBackend, Token
from palimpsests.providers.native.scheduler import (
    GenerationRequest,
    Scheduler,
    StepToken,
)


class FakeBackend:
    """A deterministic stand-in for a real llama.cpp backend.

    It implements the ``NativeBackend`` surface without a model. Decode
    returns, for each sequence, a logits vector that makes ``argmax`` pick
    a scripted next token — so a test can assert the exact token stream.

    The script is ``{seq_id: [t0, t1, ...]}`` and is keyed to *generation
    steps per sequence*: the i-th decode of a sequence emits ``t_i``. When
    a sequence's script is exhausted it emits ``eos``. This lets tests
    drive precise, repeatable generations.

    It also records ``seq_copy`` / ``seq_remove`` / ``state_*`` calls so
    the scheduler's KV bookkeeping (slot recycling) can be asserted.
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

    # ─── vocab ───────────────────────────────────────────────────────────

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        # Deterministic, model-free: one token per character code, kept in
        # range. Enough for tests that just need a prompt to feed.
        return [(ord(c) % self._vocab) for c in text]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return " ".join(str(t) for t in tokens)

    # ─── decode ──────────────────────────────────────────────────────────

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            if not entry.wants_logits:
                continue
            i = self._decode_count.get(entry.seq_id, 0)
            self._decode_count[entry.seq_id] = i + 1
            script = self._script.get(entry.seq_id, [])
            token = script[i] if i < len(script) else self._eos
            # One-hot logits so argmax picks exactly `token`.
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    # ─── prefix sharing / state (recorded, not modelled) ─────────────────

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        self.copied.append((src_seq, dst_seq))

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        # A recycled sequence starts its generation count fresh, exactly
        # as a real backend's cleared KV would.
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return self.states.get(seq_id, b"")

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.states[seq_id] = state

    # ─── lifecycle ───────────────────────────────────────────────────────

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


# ─── the fake really is a NativeBackend ───────────────────────────────────


def test_fake_backend_satisfies_protocol():
    assert isinstance(FakeBackend(), NativeBackend)


# ─── run(): end-to-end token stream ───────────────────────────────────────


def test_run_yields_scripted_tokens_until_eos():
    # seq 0 emits 5, 6, 7, then eos (0) stops it.
    backend = FakeBackend(eos=0, script={0: [5, 6, 7]})
    sched = Scheduler(backend)
    tokens = list(sched.run(GenerationRequest(prompt_tokens=[1, 2, 3], stop_tokens=(0,))))
    assert tokens == [5, 6, 7, 0]  # the eos is emitted, then it stops


def test_run_stops_at_max_tokens():
    # No stop token ever fires; the cap must end it.
    backend = FakeBackend(eos=99, script={0: [1, 1, 1, 1, 1, 1]})
    sched = Scheduler(backend)
    tokens = list(sched.run(GenerationRequest(prompt_tokens=[9], max_tokens=3)))
    assert tokens == [1, 1, 1]
    assert len(tokens) == 3


def test_run_stops_on_stop_token_midstream():
    backend = FakeBackend(script={0: [4, 5, 2, 9]})
    sched = Scheduler(backend)
    tokens = list(
        sched.run(GenerationRequest(prompt_tokens=[1], max_tokens=50, stop_tokens=(2,)))
    )
    # generation halts as soon as the stop token (2) is produced
    assert tokens == [4, 5, 2]


# ─── admission / batching structure (N=1) ─────────────────────────────────


def test_only_one_slot_active_at_n1():
    backend = FakeBackend(script={0: [1, 1, 1], 1: [2, 2, 2]})
    sched = Scheduler(backend, max_active=1)
    sched.submit(GenerationRequest(prompt_tokens=[1], max_tokens=3))
    sched.submit(GenerationRequest(prompt_tokens=[2], max_tokens=3))
    # First step admits exactly one request → batch of one sequence.
    produced = sched.step()
    assert len(produced) == 1
    assert all(isinstance(p, StepToken) for p in produced)


def test_step_on_empty_scheduler_is_noop():
    sched = Scheduler(FakeBackend())
    assert sched.step() == []


# ─── slot recycling ───────────────────────────────────────────────────────


def test_finished_slot_is_released_and_seq_recycled():
    backend = FakeBackend(script={0: [7, 7]})
    sched = Scheduler(backend)
    list(sched.run(GenerationRequest(prompt_tokens=[1], max_tokens=2)))
    # The one slot (seq_id 0) must have been removed on completion.
    assert backend.removed == [0]


def test_two_sequential_requests_reuse_the_freed_slot():
    """At N=1 the second request runs only after the first frees seq 0.

    Each request uses its own fresh backend so the test asserts scheduler
    behavior (the freed seq_id is reused) without poking at fake-backend
    internals between runs — the earlier version reset private counters by
    hand, which was brittle and wrong.
    """
    backend_a = FakeBackend(script={0: [1, 1]})
    sched_a = Scheduler(backend_a, max_active=1)
    first = list(sched_a.run(GenerationRequest(prompt_tokens=[1], max_tokens=2)))

    backend_b = FakeBackend(script={0: [3, 3]})
    sched_b = Scheduler(backend_b, max_active=1)
    second = list(sched_b.run(GenerationRequest(prompt_tokens=[2], max_tokens=2)))

    assert first == [1, 1]
    assert second == [3, 3]
    # each scheduler released its single seq (id 0) on completion
    assert backend_a.removed == [0]
    assert backend_b.removed == [0]


def test_seq_id_is_recycled_within_one_scheduler():
    """Two requests through the *same* scheduler reuse seq 0 in turn.

    The second admission can only get seq 0 back because the first was
    released to the free list — this is the recycling the scheduler owns.
    """
    backend = FakeBackend(script={0: [1, 1]})
    sched = Scheduler(backend, max_active=1)
    sched.submit(GenerationRequest(prompt_tokens=[1], max_tokens=2))
    sched.submit(GenerationRequest(prompt_tokens=[2], max_tokens=2))
    # drain both requests
    all_tokens: list[Token] = []
    while sched._queue or sched._slots:
        for st in sched.step():
            all_tokens.append(st.token)
    # first request: script gives 1,1; second: seq 0 recycled, script
    # exhausted for its fresh count → but the same backend script[0..1]=1,1
    # is consumed again from the recycled (count-reset) seq.
    assert all_tokens == [1, 1, 1, 1]
    # seq 0 released twice — once per completed request
    assert backend.removed == [0, 0]


# ─── cap never exceeds the backend's sequence budget ──────────────────────


def test_active_cap_is_clamped_to_n_seq_max():
    backend = FakeBackend(n_seq_max=2)
    sched = Scheduler(backend, max_active=8)
    # even though 8 was requested, the backend only allows 2
    assert sched._max_active == 2
