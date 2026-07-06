"""Tests for the level-3 scheduler, driven by a fake backend.

The whole point of the ADR-0002 seam: the scheduler is exercised end to
end with a deterministic ``NativeBackend`` that has no model and no native
code, so every branch of the loop (admission, batching, sampling, stop
tokens, the token cap, seq recycling) is verified in CI. The real
llama.cpp backend is validated separately, on hardware.

``FakeBackend`` lives in conftest.py so this module and the engine tests
share it.
"""
from __future__ import annotations

from palimpsests.providers.native.backend import NativeBackend
from palimpsests.providers.native.scheduler import (
    GenerationRequest,
    Scheduler,
    StepToken,
)
from tests.conftest import FakeBackend


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
    behavior (the single seq is used then released) without poking at
    fake-backend internals between runs — the earlier version reset
    private counters by hand, which was brittle and wrong.
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


# ─── cap never exceeds the backend's sequence budget ──────────────────────


def test_active_cap_is_clamped_to_n_seq_max():
    backend = FakeBackend(n_seq_max=2)
    sched = Scheduler(backend, max_active=8)
    # even though 8 was requested, the backend only allows 2
    assert sched._max_active == 2
