# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Release-ordering guard for prefix holders under shared KV (N4a).

In unified-KV mode a holder's prefix cells are shared with every session
seeded from it via ``seq_copy``; freeing the holder while a consumer is still
live corrupts that consumer (measured on hardware — a partial logit shift the
greedy chain hides, see ``test_kv_unified_isolation.py``). The scheduler tracks
each holder's live consumers and refuses an early release with
``PrefixHolderInUseError``.

These tests exercise the *bookkeeping* — the consumer set, the increment on
``copy_prefix_to_slot``, the decrement on ``_release``, and the throw on
``release_prefix_holder`` — on the fake backend, so the contract runs in CI
with no model. They do NOT test the KV/logit semantics themselves; that is the
hardware isolation suite. The two are complementary: this proves the guard
fires on the right condition; the hardware suite proves the condition is real.

FakeBackend is defined inline, matching the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import PrefixHolderInUseError, Scheduler


class HolderBackend:
    """Minimal NativeBackend recording seq_remove — enough for the guard.

    ``removed`` lists seq_remove calls in order, so a test can assert that a
    permitted release actually reached the backend (and a refused one did not).
    """

    def __init__(self, *, vocab_size: int = 32, n_seq_max: int = 8) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self.removed: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            logits = [0.0] * self._vocab
            logits[0] = 1.0
            out[entry.seq_id] = logits
        return out

    def seq_copy(self, src: int, dst: int, p0: int = -1, p1: int = -1) -> None:
        pass

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)

    def state_get(self, seq_id: int) -> bytes:
        return b""

    def state_set(self, seq_id: int, state: bytes) -> None:
        pass

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        pass


def _holder_with_consumers(sched: Scheduler, n_consumers: int) -> tuple[int, list[int]]:
    """Warm a holder and seed ``n_consumers`` session slots from it."""
    holder = sched.reserve_prefix_holder()
    prefix_len = sched.warm_prefix(holder, [1, 2, 3])
    consumers = []
    for _ in range(n_consumers):
        slot = sched.open_slot()
        sched.copy_prefix_to_slot(holder, slot, prefix_len)
        consumers.append(slot)
    return holder, consumers


def test_release_holder_under_live_consumers_raises():
    """Releasing a holder while any consumer is live is refused."""
    sched = Scheduler(HolderBackend(), max_active=4)
    holder, _ = _holder_with_consumers(sched, 2)
    with pytest.raises(PrefixHolderInUseError, match="live consumer"):
        sched.release_prefix_holder(holder)
    # Refused release must not have touched the backend.
    assert holder not in sched._backend.removed


def test_release_after_one_of_two_consumers_still_raises():
    """The decrement removes the *specific* consumer, not the whole set.

    After releasing one of two consumers the holder still has one live
    consumer, so the release is still refused — this distinguishes a correct
    per-consumer decrement from a decrement that wrongly clears the set.
    """
    sched = Scheduler(HolderBackend(), max_active=4)
    holder, (c1, _c2) = _holder_with_consumers(sched, 2)
    sched._release(c1)
    with pytest.raises(PrefixHolderInUseError, match="live consumer"):
        sched.release_prefix_holder(holder)


def test_release_holder_allowed_after_all_consumers_released():
    """Once every consumer is released, the holder release is permitted."""
    sched = Scheduler(HolderBackend(), max_active=4)
    holder, (c1, c2) = _holder_with_consumers(sched, 2)
    sched._release(c1)
    sched._release(c2)
    sched.release_prefix_holder(holder)  # must not raise
    assert holder in sched._backend.removed
    assert holder not in sched._holders


def test_release_holder_ignores_non_consumer_slots():
    """A live slot that never copied the prefix does not block release.

    The non-consumer slot is not in the holder's consumer set (no
    copy_prefix_to_slot), so discard is a no-op and the guard does not count
    it. Releasing the holder while only a non-consumer is live is permitted.
    """
    sched = Scheduler(HolderBackend(), max_active=4)
    holder = sched.reserve_prefix_holder()
    sched.warm_prefix(holder, [1, 2, 3])
    _non_consumer = sched.open_slot()  # NOT seeded from the holder
    sched.release_prefix_holder(holder)  # must not raise
    assert holder in sched._backend.removed


def test_release_holder_with_no_consumers_is_clean():
    """A warmed holder nobody copied from can be released immediately."""
    sched = Scheduler(HolderBackend(), max_active=4)
    holder = sched.reserve_prefix_holder()
    sched.warm_prefix(holder, [1, 2, 3])
    sched.release_prefix_holder(holder)  # must not raise
    assert holder in sched._backend.removed


def test_double_release_of_consumer_is_idempotent():
    """A second _release of the same consumer does not underflow the set."""
    sched = Scheduler(HolderBackend(), max_active=4)
    holder, (c1, c2) = _holder_with_consumers(sched, 2)
    sched._release(c1)
    sched._release(c1)  # idempotent discard, not an error
    # c2 is still a live consumer, so release is still refused.
    with pytest.raises(PrefixHolderInUseError, match="live consumer"):
        sched.release_prefix_holder(holder)
    sched._release(c2)
    sched.release_prefix_holder(holder)  # now permitted


def test_release_holder_idempotent_when_not_a_holder():
    """Releasing an unknown / already-released holder is a no-op, as before."""
    sched = Scheduler(HolderBackend(), max_active=4)
    sched.release_prefix_holder(999)  # not a holder — no raise, no effect
    assert sched._backend.removed == []
