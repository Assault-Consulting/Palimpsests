"""Tests for prefix holder primitives (N4a).

Proves the shared-prefix mechanism on the fake backend: a prefix is
decoded into a holder exactly once (warm_prefix), a session slot seeded
from it via copy_prefix_to_slot gets the holder's KV (seq_copy) and a
position past the prefix (seed_n_past), so the session decodes its own
turn from prefix_len WITHOUT re-decoding the prefix — the whole point of
N4. Also covers that a holder occupies a real sequence (reducing the
budget) and that releasing it recycles the sequence.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler, TurnRequest


class PrefixRecordingBackend:
    """NativeBackend recording decode entries and seq_copy calls.

    ``decodes`` is a list of ``(seq_id, start_pos, length)``; ``copies``
    is a list of ``(src, dst)``; ``removed`` records seq_remove. Enough to
    prove the prefix is warmed once, copied, and that the seeded slot
    starts past it.
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
        self.decodes: list[tuple[int, int, int]] = []
        self.copies: list[tuple[int, int]] = []
        self.removed: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            self.decodes.append(
                (entry.seq_id, entry.start_pos, len(list(entry.tokens)))
            )
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
        self.copies.append((src_seq, dst_seq))

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


# ─── warm_prefix decodes once and returns the length ──────────────────────


def test_warm_prefix_decodes_once_at_zero():
    backend = PrefixRecordingBackend()
    sched = Scheduler(backend, max_active=4)
    holder = sched.reserve_prefix_holder()
    length = sched.warm_prefix(holder, [1, 2, 3, 4, 5])
    assert length == 5
    # exactly one decode, on the holder, at position 0, covering the prefix
    assert backend.decodes == [(holder, 0, 5)]


def test_warm_prefix_on_non_holder_raises():
    backend = PrefixRecordingBackend()
    sched = Scheduler(backend, max_active=4)
    with pytest.raises(RuntimeError):
        sched.warm_prefix(999, [1, 2, 3])


# ─── copy_prefix_to_slot: seq_copy + seed, no re-decode of the prefix ─────


def test_seeded_slot_starts_past_the_prefix_without_redecoding_it():
    # Prefix is 5 tokens. A session seeded from it must decode its own
    # turn starting at position 5, and must NOT decode the prefix again.
    backend = PrefixRecordingBackend(eos=0, script={1: [7, 0]})
    sched = Scheduler(backend, max_active=4)
    holder = sched.reserve_prefix_holder()
    prefix_len = sched.warm_prefix(holder, [1, 2, 3, 4, 5])
    decodes_after_warm = len(backend.decodes)

    slot = sched.open_slot()
    sched.copy_prefix_to_slot(holder, slot, prefix_len)
    # the holder's KV was copied into the slot
    assert backend.copies == [(holder, slot)]

    # run one short turn on the seeded slot
    list(
        sched.run_batch(
            [TurnRequest(seq_id=slot, tokens=[9, 9], stop_tokens=(0,))]
        )
    )
    # the slot's first decode starts at prefix_len (5), not 0 — and none of
    # the new decodes re-fed the 5 prefix tokens
    slot_decodes = backend.decodes[decodes_after_warm:]
    assert slot_decodes[0] == (slot, prefix_len, 2)
    # no decode after warming re-fed the whole prefix on the holder
    assert all(sid != holder for (sid, _sp, _ln) in slot_decodes)


def test_copy_from_non_holder_raises():
    backend = PrefixRecordingBackend()
    sched = Scheduler(backend, max_active=4)
    slot = sched.open_slot()
    with pytest.raises(RuntimeError):
        sched.copy_prefix_to_slot(12345, slot, 3)


# ─── a holder occupies a real sequence (budget cost) ──────────────────────


def test_holder_consumes_a_sequence_from_the_budget():
    # Only 2 sequences exist. One holder + one session leaves nothing.
    backend = PrefixRecordingBackend(n_seq_max=2)
    sched = Scheduler(backend, max_active=2)
    sched.reserve_prefix_holder()
    sched.open_slot()
    # both sequences are now taken; a second session cannot open
    with pytest.raises(RuntimeError):
        sched.open_slot()


def test_reserve_holder_with_no_free_sequence_raises():
    backend = PrefixRecordingBackend(n_seq_max=1)
    sched = Scheduler(backend, max_active=1)
    sched.reserve_prefix_holder()
    with pytest.raises(RuntimeError):
        sched.reserve_prefix_holder()


# ─── releasing a holder recycles its sequence ─────────────────────────────


def test_release_holder_recycles_the_sequence():
    backend = PrefixRecordingBackend(n_seq_max=1)
    sched = Scheduler(backend, max_active=1)
    holder = sched.reserve_prefix_holder()
    sched.release_prefix_holder(holder)
    # its KV was dropped
    assert backend.removed == [holder]
    # and the sequence is reusable — reserving again works
    again = sched.reserve_prefix_holder()
    assert again == holder


def test_release_holder_is_idempotent():
    backend = PrefixRecordingBackend(n_seq_max=2)
    sched = Scheduler(backend, max_active=2)
    holder = sched.reserve_prefix_holder()
    sched.release_prefix_holder(holder)
    sched.release_prefix_holder(holder)  # must not raise or double-remove
    assert backend.removed == [holder]
