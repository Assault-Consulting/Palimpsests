"""Tests for concurrent session batching (N3b).

The point of N3b: several sessions advance together in ONE decode per
step — true continuous batching, not one-after-another. The fake backend
records how many sequences each decode call carried, so a test can prove
that two sessions were actually batched into the same forward pass rather
than run sequentially.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import (
    Scheduler,
    TurnRequest,
)
from palimpsests.providers.native.session import NativeSession, run_sessions


class BatchRecordingBackend:
    """NativeBackend that records the batch width of every decode call.

    ``decode_widths`` is the number of sequences in each decode call, in
    order. If two sessions are truly batched, at least one call has width
    >= 2; if they ran sequentially, every call has width 1.
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
        self.decode_widths: list[int] = []
        self.removed: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        self.decode_widths.append(len(list(entries)))
        out: dict[int, list[float]] = {}
        for entry in entries:
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


# ─── the core claim: two sessions share one decode ────────────────────────


def test_two_sessions_are_batched_into_one_decode():
    # Each session generates two tokens then eos. Scripts are keyed by the
    # seq_id the scheduler will assign (0 and 1 in open order).
    backend = BatchRecordingBackend(
        eos=0, script={0: [5, 6, 0], 1: [7, 8, 0]}, n_seq_max=4
    )
    scheduler = Scheduler(backend, max_active=4)
    a = NativeSession(backend, scheduler)
    b = NativeSession(backend, scheduler)

    result = run_sessions(scheduler, [(a, "hi"), (b, "yo")])

    # Both sessions produced output.
    assert result[a.seq_id]
    assert result[b.seq_id]
    # The decisive check: at least one decode carried both sequences.
    assert max(backend.decode_widths) >= 2


def test_sequential_single_sessions_are_width_one():
    # A single session at a time never batches — every decode is width 1.
    backend = BatchRecordingBackend(eos=0, script={0: [5, 0]}, n_seq_max=4)
    scheduler = Scheduler(backend, max_active=4)
    a = NativeSession(backend, scheduler)
    list(a.send("hi"))
    assert backend.decode_widths  # something happened
    assert max(backend.decode_widths) == 1


# ─── run_batch demultiplexes correctly ────────────────────────────────────


def test_run_batch_tags_tokens_by_seq_id():
    backend = BatchRecordingBackend(
        eos=0, script={0: [5, 5, 0], 1: [7, 7, 0]}, n_seq_max=4
    )
    scheduler = Scheduler(backend, max_active=4)
    a = scheduler.open_slot()
    b = scheduler.open_slot()
    seen: dict[int, list[int]] = {a: [], b: []}
    for st in scheduler.run_batch(
        [
            TurnRequest(seq_id=a, tokens=[1], max_tokens=10, stop_tokens=(0,)),
            TurnRequest(seq_id=b, tokens=[2], max_tokens=10, stop_tokens=(0,)),
        ]
    ):
        seen[st.seq_id].append(st.token)
    # each sequence got exactly its scripted tokens (through eos)
    assert seen[a] == [5, 5, 0]
    assert seen[b] == [7, 7, 0]


def test_run_batch_leaves_session_slots_alive():
    # Session slots persist after a batch turn (KV kept for the next turn);
    # only close releases them.
    backend = BatchRecordingBackend(eos=0, script={0: [5, 0], 1: [7, 0]})
    scheduler = Scheduler(backend, max_active=4)
    a = scheduler.open_slot()
    b = scheduler.open_slot()
    list(
        scheduler.run_batch(
            [
                TurnRequest(seq_id=a, tokens=[1], stop_tokens=(0,)),
                TurnRequest(seq_id=b, tokens=[2], stop_tokens=(0,)),
            ]
        )
    )
    # nothing released mid-batch
    assert backend.removed == []
    scheduler.close_slot(a)
    scheduler.close_slot(b)
    assert set(backend.removed) == {a, b}


# ─── capacity ─────────────────────────────────────────────────────────────


def test_cannot_open_more_sessions_than_max_active():
    backend = BatchRecordingBackend(n_seq_max=8)
    scheduler = Scheduler(backend, max_active=2)
    scheduler.open_slot()
    scheduler.open_slot()
    with pytest.raises(RuntimeError):
        scheduler.open_slot()


def test_max_active_clamped_to_backend_budget():
    backend = BatchRecordingBackend(n_seq_max=2)
    scheduler = Scheduler(backend, max_active=8)
    assert scheduler.max_active == 2
