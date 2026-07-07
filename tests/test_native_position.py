"""Tests for per-slot KV position tracking (N-pos).

Proves the scheduler tells the backend the right ``start_pos`` for every
decode: the first decode of a sequence starts at 0, each subsequent
decode starts after the tokens already fed, and a session's later turns
continue from the accumulated position (the KV is not reset between
turns). The fake backend records every entry's ``(seq_id, start_pos,
length)`` so the progression can be asserted exactly.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import (
    GenerationRequest,
    Scheduler,
    TurnRequest,
)


class PositionRecordingBackend:
    """NativeBackend that records the start_pos of every decode entry.

    ``entries_log`` is a list of ``(seq_id, start_pos, length)`` in decode
    order, so a test can assert the exact position progression.
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
        self.entries_log: list[tuple[int, int, int]] = []
        self.removed: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            self.entries_log.append(
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


# ─── stateless: position advances by tokens fed ───────────────────────────


def test_first_decode_starts_at_zero():
    backend = PositionRecordingBackend(eos=0, script={0: [5, 0]})
    sched = Scheduler(backend)
    list(sched.run(GenerationRequest(prompt_tokens=[1, 2, 3], max_tokens=5)))
    # first entry: seq 0, start_pos 0, length 3 (the prompt)
    assert backend.entries_log[0] == (0, 0, 3)


def test_position_advances_by_prompt_then_one_per_token():
    backend = PositionRecordingBackend(eos=0, script={0: [5, 6, 0]})
    sched = Scheduler(backend)
    list(sched.run(GenerationRequest(prompt_tokens=[1, 2, 3, 4], max_tokens=5)))
    # prompt of 4 at pos 0, then each generated token one step further
    positions = [(sp, ln) for (_sid, sp, ln) in backend.entries_log]
    assert positions[0] == (0, 4)  # prompt: 4 tokens at pos 0
    assert positions[1] == (4, 1)  # first generated token at pos 4
    assert positions[2] == (5, 1)  # next at pos 5


# ─── session: later turns continue from the accumulated position ──────────


def test_session_second_turn_continues_from_prior_position():
    # Turn one: feed 2 tokens, generate one then eos (2 decodes).
    # Turn two: feed 2 tokens — must start AFTER everything turn one used.
    backend = PositionRecordingBackend(eos=0, script={0: [7, 0, 9, 0]})
    sched = Scheduler(backend)
    seq = sched.open_slot()

    list(
        sched.run_batch(
            [TurnRequest(seq_id=seq, tokens=[1, 2], stop_tokens=(0,))]
        )
    )
    used_turn_one = backend.entries_log[-1][1] + backend.entries_log[-1][2]

    mark = len(backend.entries_log)
    list(
        sched.run_batch(
            [TurnRequest(seq_id=seq, tokens=[3, 4], stop_tokens=(0,))]
        )
    )
    second_turn_first = backend.entries_log[mark]

    # The second turn's first feed starts exactly where the first turn's
    # KV ended — no reset, no gap.
    assert second_turn_first[1] == used_turn_one


# ─── seed_n_past: for slots seeded from a copied/restored KV ──────────────


def test_seed_n_past_sets_the_starting_position():
    backend = PositionRecordingBackend(eos=0, script={0: [5, 0]})
    sched = Scheduler(backend)
    seq = sched.open_slot()
    # Pretend a prefix of 10 tokens was copied into this slot's KV.
    sched.seed_n_past(seq, 10)
    list(
        sched.run_batch(
            [TurnRequest(seq_id=seq, tokens=[1, 2], stop_tokens=(0,))]
        )
    )
    # The first decode must start at 10, not 0 — the copied prefix is there.
    assert backend.entries_log[0] == (seq, 10, 2)


# ─── a fresh sequence (recycled slot) resets to zero ──────────────────────


def test_recycled_stateless_slot_starts_fresh_at_zero():
    backend = PositionRecordingBackend(eos=0, script={0: [5, 0]})
    sched = Scheduler(backend, max_active=1)
    # First request occupies seq 0 and finishes, freeing it.
    list(sched.run(GenerationRequest(prompt_tokens=[1, 2], max_tokens=5)))
    mark = len(backend.entries_log)
    # Second request reuses seq 0 — but as a fresh sequence at pos 0.
    list(sched.run(GenerationRequest(prompt_tokens=[3, 4, 5], max_tokens=5)))
    assert backend.entries_log[mark] == (0, 0, 3)
