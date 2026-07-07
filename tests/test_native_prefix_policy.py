"""Tests for the engine-level shared-prefix policy (N4b).

Proves the policy over the N4a mechanism: with share_prefixes on, two
sessions with an identical system prompt share ONE holder (the prefix is
warmed once and copied into each slot), two sessions with different
prompts get separate holders, and with share_prefixes off the old inline
behavior is kept (no holder, no copy). The fake backend records warms
(a decode on a holder sequence) and copies.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

from collections.abc import Sequence
from palimpsests.providers.native import NativeEngine
from palimpsests.providers.native.backend import BatchEntry, Token


class PrefixPolicyBackend:
    """NativeBackend recording seq_copy calls and decode widths.

    ``copies`` is the list of ``(src, dst)`` seq_copy calls — one per
    session seeded from a holder. ``warmed_seqs`` is the set of sequences
    that had a prefix decoded into them at position 0 (holders). Deterministic
    tokenize so identical prompts produce identical token keys.
    """

    def __init__(self, *, vocab_size: int = 64, n_seq_max: int = 8) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self.copies: list[tuple[int, int]] = []
        self.warmed_seqs: list[int] = []
        self._decode_count: dict[int, int] = {}
        self.removed: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            # A warm is a decode at position 0 with more than one token on
            # a sequence we haven't generated on — record the sequence.
            if entry.start_pos == 0 and len(list(entry.tokens)) > 1:
                self.warmed_seqs.append(entry.seq_id)
            self._decode_count[entry.seq_id] = (
                self._decode_count.get(entry.seq_id, 0) + 1
            )
            logits = [0.0] * self._vocab
            logits[0] = 1.0  # always sample token 0 (eos) → turns end fast
            out[entry.seq_id] = logits
        return out

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        self.copies.append((src_seq, dst_seq))

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)

    def state_get(self, seq_id: int) -> bytes:
        return b""

    def state_set(self, seq_id: int, state: bytes) -> None:
        pass

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


# ─── identical prompts share one holder ───────────────────────────────────


def test_identical_prompts_share_one_holder():
    backend = PrefixPolicyBackend()
    eng = NativeEngine(backend=backend, share_prefixes=True)
    eng.open_session(model="m", system_prompt="you are a helpful agent")
    eng.open_session(model="m", system_prompt="you are a helpful agent")

    # The prefix was warmed exactly once (one holder), and each of the two
    # sessions had that holder copied into its slot.
    assert len(backend.warmed_seqs) == 1
    assert len(backend.copies) == 2
    # both copies came from the same holder sequence
    holder_seq = backend.warmed_seqs[0]
    assert all(src == holder_seq for (src, _dst) in backend.copies)


# ─── different prompts get different holders ──────────────────────────────


def test_different_prompts_get_separate_holders():
    backend = PrefixPolicyBackend()
    eng = NativeEngine(backend=backend, share_prefixes=True)
    eng.open_session(model="m", system_prompt="you are agent A")
    eng.open_session(model="m", system_prompt="you are agent B")

    # two distinct prompts → two holders warmed, two copies (one each)
    assert len(backend.warmed_seqs) == 2
    assert len(backend.copies) == 2
    assert backend.warmed_seqs[0] != backend.warmed_seqs[1]


# ─── off by default: no holder, no copy ───────────────────────────────────


def test_share_prefixes_off_keeps_inline_behavior():
    backend = PrefixPolicyBackend()
    eng = NativeEngine(backend=backend, share_prefixes=False)
    eng.open_session(model="m", system_prompt="you are a helpful agent")
    eng.open_session(model="m", system_prompt="you are a helpful agent")
    # no holder warmed, no prefix copied — the inline path is used
    assert backend.warmed_seqs == []
    assert backend.copies == []


def test_no_system_prompt_uses_no_holder_even_when_sharing_on():
    backend = PrefixPolicyBackend()
    eng = NativeEngine(backend=backend, share_prefixes=True)
    eng.open_session(model="m")  # no system prompt
    assert backend.warmed_seqs == []
    assert backend.copies == []


# ─── close releases the holders ───────────────────────────────────────────


def test_close_releases_all_holders():
    backend = PrefixPolicyBackend()
    eng = NativeEngine(backend=backend, share_prefixes=True)
    eng.open_session(model="m", system_prompt="prompt one")
    eng.open_session(model="m", system_prompt="prompt two")
    holders = list(backend.warmed_seqs)
    eng.close()
    # every warmed holder sequence was removed on close
    assert set(backend.removed) >= set(holders)
