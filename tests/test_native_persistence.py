"""Tests for session KV persistence (N6).

Proves save_state / load_state on the fake backend: save returns a
self-contained blob (an n_past header plus the backend's KV bytes); load
restores the backend state and the position, so a restored session
resumes from where it was frozen without re-prefilling. A round trip
reproduces the saved position.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession


class StateFakeBackend:
    """NativeBackend with a real per-sequence state store.

    ``state_get`` returns a bytes blob unique to the sequence's current
    decode count (so distinct histories serialize distinctly);
    ``state_set`` records what was restored. Enough to prove the session
    packs/unpacks n_past and routes bytes through the backend.
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
        self.set_calls: list[tuple[int, bytes]] = []
        self.decodes: list[tuple[int, int, int]] = []

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
        pass

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        # A blob that encodes the sequence's decode count, so different
        # histories produce different bytes.
        return b"KV" + bytes([seq_id, self._decode_count.get(seq_id, 0)])

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.set_calls.append((seq_id, state))

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


def _session(backend: StateFakeBackend, **kwargs) -> NativeSession:
    kwargs.setdefault("stop_tokens", (0,))
    return NativeSession(backend, Scheduler(backend, max_active=1), **kwargs)


# ─── save_state returns a self-contained blob with the position ───────────


def test_save_state_packs_n_past_header():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("hello there"))  # advances n_past past the fed tokens
    blob = sess.save_state()
    # first 4 bytes are the big-endian n_past; the rest is the KV payload
    n_past = int.from_bytes(blob[:4], "big")
    assert n_past > 0
    assert blob[4:].startswith(b"KV")


# ─── load_state restores the backend state and the position ───────────────


def test_load_state_restores_backend_and_position():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("some context to build up state"))
    saved = sess.save_state()
    saved_n_past = int.from_bytes(saved[:4], "big")

    # A fresh session on the same backend, restored from the blob.
    restored = _session(backend)
    restored.load_state(saved)
    # the backend received the KV payload (without the header)
    assert backend.set_calls
    _seq, payload = backend.set_calls[-1]
    assert payload == saved[4:]
    # and the restored slot resumes at the saved position
    assert restored._scheduler.slot_n_past(restored.seq_id) == saved_n_past


# ─── after restore, the next turn resumes without re-prefill ──────────────


def test_restored_session_resumes_without_reprefill():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("a reasonably long first user turn"))
    saved = sess.save_state()
    saved_n_past = int.from_bytes(saved[:4], "big")

    restored = _session(backend)
    restored.load_state(saved)
    mark = len(backend.decodes)
    list(restored.send("q"))
    # the restored session's first decode starts at the saved position —
    # it did not re-feed the earlier context
    first_after = backend.decodes[mark]
    assert first_after[1] == saved_n_past


# ─── errors ───────────────────────────────────────────────────────────────


def test_load_state_rejects_truncated_blob():
    backend = StateFakeBackend()
    sess = _session(backend)
    with pytest.raises(ValueError):
        sess.load_state(b"\x00")  # shorter than the 4-byte header


def test_save_state_after_close_raises():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    sess.close()
    with pytest.raises(RuntimeError):
        sess.save_state()
