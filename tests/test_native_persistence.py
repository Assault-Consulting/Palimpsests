"""Tests for session KV persistence (N6).

Proves save_state / load_state on the fake backend: save returns a
self-contained, framed blob (magic + version + n_past + payload length +
the backend's KV bytes); load validates the frame, restores the backend
state and the position, so a restored session resumes from where it was
frozen without re-prefilling.

The frame exists because load_state's payload reaches a C parser in the
real backend. The rejection tests below therefore matter as much as the
round-trip ones: each proves a malformed blob dies in Python, before any
byte crosses that line.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import (
    NativeSession,
    StateBlobError,
)

# Frame layout, mirrored here so a silent change to the module's constants
# breaks these tests rather than sliding past them.
_MAGIC = b"PALKV1"
_HEADER_LEN = 20
_PAYLOAD_OFFSET = _HEADER_LEN


class StateFakeBackend:
    """NativeBackend with a real per-sequence state store.

    ``state_get`` returns a bytes blob unique to the sequence's current
    decode count (so distinct histories serialize distinctly);
    ``state_set`` records what was restored. Enough to prove the session
    packs/unpacks the frame and routes bytes through the backend.
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


def _n_past_of(blob: bytes) -> int:
    """Read the position out of a framed blob (magic 6 + version 2)."""
    return int.from_bytes(blob[8:12], "big")


# ─── save_state returns a self-contained, framed blob ────────────────────


def test_save_state_frames_the_blob():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("hello there"))  # advances n_past past the fed tokens
    blob = sess.save_state()

    assert blob[:6] == _MAGIC
    assert int.from_bytes(blob[6:8], "big") == 1  # version
    assert _n_past_of(blob) > 0
    declared = int.from_bytes(blob[12:20], "big")
    assert declared == len(blob) - _HEADER_LEN
    assert blob[_PAYLOAD_OFFSET:].startswith(b"KV")


# ─── load_state restores the backend state and the position ───────────────


def test_load_state_restores_backend_and_position():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("some context to build up state"))
    saved = sess.save_state()
    saved_n_past = _n_past_of(saved)

    # A fresh session on the same backend, restored from the blob.
    restored = _session(backend)
    restored.load_state(saved)
    # the backend received the KV payload (without the header)
    assert backend.set_calls
    _seq, payload = backend.set_calls[-1]
    assert payload == saved[_PAYLOAD_OFFSET:]
    # and the restored slot resumes at the saved position
    assert restored._scheduler.slot_n_past(restored.seq_id) == saved_n_past


# ─── after restore, the next turn resumes without re-prefill ──────────────


def test_restored_session_resumes_without_reprefill():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("a reasonably long first user turn"))
    saved = sess.save_state()
    saved_n_past = _n_past_of(saved)

    restored = _session(backend)
    restored.load_state(saved)
    mark = len(backend.decodes)
    list(restored.send("q"))
    # the restored session's first decode starts at the saved position —
    # it did not re-feed the earlier context
    first_after = backend.decodes[mark]
    assert first_after[1] == saved_n_past


# ─── the frame rejects malformed blobs before they reach the backend ──────

# Each of these would, in the real backend, otherwise be handed to
# llama_state_seq_set_data. The assertion that `set_calls` stayed empty is
# the point of the test, not an extra.


def test_load_state_rejects_blob_shorter_than_the_header():
    backend = StateFakeBackend()
    sess = _session(backend)
    with pytest.raises(StateBlobError, match="too short"):
        sess.load_state(b"\x00")
    assert backend.set_calls == []


def test_load_state_rejects_foreign_bytes():
    """Bytes that are simply not ours — the case the old check let through."""
    backend = StateFakeBackend()
    sess = _session(backend)
    with pytest.raises(StateBlobError, match="magic"):
        sess.load_state(b"\x00" * 64)
    assert backend.set_calls == []


def test_load_state_rejects_unknown_version():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("x"))
    blob = bytearray(sess.save_state())
    blob[6:8] = (99).to_bytes(2, "big")

    other = _session(backend)
    with pytest.raises(StateBlobError, match="version"):
        other.load_state(bytes(blob))
    assert backend.set_calls == []


def test_load_state_rejects_truncated_payload():
    """A short read leaves a valid header over a partial payload."""
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("x"))
    blob = sess.save_state()

    other = _session(backend)
    with pytest.raises(StateBlobError, match="length mismatch"):
        other.load_state(blob[:-1])
    assert backend.set_calls == []


def test_load_state_rejects_appended_bytes():
    """Trailing garbage is as wrong as a missing tail, and as invisible
    to a minimum-length check."""
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("x"))
    blob = sess.save_state()

    other = _session(backend)
    with pytest.raises(StateBlobError, match="length mismatch"):
        other.load_state(blob + b"\xff\xff")
    assert backend.set_calls == []


def test_load_state_rejects_empty_payload():
    header = (
        _MAGIC
        + (1).to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(8, "big")
    )
    backend = StateFakeBackend()
    sess = _session(backend)
    with pytest.raises(StateBlobError, match="no KV payload"):
        sess.load_state(header)
    assert backend.set_calls == []


def test_load_state_rejects_implausible_position():
    payload = b"KV\x00\x00"
    blob = (
        _MAGIC
        + (1).to_bytes(2, "big")
        + (0xFFFFFFFF).to_bytes(4, "big")  # n_past far past any context
        + len(payload).to_bytes(8, "big")
        + payload
    )
    backend = StateFakeBackend()
    sess = _session(backend)
    with pytest.raises(StateBlobError, match="implausible position"):
        sess.load_state(blob)
    assert backend.set_calls == []


def test_state_blob_error_is_a_value_error():
    """Existing callers catching ValueError keep working."""
    assert issubclass(StateBlobError, ValueError)


# ─── lifecycle ────────────────────────────────────────────────────────────


def test_save_state_after_close_raises():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    sess.close()
    with pytest.raises(RuntimeError):
        sess.save_state()


def test_load_state_after_close_raises():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    list(sess.send("x"))
    blob = sess.save_state()
    sess.close()
    with pytest.raises(RuntimeError):
        sess.load_state(blob)
