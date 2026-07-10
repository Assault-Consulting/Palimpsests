"""Tests for the content-addressed KV store (N6b).

Two layers of proof. First, the store in isolation: identical token
sequences map to one key and reuse the same blob, different sequences
miss, order matters, and reuse is counted. Second, the store over the
real N6 primitive: a session's save_state blob, put under its tokens, is
fetched by a second session with the same tokens and load_state'd — and
that session then resumes without re-prefilling the restored context.

The blob is framed (see ``session.py``): magic, version, n_past, payload
length, payload. The store treats it as opaque bytes; only the position
read below reaches into the frame, and it does so through the same offset
the module documents.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.kvstore import (
    InMemoryKVStore,
    KVStore,
    content_key,
)
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession


def _n_past_of(blob: bytes) -> int:
    """Read the position out of a framed state blob (magic 6 + version 2)."""
    return int.from_bytes(blob[8:12], "big")


class StateFakeBackend:
    """NativeBackend with a per-sequence state store and decode log.

    ``state_get`` returns a blob unique to the sequence's decode count so
    distinct histories serialize distinctly; ``decodes`` logs every
    entry's ``(seq_id, start_pos, length)`` so a test can prove a restored
    session resumes at the saved position.
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


# ─── content_key: deterministic, order- and length-sensitive ──────────────


def test_content_key_is_deterministic():
    assert content_key([1, 2, 3]) == content_key([1, 2, 3])


def test_content_key_depends_on_order():
    assert content_key([1, 2, 3]) != content_key([3, 2, 1])


def test_content_key_depends_on_length():
    assert content_key([1, 2, 3]) != content_key([1, 2, 3, 4])


def test_content_key_handles_large_token_ids():
    # ids beyond one byte must not collide by truncation
    assert content_key([256]) != content_key([0])
    assert content_key([1000, 2000]) != content_key([2000, 1000])


# ─── the store in isolation ───────────────────────────────────────────────


def test_put_then_get_returns_the_blob():
    store = InMemoryKVStore()
    store.put([10, 11, 12], b"payload")
    assert store.get([10, 11, 12]) == b"payload"


def test_get_missing_returns_none():
    store = InMemoryKVStore()
    assert store.get([9, 9, 9]) is None


def test_identical_tokens_reuse_one_entry():
    store = InMemoryKVStore()
    store.put([1, 2, 3], b"first")
    # a second, identical token sequence addresses the same slot
    store.put([1, 2, 3], b"second")
    assert store.get([1, 2, 3]) == b"second"  # last-write-wins
    assert len(store) == 1


def test_different_tokens_are_separate_entries():
    store = InMemoryKVStore()
    store.put([1, 2, 3], b"a")
    store.put([4, 5, 6], b"b")
    assert store.get([1, 2, 3]) == b"a"
    assert store.get([4, 5, 6]) == b"b"
    assert len(store) == 2


def test_contains_does_not_count_a_hit():
    store = InMemoryKVStore()
    store.put([7, 8], b"x")
    assert store.contains([7, 8]) is True
    assert store.hits_for([7, 8]) == 0


def test_get_counts_hits():
    store = InMemoryKVStore()
    store.put([7, 8], b"x")
    store.get([7, 8])
    store.get([7, 8])
    assert store.hits_for([7, 8]) == 2


def test_clear_empties_the_store():
    store = InMemoryKVStore()
    store.put([1], b"a")
    store.clear()
    assert len(store) == 0
    assert store.get([1]) is None


def test_in_memory_store_satisfies_protocol():
    assert isinstance(InMemoryKVStore(), KVStore)


# ─── the store over the real N6 primitive (the point of N6b) ──────────────


def test_saved_state_is_reusable_by_content():
    """A blob saved by one session is fetched by content and restores
    another session to the saved position — no re-prefill."""
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    store = InMemoryKVStore()

    # Session A warms a context and we cache its state under its tokens.
    warm = _session(backend)
    warm_tokens = backend.tokenize("a shared context prefix")
    list(warm.send("a shared context prefix"))
    saved = warm.save_state()
    saved_n_past = _n_past_of(saved)
    store.put(warm_tokens, saved)

    # Session B, about to use the same context, finds it in the store.
    blob = store.get(warm_tokens)
    assert blob is not None

    restored = _session(backend)
    restored.load_state(blob)
    mark = len(backend.decodes)
    list(restored.send("q"))
    # B resumes at the saved position — the cached KV was reused, not rebuilt
    assert backend.decodes[mark][1] == saved_n_past


def test_stored_blob_round_trips_unchanged():
    """The store must not touch the frame it holds.

    A content-addressed cache that silently rewrote its payload would
    hand load_state a blob whose header no longer matched its bytes.
    """
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    store = InMemoryKVStore()
    sess = _session(backend)
    list(sess.send("x"))
    saved = sess.save_state()

    store.put([1, 2, 3], saved)
    assert store.get([1, 2, 3]) == saved


def test_cache_miss_leaves_store_untouched():
    backend = StateFakeBackend(eos=0, script={0: [5, 0]})
    store = InMemoryKVStore()
    tokens = backend.tokenize("never cached")
    assert store.get(tokens) is None
    assert len(store) == 0
