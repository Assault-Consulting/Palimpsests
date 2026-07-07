"""Content-addressed KV store — reuse saved states by their content (N6b).

N6 gave a session ``save_state`` / ``load_state``: a self-contained blob
(``n_past`` header + backend KV bytes) that freezes and thaws one
session's context. That is addressed by *identity* — you hold a blob and
give it back to the same logical session.

N6b adds the layer above: address a saved state by the **content that
produced it**. The key is a hash of the *tokens* fed to reach that state,
not of the resulting bytes — so two runs over the same prefix map to the
same key even if their serialized KV differs. This is the "LMCache for
edge" idea: a warm KV becomes reusable knowledge keyed by what it
represents, not by where it happens to be stored.

**Why hash the tokens, not the blob.** The blob is the *output* (KV
bytes); it can vary run to run and reveals nothing about what to reuse
for. The tokens are the *input* — the thing a future caller actually has
in hand ("I'm about to prefill these tokens; is that already cached?").
Keying on the input is what makes the store answer that question. This
mirrors llama.cpp's ``--slot-save-path``, which addresses by an opaque
path the caller must track; content-addressing removes that bookkeeping —
the tokens *are* the address.

**Deliberately thin and backend-agnostic.** ``KVStore`` neither produces
nor consumes KV; it moves opaque ``bytes`` keyed by tokens. The engine or
a session decides *which* tokens are the key (a shared prefix, a whole
conversation) and calls ``save_state`` / ``load_state`` around it. That
keeps the store a pure policy object over the N6 primitive — the same
Variant-B split used for prefix holders: mechanism below, policy here,
and the store itself unaware of both.

Only an in-memory store ships here. A disk-backed store (survive process
exit) is a strict subclass of the same interface and a later step; the
content-addressing itself is what N6b proves.
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Width in bytes each token is packed into before hashing. Tokens are
# vocabulary ids, which can exceed one byte, so a fixed 4-byte big-endian
# packing gives a stable, collision-free key across platforms.
_TOKEN_WIDTH = 4


def content_key(tokens: Sequence[int]) -> str:
    """Return the content-address of a token sequence.

    A SHA-256 over the tokens packed big-endian at a fixed width, returned
    as a hex digest. Deterministic and order-sensitive: the same tokens in
    the same order always map to the same key, and any difference (a
    different token, a different order, a different length) maps elsewhere.
    """
    h = hashlib.sha256()
    for token in tokens:
        h.update(int(token).to_bytes(_TOKEN_WIDTH, "big"))
    return h.hexdigest()


@runtime_checkable
class KVStore(Protocol):
    """A content-addressed store of saved KV blobs.

    Implementations map a token sequence to an opaque ``bytes`` blob (the
    output of a session's ``save_state``). They never interpret the blob;
    they only move it. This Protocol lets an in-memory store and a future
    disk-backed store be used interchangeably.
    """

    def put(self, tokens: Sequence[int], blob: bytes) -> str:
        """Store ``blob`` under the content-key of ``tokens``; return the key."""
        ...

    def get(self, tokens: Sequence[int]) -> bytes | None:
        """Return the blob stored for ``tokens``, or ``None`` if absent."""
        ...

    def contains(self, tokens: Sequence[int]) -> bool:
        """Whether a blob is stored for ``tokens``."""
        ...


@dataclass
class _Entry:
    """A stored blob and how often it has been reused.

    ``hits`` counts successful ``get`` calls — useful for diagnostics and
    a future eviction policy (least-reused first). It is not part of the
    stored content and never affects the key.
    """

    blob: bytes
    hits: int = 0


@dataclass
class InMemoryKVStore:
    """A content-addressed KV store held in memory.

    Keys are the content-address of the tokens (``content_key``); values
    are the opaque blobs. Last-write-wins on a repeated key. Nothing here
    survives process exit — a disk-backed store is a later step with the
    same interface.

    ``_entries`` is keyed by the hex content-key, so lookups are O(1) and
    independent of token-sequence length once hashed.
    """

    _entries: dict[str, _Entry] = field(default_factory=dict)

    def put(self, tokens: Sequence[int], blob: bytes) -> str:
        """Store ``blob`` under the content-key of ``tokens``.

        Returns the content-key so a caller can log or correlate it.
        Overwrites any blob previously stored under the same key
        (last-write-wins); the hit count resets, since the content changed.
        """
        key = content_key(tokens)
        self._entries[key] = _Entry(blob=blob)
        return key

    def get(self, tokens: Sequence[int]) -> bytes | None:
        """Return the blob stored for ``tokens``, or ``None`` if absent.

        A hit increments the entry's reuse counter. A miss leaves the
        store untouched and returns ``None`` — the caller then prefills
        normally and may ``put`` the resulting state for next time.
        """
        entry = self._entries.get(content_key(tokens))
        if entry is None:
            return None
        entry.hits += 1
        return entry.blob

    def contains(self, tokens: Sequence[int]) -> bool:
        """Whether a blob is stored for ``tokens`` (without counting a hit)."""
        return content_key(tokens) in self._entries

    def hits_for(self, tokens: Sequence[int]) -> int:
        """How many times the blob for ``tokens`` has been reused.

        Zero if never reused or absent. Exposed for diagnostics and to let
        a future eviction policy rank entries by reuse.
        """
        entry = self._entries.get(content_key(tokens))
        return entry.hits if entry is not None else 0

    def clear(self) -> None:
        """Drop every stored blob."""
        self._entries.clear()

    def __len__(self) -> int:
        """How many distinct content-keys are stored."""
        return len(self._entries)
