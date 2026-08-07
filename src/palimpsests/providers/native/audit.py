# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The wiring seam between the native engine and the PALA-1 writer.

:class:`NativeAudit` adapts the profile-typed :class:`PalaWriter` emit
methods to the engine's own vocabulary — "a session opened", "a blob was
saved", "a release was refused" — so the serving code never touches wire
concepts (spans, TLVs, record types). The dependency points one way:
``providers.native`` imports ``audit``; the writer and the codec know
nothing about engines.

Design points:

- **Chain lifecycle.** Constructing the adapter opens the chain: GENESIS
  if the writer has emitted nothing yet, then BOOT. A second adapter over
  the same live writer emits only BOOT — the cross-boot link (core §4.2)
  at instance granularity. Resuming a chain across *processes* needs
  reader-side head recovery and is out of scope here.
- **Digest, not content.** ``kv_saved`` / ``kv_restored`` take the blob
  and record its SHA-256 — the blob itself never reaches the chain
  (profile discipline: metadata only).
- **The engine does not own the writer.** The adapter never closes it;
  the caller who constructed the :class:`PalaWriter` does.
- **Hot path untouched.** Every method here maps to a lifecycle event
  (load, open, save, refuse) — nothing is called per token, and with no
  adapter installed the serving code pays one ``is None`` check per
  event site.
"""
from __future__ import annotations

import itertools
import os
from hashlib import sha256
from palimpsests.audit.pala_writer import PalaWriter

# Read model files in 1 MiB slices: bounded memory for multi-GB GGUFs.
_DIGEST_CHUNK = 1 << 20


def file_digest(path: str | os.PathLike[str]) -> bytes:
    """Streaming SHA-256 of a file — the model-artefact digest for
    ``ORIGIN_MODEL_DIGEST`` (profile: the GGUF file's digest at levels 2–3)."""
    h = sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_DIGEST_CHUNK):
            h.update(chunk)
    return h.digest()


def injected_backend_digest(backend: object) -> bytes:
    """A deterministic stand-in digest for a backend injected without a
    model artefact (tests, fakes). Derived from the backend's importable
    identity, and always paired with an ``injected:`` detail so a reader
    cannot mistake it for a file digest."""
    cls = type(backend)
    ident = f"palimpsests:injected-backend:{cls.__module__}.{cls.__qualname__}"
    return sha256(ident.encode("utf-8")).digest()


class NativeAudit:
    """Engine-facing emit surface over a :class:`PalaWriter`.

    Thread-safety follows the writer's: every method is a single writer
    call (the writer serializes records under its own lock), and the
    session counter is an :func:`itertools.count`, whose ``next`` is
    atomic on CPython.
    """

    def __init__(self, writer: PalaWriter) -> None:
        self._writer = writer
        self._session_ids = itertools.count()
        if writer.seq == 0:
            writer.genesis()
        writer.boot()

    @property
    def writer(self) -> PalaWriter:
        return self._writer

    # ─── origin ──────────────────────────────────────────────────────────

    def model_loaded(
        self, model_digest: bytes, config_digest: bytes, *, detail: str
    ) -> None:
        """The engine's active origin changed to this model+config."""
        self._writer.model_load(model_digest, config_digest, detail=detail)

    def model_unloaded(self) -> None:
        self._writer.model_unload()

    # ─── sessions ────────────────────────────────────────────────────────

    def session_opened(self) -> bytes:
        """Open a session span and return its ``span_id``.

        The session identifier is ``<boot_id>:<ordinal>`` — unique within
        the chain even though scheduler ``seq_id`` slots are recycled.
        """
        sid = f"{self._writer.boot_id.hex()}:{next(self._session_ids)}"
        return self._writer.session_start(sid)

    def session_closed(self, span_id: bytes) -> None:
        self._writer.session_end(span_id)

    # ─── KV persistence (the session's save/load boundary) ───────────────

    def kv_saved(self, blob: bytes, span_id: bytes | None) -> None:
        self._writer.kv_save(sha256(blob).digest(), span_id=span_id or b"\x00" * 16)

    def kv_restored(self, blob: bytes, span_id: bytes | None) -> None:
        self._writer.kv_restore(sha256(blob).digest(), span_id=span_id or b"\x00" * 16)

    def state_rejected(self, reason: str, span_id: bytes | None) -> None:
        """A persisted KV blob failed frame validation before the C parser."""
        self._writer.guard_state_reject(
            detail=reason, span_id=span_id or b"\x00" * 16
        )

    # ─── shared prefixes ─────────────────────────────────────────────────

    def prefix_warmed(self, token_count: int) -> None:
        self._writer.prefix_warm(token_count=token_count)

    def prefix_copied(self, token_count: int, span_id: bytes) -> None:
        self._writer.prefix_copy(token_count, span_id=span_id)

    def prefix_release_refused(self, holder_seq: int, consumer_count: int) -> None:
        """The scheduler refused to free a holder with live consumers."""
        self._writer.guard_prefix_release(holder_seq, consumer_count)

    # ─── anchoring ───────────────────────────────────────────────────────

    def anchor(self) -> bytes:
        """Anchor the chain tip; returns the head for the anchor store."""
        return self._writer.anchor()
