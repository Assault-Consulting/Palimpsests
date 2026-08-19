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
  at instance granularity. Resuming a chain across *processes* is the
  writer's :meth:`PalaWriter.open_existing`: the adapter then emits BOOT
  over the adopted head — and, when the resume truncated a torn tail,
  records the recovery immediately after it (profile §3, kind 7).
- **Digest, not content.** ``kv_saved`` / ``kv_restored`` take the blob
  and record its SHA-256 — the blob itself never reaches the chain
  (profile discipline: metadata only).
- **The engine does not own the writer.** The adapter never closes it;
  the caller who constructed the :class:`PalaWriter` does.
- **Hot path untouched.** Every method here maps to a lifecycle event
  (load, open, save, refuse) — nothing is called per token, and with no
  adapter installed the serving code pays one ``is None`` check per
  event site.
- **The pre-registered triggers live here (profile r2).** The adapter is
  where engine events become policy, so the three r2 incident triggers
  are its state, not the writer's: a sliding window over guard refusals
  (``GUARD_ESCALATION``), a consecutive-failure counter over anchor-store
  writes (``ANCHOR_ANOMALY``), and :meth:`self_check` — the library
  verifying its own chain and putting a failure *on that chain*
  (``SELF_CHECK_FAILED``). Thresholds are deployment-tunable constructor
  arguments; the semantics are the profile's. A candidate is an
  observation, never a determination, and the writer stays dumb.
"""
from __future__ import annotations

import itertools
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from hashlib import sha256
from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.verify import VerifyResult
from palimpsests.audit.pala_writer import (
    CAT_ANCHOR_ANOMALY,
    CAT_GUARD_ESCALATION,
    CAT_SELF_CHECK_FAILED,
    ZERO16,
    PalaWriter,
)

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

    def __init__(
        self,
        writer: PalaWriter,
        *,
        guard_escalation_threshold: int = 5,
        guard_escalation_window_ns: int = 60_000_000_000,
        anchor_failure_threshold: int = 3,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._writer = writer
        self._session_ids = itertools.count()
        # r2 trigger state (profile §4, kind 102). Guarded by its own lock:
        # each trigger is a check-then-act over shared counters, which the
        # writer's per-record lock cannot cover.
        self._trigger_lock = threading.Lock()
        self._clock = clock
        self._guard_threshold = guard_escalation_threshold
        self._guard_window_ns = guard_escalation_window_ns
        self._guards: deque[tuple[int, int, bytes]] = deque()  # (t, seq, hash)
        self._anchor_threshold = anchor_failure_threshold
        self._anchor_failures = 0
        if writer.seq == 0:
            writer.genesis()
        writer.boot()
        if writer.recovered_tail_bytes:
            # The resume truncated a torn trailing record (a crash mid-write);
            # the removal goes on the record right after the cross-boot link.
            writer.recovery_truncated_tail()

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
        rh = self._writer.guard_state_reject(
            detail=reason, span_id=span_id or b"\x00" * 16
        )
        self._note_guard(rh)

    # ─── shared prefixes ─────────────────────────────────────────────────

    def prefix_warmed(self, token_count: int) -> None:
        self._writer.prefix_warm(token_count=token_count)

    def prefix_copied(self, token_count: int, span_id: bytes) -> None:
        self._writer.prefix_copy(token_count, span_id=span_id)

    def tool_called(
        self, name: str, args_digest: bytes | None, span_id: bytes | None
    ) -> tuple[int, bytes]:
        """Record a dispatched tool invocation; return its (seq, hash).

        The pair is what a later ``tool_result`` binds to — the session
        keeps it per pending call and hands it back on completion.
        """
        rh = self._writer.tool_call(
            name, args_digest=args_digest, span_id=span_id or ZERO16
        )
        return self._writer.seq - 1, rh

    def tool_result(
        self,
        call_seq: int,
        call_hash: bytes,
        outcome: int,
        result_digest: bytes | None,
        span_id: bytes | None,
    ) -> None:
        """Record the invocation's completion, hash-bound to its call."""
        self._writer.tool_result(
            call_seq,
            call_hash,
            outcome,
            result_digest=result_digest,
            span_id=span_id or ZERO16,
        )

    def tool_loop_limited(
        self,
        iterations: int,
        call_seq: int | None,
        call_hash: bytes | None,
        span_id: bytes | None,
    ) -> None:
        """The loop cap refused further dispatches (SAFETY 104) — a guard.

        Feeds the same escalation window as every guard refusal: a burst
        of loop-limit hits becomes an ``INCIDENT_CANDIDATE`` (category 1)
        through the existing r2 trigger, not through anything new.
        """
        rh = self._writer.guard_tool_loop_limit(
            iterations, call_seq=call_seq, call_hash=call_hash,
            span_id=span_id or ZERO16,
        )
        self._note_guard(rh)

    def prefix_release_refused(self, holder_seq: int, consumer_count: int) -> None:
        """The scheduler refused to free a holder with live consumers."""
        rh = self._writer.guard_prefix_release(holder_seq, consumer_count)
        self._note_guard(rh)

    # ─── r2 triggers (profile §4, kind 102 — pre-registered) ─────────────

    def _note_guard(self, guard_hash: bytes) -> None:
        """Feed one guard refusal into the escalation window.

        When the window holds ``guard_escalation_threshold`` refusals, one
        ``INCIDENT_CANDIDATE`` (category ``GUARD_ESCALATION``) is emitted,
        referencing the latest refusal by seq+hash, and the window is
        cleared — "once per window" by construction: the next candidate
        needs a fresh threshold's worth of refusals.
        """
        guard_seq = self._writer.seq - 1
        now = self._clock()
        emit_ref: tuple[int, bytes] | None = None
        count = 0
        with self._trigger_lock:
            self._guards.append((now, guard_seq, guard_hash))
            horizon = now - self._guard_window_ns
            while self._guards and self._guards[0][0] < horizon:
                self._guards.popleft()
            if len(self._guards) >= self._guard_threshold:
                count = len(self._guards)
                _, ref_seq, ref_hash = self._guards[-1]
                emit_ref = (ref_seq, ref_hash)
                self._guards.clear()
        if emit_ref is not None:
            self._writer.incident_candidate(
                CAT_GUARD_ESCALATION,
                2,
                recoverable=True,
                ref_seq=emit_ref[0],
                ref_hash=emit_ref[1],
                detail=(
                    f"{count} guard refusal(s) within "
                    f"{self._guard_window_ns // 1_000_000_000}s window"
                ),
            )

    def self_check(self) -> VerifyResult:
        """Verify the writer's own chain; a failure goes on that chain.

        Header-only §7.1 verification of the container this adapter is
        writing — the library checking itself with the same code any
        auditor runs. A failing result emits an ``INCIDENT_CANDIDATE``
        (category ``SELF_CHECK_FAILED``, severity 3, not recoverable):
        the observation is recorded even though the chain it lands on is
        the one that just failed — the writer's in-memory head is intact,
        the append is sound, and a verifier will see both the damage and
        the machine noticing it. Reading a file the writer is appending
        to is safe at record granularity: writes are whole-record and
        unbuffered.
        """
        with open(self._writer.path, "rb") as fh:
            blob = fh.read()
        headers = [hb for hb, _ in iter_records(blob)]
        res = verify_headers(headers)
        if not res.chain_ok:
            first = (
                f"breaks={res.breaks[:3]} gaps={res.gaps[:3]} "
                f"violations={res.violations[:3]}"
            )
            self._writer.incident_candidate(
                CAT_SELF_CHECK_FAILED,
                3,
                recoverable=False,
                detail=f"self-verification failed over {res.count} record(s): {first}",
            )
        return res

    def anchor_store_failed(self, error: str) -> None:
        """Report that storing the anchored head out-of-band failed.

        The store write is the caller's operation (the adapter cannot see
        it), so failures are reported back here. Reaching
        ``anchor_failure_threshold`` *consecutive* failures emits one
        ``INCIDENT_CANDIDATE`` (category ``ANCHOR_ANOMALY``); the counter
        then keeps counting but does not re-emit until a success resets
        it — a dead store produces one candidate, not one per attempt.
        """
        with self._trigger_lock:
            self._anchor_failures += 1
            emit = self._anchor_failures == self._anchor_threshold
            count = self._anchor_failures
        if emit:
            self._writer.incident_candidate(
                CAT_ANCHOR_ANOMALY,
                2,
                recoverable=True,
                detail=(
                    f"{count} consecutive anchor-store failure(s); "
                    f"last: {error}"
                ),
            )

    def anchor_stored(self) -> None:
        """Report a successful out-of-band store write; resets the counter."""
        with self._trigger_lock:
            self._anchor_failures = 0

    # ─── anchoring ───────────────────────────────────────────────────────

    def anchor(self) -> bytes:
        """Anchor the chain tip; returns the head for the anchor store."""
        return self._writer.anchor()
