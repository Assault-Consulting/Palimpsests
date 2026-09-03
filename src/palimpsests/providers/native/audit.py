# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The wiring seam between the native engine and the PALA-1 writer."""
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
    SOURCE_PARSED_FROM_WIRE,
    ZERO16,
    PalaWriter,
)

_DIGEST_CHUNK = 1 << 20


def file_digest(path: str | os.PathLike[str]) -> bytes:
    h = sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_DIGEST_CHUNK):
            h.update(chunk)
    return h.digest()


def injected_backend_digest(backend: object) -> bytes:
    cls = type(backend)
    ident = f"palimpsests:injected-backend:{cls.__module__}.{cls.__qualname__}"
    return sha256(ident.encode("utf-8")).digest()


class NativeAudit:
    """Engine-facing emit surface over a :class:`PalaWriter`."""

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
        self._trigger_lock = threading.Lock()
        self._clock = clock
        self._guard_threshold = guard_escalation_threshold
        self._guard_window_ns = guard_escalation_window_ns
        self._guards: deque[tuple[int, int, bytes]] = deque()
        self._anchor_threshold = anchor_failure_threshold
        self._anchor_failures = 0
        if writer.seq == 0:
            writer.genesis()
        writer.boot()
        if writer.recovered_tail_bytes:
            writer.recovery_truncated_tail()

    @property
    def writer(self) -> PalaWriter:
        return self._writer

    def model_loaded(self, model_digest: bytes, config_digest: bytes, *, detail: str) -> None:
        self._writer.model_load(model_digest, config_digest, detail=detail)

    def model_unloaded(self) -> None:
        self._writer.model_unload()

    def session_opened(self) -> bytes:
        sid = f"{self._writer.boot_id.hex()}:{next(self._session_ids)}"
        return self._writer.session_start(sid)

    def session_closed(self, span_id: bytes) -> None:
        self._writer.session_end(span_id)

    def kv_saved(self, blob: bytes, span_id: bytes | None) -> None:
        self._writer.kv_save(sha256(blob).digest(), span_id=span_id or b"\x00" * 16)

    def kv_restored(self, blob: bytes, span_id: bytes | None) -> None:
        self._writer.kv_restore(sha256(blob).digest(), span_id=span_id or b"\x00" * 16)

    def state_rejected(self, reason: str, span_id: bytes | None) -> None:
        rh = self._writer.guard_state_reject(detail=reason, span_id=span_id or b"\x00" * 16)
        self._note_guard(rh)

    def prefix_warmed(self, token_count: int) -> None:
        self._writer.prefix_warm(token_count=token_count)

    def prefix_copied(self, token_count: int, span_id: bytes) -> None:
        self._writer.prefix_copy(token_count, span_id=span_id)

    def tool_called(
        self,
        name: str,
        args_digest: bytes | None,
        span_id: bytes | None,
        *,
        source: int = SOURCE_PARSED_FROM_WIRE,
    ) -> tuple[int, bytes]:
        """Record a dispatched tool invocation; return its (seq, hash)."""
        rh = self._writer.tool_call(
            name, args_digest=args_digest, span_id=span_id or ZERO16, source=source,
        )
        return self._writer.seq - 1, rh

    def tools_offered_no_call(
        self, count: int, tools_digest: bytes, span_id: bytes | None
    ) -> None:
        self._writer.tools_offered_no_call(count, tools_digest, span_id=span_id or ZERO16)

    def tool_result(
        self,
        call_seq: int,
        call_hash: bytes,
        outcome: int,
        result_digest: bytes | None,
        span_id: bytes | None,
        *,
        source: int = SOURCE_PARSED_FROM_WIRE,
    ) -> bytes:
        """Record the invocation's completion; returns the result record's hash."""
        return self._writer.tool_result(
            call_seq, call_hash, outcome,
            result_digest=result_digest, span_id=span_id or ZERO16, source=source,
        )

    def tool_loop_limited(
        self,
        iterations: int,
        call_seq: int | None,
        call_hash: bytes | None,
        span_id: bytes | None,
    ) -> None:
        rh = self._writer.guard_tool_loop_limit(
            iterations, call_seq=call_seq, call_hash=call_hash, span_id=span_id or ZERO16,
        )
        self._note_guard(rh)

    def prefix_release_refused(self, holder_seq: int, consumer_count: int) -> None:
        rh = self._writer.guard_prefix_release(holder_seq, consumer_count)
        self._note_guard(rh)

    def _note_guard(self, guard_hash: bytes) -> None:
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
            window_s = self._guard_window_ns // 1_000_000_000
            self._writer.incident_candidate(
                CAT_GUARD_ESCALATION, 2, recoverable=True,
                ref_seq=emit_ref[0], ref_hash=emit_ref[1],
                detail=f"{count} guard refusal(s) within {window_s}s window",
            )

    def self_check(self) -> VerifyResult:
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
                CAT_SELF_CHECK_FAILED, 3, recoverable=False,
                detail=f"self-verification failed over {res.count} record(s): {first}",
            )
        return res

    def anchor_store_failed(self, error: str) -> None:
        with self._trigger_lock:
            self._anchor_failures += 1
            emit = self._anchor_failures == self._anchor_threshold
            count = self._anchor_failures
        if emit:
            self._writer.incident_candidate(
                CAT_ANCHOR_ANOMALY, 2, recoverable=True,
                detail=f"{count} consecutive anchor-store failure(s); last: {error}",
            )

    def anchor_stored(self) -> None:
        with self._trigger_lock:
            self._anchor_failures = 0

    def anchor(self) -> bytes:
        return self._writer.anchor()
