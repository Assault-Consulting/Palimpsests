# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Live tailing of a growing PALA-1 container.

``TailingReader`` is the second surface over the one ``IncrementalVerifier``
(``AuditReader`` is the batch surface): a chain verified live and the same
chain verified after the fact produce identical answers, because the §7.1
rules run in exactly one place. ``snapshot()`` returns the batch
``Verification`` at any moment, so a UI can render the same three questions
in either mode.

The hard part live is telling apart the *reasons* a file's tail moves:

* a partial record at the live tail is ``pending_tail``, not truncation —
  the writer is mid-write, and the torn bytes never enter the verifier;
* a pending tail that stops growing for ``torn_grace`` becomes a
  ``truncated_tail`` diagnosis (a writer that crashed mid-write);
* the file shrinking *within* the pending region is ``shrunk`` — the merged
  writer's ``open_existing()`` truncates a torn tail on resume, so the
  reader waits for the BOOT + ``RECOVERY_TRUNCATED_TAIL`` that follow and
  emits ``recovered``; the verifier state was never invalidated because the
  torn bytes had never been stepped;
* the file shrinking **below the last verified record** is the one real
  alarm — a ``replaced_or_rolled_back`` diagnosis; no honest writer rewrites
  history.

No inotify/watchdog: ``os.stat`` polling, stdlib-only, and the interval is
the consumer's dial.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Iterator
from dataclasses import dataclass
from palimpsests.audit.anchors import AnchorSource
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    KNOWN_RECORD_TYPES,
    MAGIC,
    RT_ANCHOR,
    RT_EVENT,
)
from palimpsests.audit.pala.incremental import IncrementalVerifier
from palimpsests.audit.pala_writer import KIND_RECOVERY_TRUNCATED_TAIL
from palimpsests.audit.reader import (
    AuditReader,
    DecodedRecord,
    Verification,
    decode_record,
)
from pathlib import Path

__all__ = ["TailingReader", "TailEvent"]


@dataclass(frozen=True)
class TailEvent:
    """One thing that happened at the tail. ``kind`` is the discriminator."""

    kind: str  # record | pending_tail | shrunk | recovered | anchor_seen | diagnosis
    seq: int | None
    record: DecodedRecord | None
    detail: str


def _parse_one(buf: bytes, off: int) -> tuple[int, bytes, bytes] | None:
    """One complete record at ``off``, or None if incomplete/unparseable.

    Boundary logic mirrors ``iter_records`` but never raises: at the live
    tail an incomplete or not-yet-valid record is simply "not ready", which
    the caller treats as a pending tail rather than a defect.
    """
    n = len(buf)
    if off + FIXED_HEADER_LEN > n:
        return None
    if buf[off : off + 4] != MAGIC:
        return None
    (hlen,) = struct.unpack_from("<H", buf, off + 6)
    if hlen < FIXED_HEADER_LEN:
        return None
    (blen,) = struct.unpack_from("<I", buf, off + 120)
    end = off + hlen + blen
    if end > n:
        return None
    return end - off, buf[off : off + hlen], buf[off + hlen : end]


class TailingReader:
    """Follow a growing container, emitting one event stream over one verifier."""

    def __init__(
        self,
        path,
        *,
        anchor: AnchorSource | None = None,
        poll_interval: float = 0.5,
        torn_grace: float = 5.0,
    ) -> None:
        self._path = Path(path)
        self._anchor = anchor
        self._poll_interval = poll_interval
        self._torn_grace = torn_grace

        self._verifier = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
        self._verified = bytearray()  # complete records consumed, in order
        self._cursor = 0  # byte offset up to which records are verified
        self._count = 0
        self._last_size = 0
        self._pending_since: float | None = None
        self._awaiting_recovery = False
        self._diag_torn = False
        self._diag_replaced = False
        self._closed = False

    # ── time / io seams (overridable in tests) ──────────────────────────
    def _now(self) -> float:
        return time.monotonic()

    def _size(self) -> int:
        try:
            return self._path.stat().st_size
        except FileNotFoundError:
            return 0

    def _read(self, start: int, end: int) -> bytes:
        if end <= start:
            return b""
        with open(self._path, "rb") as fh:
            fh.seek(start)
            return fh.read(end - start)

    # ── the poll ────────────────────────────────────────────────────────
    def _drain(self) -> list[TailEvent]:
        """Assess the file once and return the events since the last drain."""
        ev: list[TailEvent] = []
        size = self._size()

        if size < self._cursor:
            # Verified history changed under us — the one real alarm.
            if not self._diag_replaced:
                self._diag_replaced = True
                ev.append(
                    TailEvent(
                        "diagnosis",
                        None,
                        None,
                        "replaced_or_rolled_back: the file shrank below the verified head",
                    )
                )
            self._last_size = size
            return ev

        if size < self._last_size:
            # Shrank within the pending (torn) region, above the verified
            # head: a resume most likely truncated a torn tail. Keep state;
            # await the BOOT + RECOVERY_TRUNCATED_TAIL that follow.
            self._awaiting_recovery = True
            self._pending_since = self._now()
            ev.append(
                TailEvent(
                    "shrunk",
                    None,
                    None,
                    "the pending tail shrank; awaiting BOOT + RECOVERY_TRUNCATED_TAIL",
                )
            )

        tail = self._read(self._cursor, size)
        off = 0
        while True:
            parsed = _parse_one(tail, off)
            if parsed is None:
                break
            total, hb, body = parsed
            self._verifier.step(hb)
            self._verified += tail[off : off + total]
            dr = decode_record(self._count, hb, body)
            self._count += 1
            self._cursor += total
            off += total

            ev.append(
                TailEvent("record", dr.seq, dr, dr.type_name or f"type 0x{dr.record_type:04x}")
            )
            if dr.record_type == RT_ANCHOR:
                ev.append(
                    TailEvent(
                        "anchor_seen",
                        dr.seq,
                        dr,
                        f"ANCHOR at seq {dr.seq}; chain head {self._verifier.head.hex()[:8]}…",
                    )
                )
            if (
                self._awaiting_recovery
                and dr.record_type == RT_EVENT
                and dr.kind == KIND_RECOVERY_TRUNCATED_TAIL
            ):
                self._awaiting_recovery = False
                ev.append(
                    TailEvent(
                        "recovered",
                        dr.seq,
                        dr,
                        "resume recorded RECOVERY_TRUNCATED_TAIL; verifier state intact",
                    )
                )

        pending = len(tail) - off
        if pending > 0:
            grew = size > self._last_size
            if grew or self._pending_since is None:
                self._pending_since = self._now()
                ev.append(
                    TailEvent(
                        "pending_tail",
                        None,
                        None,
                        f"{pending} pending byte(s) at the live tail (incomplete record)",
                    )
                )
            elif not self._diag_torn and (self._now() - self._pending_since) >= self._torn_grace:
                self._diag_torn = True
                ev.append(
                    TailEvent(
                        "diagnosis",
                        None,
                        None,
                        "truncated_tail: the pending tail stopped growing "
                        "(writer likely crashed mid-write)",
                    )
                )
        else:
            self._pending_since = None
            self._diag_torn = False

        self._last_size = size
        return ev

    # ── public surface ──────────────────────────────────────────────────
    def events(self) -> Iterator[TailEvent]:
        """Block, polling the file, yielding events until ``close()``."""
        while not self._closed:
            yield from self._drain()
            if self._closed:
                break
            time.sleep(self._poll_interval)

    def snapshot(self) -> Verification:
        """The batch ``Verification`` over the records verified so far.

        Identical to opening the verified prefix with ``AuditReader`` — the
        proof that live and batch agree is that this *is* the batch path.
        """
        reader = AuditReader.from_bytes(bytes(self._verified), anchor=self._anchor)
        return reader.verify()

    def close(self) -> None:
        self._closed = True
