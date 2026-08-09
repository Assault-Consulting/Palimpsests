# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The anchor boundary: where the trusted head comes from, and where it goes.

PALA-1 verification answers three questions; the third — *is this chain
complete?* — can only be answered against a head obtained from **outside**
the log (spec §7.2). This module is the one seam through which that head
enters and leaves. The verifier never learns where anchors live.

Two protocols, deliberately segregated:

- ``AnchorSource`` (read side) yields the head a chain is *supposed* to
  have. The reading-side facade (``AuditReader``) depends on this and
  nothing else about anchor storage.
- ``AnchorStore`` (write side) persists a head. The verifier must never
  be handed a writable store, so the two are kept apart even though a
  ``FileAnchor`` / ``FileAnchorStore`` pair shares one file.

Placement rule: only stdlib-backed sources live here (``ManualAnchor``,
``FileAnchor``, ``ChainedAnchorSource``). Sources that need a dependency
the core must not carry — an OS keychain, a Rekor or TSA client — live
with their consumer (the Auditor shell, or an optional extra). The seam
is what makes that placement invisible to the verifier.

Absent vs unreadable
--------------------
A source that has nothing returns ``None``; that is normal, not an error
(a fresh deployment, a witness not yet published). A source that *should*
have answered but could not — a corrupt file, a denied keychain — raises
``AnchorSourceError``. They are different UI states and different report
lines, and the return type keeps them apart end to end.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = [
    "AnchorReading",
    "AnchorSource",
    "AnchorSourceError",
    "AnchorAttempt",
    "ManualAnchor",
    "FileAnchor",
    "ChainedAnchorSource",
    "AnchorStore",
    "FileAnchorStore",
]

_HEAD_LEN = 32


@dataclass(frozen=True)
class AnchorReading:
    """A head obtained from outside the log, with its provenance.

    ``observed_at_ns`` is the reader's wall clock at the moment of reading:
    provenance for a UI, **not** a time proof — nothing here is chained or
    signed.
    """

    head: bytes  # exactly 32 bytes
    source_kind: str  # "manual" | "file" | "chained" | consumer kinds
    source_detail: str  # path / account / index — display only
    observed_at_ns: int | None

    def __post_init__(self) -> None:
        if len(self.head) != _HEAD_LEN:
            raise ValueError(
                f"anchor head must be {_HEAD_LEN} bytes, got {len(self.head)}"
            )


class AnchorSourceError(RuntimeError):
    """A source that should have answered could not.

    Carries ``source_kind`` and ``source_detail`` so a shell can render the
    failed link ("file /var/lib/pala/anchor.head — unparsable").
    """

    def __init__(self, message: str, *, source_kind: str, source_detail: str) -> None:
        super().__init__(message)
        self.source_kind = source_kind
        self.source_detail = source_detail


@runtime_checkable
class AnchorSource(Protocol):
    """The read side of the anchor boundary.

    ``current_head()`` returns the head this chain is supposed to have:

    - ``None`` — this source has nothing (absent is normal, not an error).
    - raises ``AnchorSourceError`` — present but unreadable.

    Concrete sources also expose ``source_kind`` / ``source_detail`` string
    attributes so a chain can record an absent attempt with its identity;
    consumers should follow the same convention.
    """

    source_kind: str
    source_detail: str

    def current_head(self) -> AnchorReading | None: ...


@dataclass(frozen=True)
class AnchorAttempt:
    """One link's outcome inside a ``ChainedAnchorSource`` resolution."""

    source_kind: str
    source_detail: str
    outcome: str  # "answered" | "absent" | "error"
    error: str | None


# --------------------------------------------------------------------------- #
# Core sources — stdlib only.
# --------------------------------------------------------------------------- #


class ManualAnchor:
    """A head supplied directly (e.g. the CLI ``--anchor`` value).

    Validates hex and length **at construction**, so a typo fails fast at
    the boundary that supplied it rather than deep inside a verification.
    """

    source_kind = "manual"

    def __init__(self, head_hex: str, *, detail: str = "") -> None:
        cleaned = head_hex.strip()
        try:
            head = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"manual anchor is not valid hex: {exc}") from exc
        if len(head) != _HEAD_LEN:
            raise ValueError(
                f"manual anchor must be {_HEAD_LEN} bytes ({_HEAD_LEN * 2} hex "
                f"chars), got {len(head)}"
            )
        self._head = head
        self.source_detail = detail

    def current_head(self) -> AnchorReading | None:
        return AnchorReading(
            head=self._head,
            source_kind=self.source_kind,
            source_detail=self.source_detail,
            observed_at_ns=time.time_ns(),
        )


class FileAnchor:
    """A head read from a file.

    Format (shared with ``FileAnchorStore`` so third parties interoperate):
    a single line holding the head as lowercase hex, any number of optional
    ``# comment`` lines, blank lines and a trailing newline tolerated.

    A missing file is *absent* (``None``). A file that exists but does not
    hold exactly one valid hex head is *unreadable* (``AnchorSourceError``)
    — a present-but-broken anchor is not silently treated as "no anchor".
    """

    source_kind = "file"

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self.source_detail = str(self._path)

    def current_head(self) -> AnchorReading | None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AnchorSourceError(
                f"anchor file could not be read: {exc}",
                source_kind=self.source_kind,
                source_detail=self.source_detail,
            ) from exc

        candidates = [
            line.strip()
            for line in raw.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(candidates) != 1:
            raise AnchorSourceError(
                f"anchor file must hold exactly one hex head, found "
                f"{len(candidates)} content line(s)",
                source_kind=self.source_kind,
                source_detail=self.source_detail,
            )
        try:
            head = bytes.fromhex(candidates[0])
        except ValueError as exc:
            raise AnchorSourceError(
                f"anchor file head is not valid hex: {exc}",
                source_kind=self.source_kind,
                source_detail=self.source_detail,
            ) from exc
        if len(head) != _HEAD_LEN:
            raise AnchorSourceError(
                f"anchor file head must be {_HEAD_LEN} bytes, got {len(head)}",
                source_kind=self.source_kind,
                source_detail=self.source_detail,
            )
        return AnchorReading(
            head=head,
            source_kind=self.source_kind,
            source_detail=self.source_detail,
            observed_at_ns=time.time_ns(),
        )


class ChainedAnchorSource:
    """Try sources in order; the first that answers wins.

    Availability beats strictness at this layer: a link that **raises** is
    recorded and the chain continues; a link that returns ``None`` is
    recorded absent and the chain continues. Only an actual reading stops
    the walk. After ``current_head()``, ``last_attempts`` holds the full
    trace — this *is* the Auditor's anchor-flow UI ("manual → file →
    keychain", the answering link highlighted, the broken link marked),
    with no side channel.
    """

    source_kind = "chained"

    def __init__(self, sources: Iterable[AnchorSource]) -> None:
        self._sources = list(sources)
        self.source_detail = " → ".join(
            getattr(s, "source_kind", "unknown") for s in self._sources
        )
        self.last_attempts: list[AnchorAttempt] = []

    def current_head(self) -> AnchorReading | None:
        attempts: list[AnchorAttempt] = []
        answer: AnchorReading | None = None
        for src in self._sources:
            kind = getattr(src, "source_kind", "unknown")
            detail = getattr(src, "source_detail", "")
            try:
                reading = src.current_head()
            except AnchorSourceError as exc:
                attempts.append(
                    AnchorAttempt(
                        source_kind=getattr(exc, "source_kind", kind),
                        source_detail=getattr(exc, "source_detail", detail),
                        outcome="error",
                        error=str(exc),
                    )
                )
                continue
            if reading is None:
                attempts.append(
                    AnchorAttempt(
                        source_kind=kind,
                        source_detail=detail,
                        outcome="absent",
                        error=None,
                    )
                )
                continue
            attempts.append(
                AnchorAttempt(
                    source_kind=reading.source_kind,
                    source_detail=reading.source_detail,
                    outcome="answered",
                    error=None,
                )
            )
            answer = reading
            break
        self.last_attempts = attempts
        return answer


# --------------------------------------------------------------------------- #
# Write side — segregated from AnchorSource on purpose.
# --------------------------------------------------------------------------- #


class AnchorStore(Protocol):
    """The write side of the anchor boundary.

    Kept apart from ``AnchorSource`` so the verifier is never handed a
    writable store.
    """

    def store_head(
        self, head: bytes, *, meta: Mapping[str, str] | None = None
    ) -> None: ...


class FileAnchorStore:
    """Persist a head in the ``FileAnchor`` format, atomically.

    A torn anchor file is worse than a stale one — §7.2's "store's current
    head" must never be half a hex string — so the write goes to a temp
    file, is fsync'd, and is then ``os.replace``d into place.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    def store_head(
        self, head: bytes, *, meta: Mapping[str, str] | None = None
    ) -> None:
        if len(head) != _HEAD_LEN:
            raise ValueError(
                f"anchor head must be {_HEAD_LEN} bytes, got {len(head)}"
            )
        lines = []
        if meta:
            lines.extend(f"# {key}: {value}" for key, value in meta.items())
        lines.append(head.hex())
        payload = ("\n".join(lines) + "\n").encode("utf-8")

        tmp = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)
