# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Cross-process exclusive locks for the audit stores.

``threading.Lock`` protects a chain from the threads of one process. It
does nothing about a second *process*: two of them can each read the same
head, each compute a record linked to it, and each append — two records
with one ``prev_hash``, a fork that ``verify()`` then reports as a break.
No attack, no crash: just two writers. These locks close that.

A lock lives in a sidecar file beside the store (``<store>.lock``), never
on the store itself: SQLite runs its own locking protocol on its database
file, and the two must not interfere. The sidecar is left in place on
release — deleting a lock file while another process may be opening it
is its own race.

POSIX uses ``fcntl.flock``; Windows uses ``msvcrt.locking`` on the first
byte. Both are released by the OS if the holder dies, so a crashed
writer never leaves a chain locked.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

__all__ = ["ExclusiveLock", "LockHeld"]

#: Seconds between "still waiting" warnings during a blocking acquire.
WARN_EVERY = 30.0


class LockHeld(RuntimeError):
    """Another process holds the lock this one needs."""


def lock_path_for(store: str | os.PathLike[str]) -> Path:
    return Path(f"{os.fspath(store)}.lock")


class ExclusiveLock:
    """An exclusive, cross-process lock on ``<store>.lock``.

    ``acquire(blocking=False)`` raises :class:`LockHeld` at once if
    another process holds it. ``blocking=True`` waits — by default with
    no deadline, because the locks this guards are held for one append
    at a time and released by the OS if their holder dies: a write must
    not fail just because another process is slow. A long wait is not
    silent, though: every ``WARN_EVERY`` seconds it logs who holds the
    lock. Pass ``timeout`` for a bounded wait. Not re-entrant: a second
    acquire on the same instance is a programming error.
    """

    def __init__(self, store: str | os.PathLike[str]) -> None:
        self.path = lock_path_for(store)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self, *, blocking: bool = False, timeout: float | None = None) -> None:
        if self._fd is not None:
            raise RuntimeError("lock already held by this instance")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        start = time.monotonic()
        deadline = None if timeout is None else start + timeout
        next_warning = start + WARN_EVERY
        while True:
            try:
                _lock(fd)
                break
            except OSError as exc:
                now = time.monotonic()
                if not blocking or (deadline is not None and now >= deadline):
                    os.close(fd)
                    holder = _read_holder(self.path)
                    raise LockHeld(
                        f"{self.path} is held by another process"
                        + (f" (pid {holder})" if holder else "")
                    ) from exc
                if now >= next_warning:
                    holder = _read_holder(self.path)
                    logging.getLogger("palimpsests.audit").warning(
                        "still waiting for %s after %.0f s%s",
                        self.path,
                        now - start,
                        f" (held by pid {holder})" if holder else "",
                    )
                    next_warning = now + WARN_EVERY
                time.sleep(0.01)
        try:  # best-effort note of who holds it, for the error above
            # From byte 1: on Windows the lock covers byte 0, and another
            # process cannot read a locked range — the pid has to sit
            # outside it to be readable by the one being refused.
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"\n" + str(os.getpid()).encode())
        except OSError:
            pass
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> ExclusiveLock:
        self.acquire(blocking=True)
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def _read_holder(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            fh.seek(1)  # past byte 0, which a Windows lock makes unreadable
            text = fh.read(32).decode("ascii", errors="ignore").strip()
    except OSError:
        return None
    return text if text.isdigit() else None


if os.name == "nt":  # pragma: no cover — exercised on the Windows CI legs
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
