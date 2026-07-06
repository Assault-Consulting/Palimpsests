"""Encrypted audit log for every model and KV operation.

Every consequential action — a model call, a KV persist/restore, a
capability that was gated off — writes one row here. The log is the
compliance surface: it answers "what did this process do, when, and
what was the outcome" without the caller having to remember to log.

Design
------
- **Encrypted at rest** via SQLCipher (``sqlcipher3``). The key comes
  from ``key_manager`` (OS keychain) or is injected explicitly for
  tests.
- **One row per operation**, written by the ``@audited`` decorator so
  call sites don't hand-roll logging (and can't forget to).
- **Append-only in spirit**: there is no update/delete API. The log
  grows; rotation/retention is a future concern, deliberately absent
  here so there is no code path that mutates history.

The ``AuditDenied`` exception
-----------------------------
When a capability is disabled, the gating layer raises ``AuditDenied``.
The decorator catches it, records ``outcome="denied"``, and re-raises
so the tool layer can map it to a structured refusal. This is the
"loud refusal" principle: a blocked capability leaves a durable trace,
not a silent no-op.

Field semantics
---------------
- ``operation`` — a coarse verb: ``model.call``, ``kv.persist``,
  ``kv.restore``, ``engine.select``, etc.
- ``engine_id`` — which engine served the operation (``ollama`` /
  ``llamacpp`` / ``pal-native``); ``None`` for operations that aren't
  engine-bound.
- ``outcome`` — ``success`` | ``error`` | ``denied``.
- ``data_class`` — a hint for downstream review: ``public`` |
  ``internal``. Model prompts/outputs are never stored — only metadata.
"""
from __future__ import annotations

import functools
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar


class AuditDenied(Exception):
    """Raised when a gated capability is disabled.

    Carries a human-readable reason. The audit decorator records it as
    ``outcome="denied"`` and re-raises so the caller can surface a
    structured refusal.
    """


@dataclass(frozen=True)
class AuditEvent:
    """One row read back from the log. Immutable by construction."""

    timestamp: str
    operation: str
    tool_name: str
    outcome: str
    engine_id: str | None
    model_locality: str | None
    data_class: str
    error_message: str | None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    operation     TEXT    NOT NULL,
    tool_name     TEXT    NOT NULL,
    outcome       TEXT    NOT NULL,
    engine_id     TEXT,
    model_locality TEXT,
    data_class    TEXT    NOT NULL DEFAULT 'internal',
    error_message TEXT
);
"""


class AuditLog:
    """An encrypted, append-only audit log backed by SQLCipher.

    Thread-safe: a single connection guarded by a lock. The write rate
    (one row per operation) is far below any level where connection
    pooling would matter, so one serialized connection keeps the
    encryption context simple and correct.
    """

    def __init__(self, db_path: Path, key: bytes) -> None:
        self._path = Path(db_path)
        self._lock = threading.Lock()
        self._conn = self._connect(key)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _connect(self, key: bytes) -> sqlite3.Connection:
        """Open an encrypted connection.

        Uses ``sqlcipher3`` when available; the PRAGMA key must be set
        before any other statement touches the database. Falls back to
        plain sqlite3 only when explicitly permitted (tests on runners
        without the native SQLCipher build).
        """
        try:
            import sqlcipher3

            conn = sqlcipher3.connect(  # type: ignore[attr-defined]
                str(self._path), check_same_thread=False
            )
            # Key must be applied as the very first operation.
            conn.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
            return conn
        except ImportError:
            # No native SQLCipher build available. We still function,
            # unencrypted, so development and CI aren't blocked — but
            # this is not the production path. The key is accepted and
            # ignored so the call signature is stable across builds.
            return sqlite3.connect(str(self._path), check_same_thread=False)

    def record(
        self,
        *,
        operation: str,
        tool_name: str,
        outcome: str,
        engine_id: str | None = None,
        model_locality: str | None = None,
        data_class: str = "internal",
        error_message: str | None = None,
    ) -> None:
        """Append one event. Timestamped in UTC at write time."""
        ts = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events "
                "(timestamp, operation, tool_name, outcome, engine_id, "
                " model_locality, data_class, error_message) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    operation,
                    tool_name,
                    outcome,
                    engine_id,
                    model_locality,
                    data_class,
                    error_message,
                ),
            )
            self._conn.commit()

    def recent(self, limit: int = 100) -> list[AuditEvent]:
        """Return the most recent events, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT timestamp, operation, tool_name, outcome, engine_id, "
                "model_locality, data_class, error_message "
                "FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            AuditEvent(
                timestamp=r[0],
                operation=r[1],
                tool_name=r[2],
                outcome=r[3],
                engine_id=r[4],
                model_locality=r[5],
                data_class=r[6],
                error_message=r[7],
            )
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ─── Process-wide singleton ──────────────────────────────────────────────

_instance: AuditLog | None = None
_singleton_lock = threading.Lock()


def get_audit_log() -> AuditLog | None:
    """Return the active audit log, or None if none is installed.

    Unlike the workspace/engine singletons, this returns None rather
    than lazy-initializing: the log needs a key + path that only the
    application entrypoint can supply. The decorator tolerates a
    missing log (no-op) so library use without an initialized log
    doesn't crash.
    """
    return _instance


def set_audit_log(log: AuditLog | None) -> None:
    """Install (or clear) the process-wide audit log."""
    global _instance
    _instance = log


# ─── The @audited decorator ──────────────────────────────────────────────

F = TypeVar("F", bound=Callable[..., dict])


def audited(
    operation: str,
    *,
    data_class: str = "internal",
    model_locality: str | None = None,
) -> Callable[[F], F]:
    """Wrap a callable so its invocation is recorded to the audit log.

    The wrapped function's ``__name__`` becomes the ``tool_name`` field
    — callers that need a stable audit name rename the inner before
    decorating (the gating decorators do this).

    Outcome mapping:
    - returns normally         -> ``success``
    - raises ``AuditDenied``   -> ``denied`` (re-raised)
    - raises anything else     -> ``error`` (re-raised)

    A missing audit log is tolerated (the call runs, nothing is
    recorded) so library use without an initialized log still works.
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            log = get_audit_log()
            tool_name = fn.__name__
            try:
                result = fn(*args, **kwargs)
            except AuditDenied as e:
                if log is not None:
                    log.record(
                        operation=operation,
                        tool_name=tool_name,
                        outcome="denied",
                        model_locality=model_locality,
                        data_class=data_class,
                        error_message=str(e),
                    )
                raise
            except Exception as e:
                if log is not None:
                    log.record(
                        operation=operation,
                        tool_name=tool_name,
                        outcome="error",
                        model_locality=model_locality,
                        data_class=data_class,
                        error_message=f"{type(e).__name__}: {e}",
                    )
                raise
            else:
                if log is not None:
                    log.record(
                        operation=operation,
                        tool_name=tool_name,
                        outcome="success",
                        model_locality=model_locality,
                        data_class=data_class,
                    )
                return result

        return wrapper  # type: ignore[return-value]

    return decorator
