"""Encrypted, tamper-evident audit log for every model and KV operation.

Every consequential action — a model call, a KV persist/restore, a
capability that was gated off — writes one row here. The log is the
compliance surface: it answers "what did this process do, when, and
what was the outcome" without the caller having to remember to log.

Design
------
- **Encrypted at rest** via SQLCipher (``sqlcipher3``). The key comes
  from ``key_manager`` (OS keychain) or is injected explicitly for
  tests. Without a native SQLCipher build the constructor *fails*
  rather than silently writing plaintext — see ``allow_unencrypted``.
- **One row per operation**, written by the ``@audited`` decorator so
  call sites don't hand-roll logging (and can't forget to).
- **Append-only and tamper-evident.** There is no update/delete API,
  and each row commits to its predecessor by hash (see below), so the
  absence of mutation is enforced cryptographically rather than merely
  by the shape of this class.

Tamper-evidence: the hash chain
-------------------------------
Encryption gives confidentiality, not integrity: anyone holding the key
can open the database and rewrite rows. To make modification *evident*,
each row carries::

    prev_hash  — the row_hash of the row before it (GENESIS for the first)
    row_hash   — SHA-256 over (prev_hash || canonical(row fields))

Altering, deleting, or reordering any row breaks the chain from that
point on, and ``verify()`` reports the first broken row.

A chain alone does not stop *wholesale replacement*: an attacker with
the key can drop the table and build a fresh, internally-consistent
chain. So the current head hash is also stored outside the database, in
the OS keychain (``key_manager.store_head_anchor``). ``verify()``
compares the chain's head against that anchor.

**The honest boundary.** This makes tampering require compromising two
separate stores (the database file *and* the keychain) instead of one.
It does not make the log unforgeable: an attacker who holds the
encryption key and can write to the keychain can rewrite both. Real
unforgeability requires committing the head somewhere outside the
host's trust boundary — a remote append-only log, a notary, a
transparency log. Palimpsests does not do that, and does not claim it.

The anchor is refreshed every ``anchor_every`` rows (default 1: every
write). Raising it trades a window — the last few events before a crash
would be unanchored, though still chained — for fewer keychain calls,
which are not free on macOS and Windows.

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
import hashlib
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from palimpsests.audit.key_manager import load_head_anchor, store_head_anchor
from pathlib import Path
from typing import TypeVar

#: The chain's fixed starting point. The first row's ``prev_hash``.
#: A constant (not a random nonce) so a fresh log is reproducible and a
#: truncated-to-empty log is distinguishable from one that never existed.
GENESIS = "0" * 64


class AuditDenied(Exception):
    """Raised when a gated capability is disabled.

    Carries a human-readable reason. The audit decorator records it as
    ``outcome="denied"`` and re-raises so the caller can surface a
    structured refusal.
    """


class AuditIntegrityError(Exception):
    """Raised when the log cannot be opened in a trustworthy state.

    Distinct from a verification *result*: this signals that the store
    itself is unusable (wrong key, unencrypted when encryption was
    required), not that history was found to be altered.
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


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of a chain verification.

    ``ok`` is the headline, but the two flags below matter for an
    auditor: they state *which* guarantees were actually checked, so a
    passing result is never read as stronger than it is.
    """

    ok: bool
    rows_checked: int
    #: True if the stored head anchor was present AND matched the chain
    #: head. False means the anchor was unavailable (no keychain, or a
    #: never-anchored log) — the chain was still checked, but wholesale
    #: replacement would not have been detected.
    head_anchored: bool
    #: The id of the first row whose hash did not match, if any.
    first_bad_row: int | None = None
    reason: str | None = None


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
    error_message TEXT,
    prev_hash     TEXT    NOT NULL,
    row_hash      TEXT    NOT NULL
);
"""


def _canonical(*fields: str | None) -> bytes:
    """Serialize row fields deterministically for hashing.

    Length-prefixed rather than delimiter-joined, so no field value can
    forge a boundary (``"a|b"`` and ``["a", "b"]`` must not hash alike).
    ``None`` is encoded distinctly from the empty string, because
    ``engine_id=None`` and ``engine_id=""`` are different facts.
    """
    out = bytearray()
    for f in fields:
        if f is None:
            out.extend(b"\x00")  # null marker, no length, no payload
        else:
            raw = f.encode("utf-8")
            out.extend(b"\x01")
            out.extend(len(raw).to_bytes(8, "big"))
            out.extend(raw)
    return bytes(out)


def _row_hash(
    prev_hash: str,
    timestamp: str,
    operation: str,
    tool_name: str,
    outcome: str,
    engine_id: str | None,
    model_locality: str | None,
    data_class: str,
    error_message: str | None,
) -> str:
    """SHA-256 over the predecessor's hash and this row's canonical form."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(
        _canonical(
            timestamp,
            operation,
            tool_name,
            outcome,
            engine_id,
            model_locality,
            data_class,
            error_message,
        )
    )
    return h.hexdigest()


class AuditLog:
    """An encrypted, append-only, tamper-evident audit log.

    Thread-safe: a single connection guarded by a lock. The write rate
    (one row per operation) is far below any level where connection
    pooling would matter, so one serialized connection keeps the
    encryption context simple and correct.

    Parameters
    ----------
    db_path:
        Where the SQLCipher database lives.
    key:
        The 256-bit encryption key.
    allow_unencrypted:
        When ``sqlcipher3`` is not installed, refuse to open (the
        default) rather than silently writing plaintext. Tests and CI
        runners without a native SQLCipher build pass ``True``
        *explicitly*, which is the point: an unencrypted audit log is a
        deliberate choice, never an accident of packaging.
    anchor_every:
        Refresh the keychain head anchor every N rows. Default 1 (every
        write). Higher values reduce keychain traffic at the cost of a
        window in which the most recent rows are chained but not
        anchored.
    """

    def __init__(
        self,
        db_path: Path,
        key: bytes,
        *,
        allow_unencrypted: bool = False,
        anchor_every: int = 1,
    ) -> None:
        if anchor_every < 1:
            raise ValueError("anchor_every must be >= 1")
        self._path = Path(db_path)
        self._lock = threading.Lock()
        self._anchor_every = anchor_every
        self._since_anchor = 0
        self._conn = self._connect(key, allow_unencrypted=allow_unencrypted)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _connect(self, key: bytes, *, allow_unencrypted: bool) -> sqlite3.Connection:
        """Open an encrypted connection, or fail loudly.

        The PRAGMA key must be set before any other statement touches the
        database. Immediately afterwards we force a read: SQLCipher does
        not validate the key at PRAGMA time, so a wrong key would
        otherwise sail past the constructor and surface much later — or,
        worse, silently initialize a *new* encrypted database over what
        looked like an unreadable one.
        """
        try:
            import sqlcipher3
        except ImportError as e:
            if not allow_unencrypted:
                raise AuditIntegrityError(
                    "sqlcipher3 is not installed, so the audit log cannot be "
                    "encrypted at rest. Install the [encryption] extra, or pass "
                    "allow_unencrypted=True to accept a plaintext log explicitly."
                ) from e
            # Explicitly-permitted plaintext path (tests, CI). The key is
            # accepted and unused; the call signature stays stable.
            return sqlite3.connect(str(self._path), check_same_thread=False)

        conn = sqlcipher3.connect(  # type: ignore[attr-defined]
            str(self._path), check_same_thread=False
        )
        # Key must be applied as the very first operation. The hex form is
        # produced from `secrets.token_bytes`, so this is not an injection
        # surface; it is SQLCipher's documented raw-key syntax, which takes
        # no bind parameter.
        conn.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except Exception as e:
            conn.close()
            raise AuditIntegrityError(
                "audit database could not be read with the supplied key"
            ) from e
        return conn

    # ─── writing ──────────────────────────────────────────────────────

    def _head_hash_locked(self) -> str:
        """The row_hash of the newest row, or GENESIS if the log is empty."""
        row = self._conn.execute(
            "SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS

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
        """Append one event, extending the hash chain. Timestamped in UTC."""
        ts = datetime.now(UTC).isoformat()
        with self._lock:
            prev = self._head_hash_locked()
            rh = _row_hash(
                prev,
                ts,
                operation,
                tool_name,
                outcome,
                engine_id,
                model_locality,
                data_class,
                error_message,
            )
            self._conn.execute(
                "INSERT INTO audit_events "
                "(timestamp, operation, tool_name, outcome, engine_id, "
                " model_locality, data_class, error_message, prev_hash, row_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    operation,
                    tool_name,
                    outcome,
                    engine_id,
                    model_locality,
                    data_class,
                    error_message,
                    prev,
                    rh,
                ),
            )
            self._conn.commit()

            self._since_anchor += 1
            if self._since_anchor >= self._anchor_every:
                store_head_anchor(rh)
                self._since_anchor = 0

    # ─── reading ──────────────────────────────────────────────────────

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

    # ─── verification ─────────────────────────────────────────────────

    def verify(self) -> VerifyResult:
        """Recompute the chain and compare its head to the stored anchor.

        Walks every row oldest-first, recomputing ``row_hash`` from the
        stored fields and the previous row's hash. Any alteration,
        deletion, or reordering shows up as the first row whose recomputed
        hash does not match what is stored, or whose ``prev_hash`` does not
        equal its predecessor's ``row_hash``.

        The result's ``head_anchored`` flag says whether the wholesale-
        replacement check was actually performed: a chain that verifies
        with ``head_anchored=False`` is internally consistent but could
        have been rebuilt from scratch.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, timestamp, operation, tool_name, outcome, engine_id, "
                "model_locality, data_class, error_message, prev_hash, row_hash "
                "FROM audit_events ORDER BY id ASC"
            ).fetchall()

        expected_prev = GENESIS
        for r in rows:
            (
                row_id,
                ts,
                operation,
                tool_name,
                outcome,
                engine_id,
                model_locality,
                data_class,
                error_message,
                prev_hash,
                row_hash,
            ) = r

            if prev_hash != expected_prev:
                return VerifyResult(
                    ok=False,
                    rows_checked=len(rows),
                    head_anchored=False,
                    first_bad_row=row_id,
                    reason="prev_hash does not match the preceding row",
                )

            recomputed = _row_hash(
                prev_hash,
                ts,
                operation,
                tool_name,
                outcome,
                engine_id,
                model_locality,
                data_class,
                error_message,
            )
            if recomputed != row_hash:
                return VerifyResult(
                    ok=False,
                    rows_checked=len(rows),
                    head_anchored=False,
                    first_bad_row=row_id,
                    reason="row contents do not match their recorded hash",
                )
            expected_prev = row_hash

        # The chain is internally consistent. Now the harder question:
        # is it the *same* chain we last wrote, or a convincing replacement?
        anchor = load_head_anchor()
        if anchor is None:
            return VerifyResult(
                ok=True,
                rows_checked=len(rows),
                head_anchored=False,
                reason=(
                    "chain is consistent, but no head anchor was available; "
                    "wholesale replacement of the log would not be detected"
                ),
            )
        if anchor != expected_prev:
            return VerifyResult(
                ok=False,
                rows_checked=len(rows),
                head_anchored=True,
                reason=(
                    "chain is internally consistent but its head does not match "
                    "the stored anchor — the history appears to have been replaced"
                ),
            )
        return VerifyResult(ok=True, rows_checked=len(rows), head_anchored=True)

    def close(self) -> None:
        with self._lock:
            # Flush the anchor even if anchor_every > 1 left it stale, so a
            # clean shutdown never leaves unanchored rows behind.
            head = self._head_hash_locked()
            if head != GENESIS:
                store_head_anchor(head)
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
