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

Anchoring rules
---------------
The anchor is refreshed every ``anchor_every`` rows (default 1: every
write). Raising it trades a window — the last few events before a crash
would be unanchored, though still chained — for fewer keychain calls,
which are not free on macOS and Windows.

``close()`` flushes the anchor **only if this process actually wrote a
row**, and anchors the hash *it* wrote. Opening a log and closing it
must never move the anchor: otherwise a read-only operation (notably
``verify``) would silently re-anchor whatever chain happens to be on
disk — blessing a forged one and destroying the very evidence it was
asked to check.

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
import logging
import os
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from palimpsests.audit.key_manager import (
    anchor_scope,
    load_head_anchor,
    store_head_anchor,
)
from pathlib import Path
from typing import TypeVar

logger = logging.getLogger("palimpsests.audit")

#: Longest error text stored in a row. Exception messages are written by
#: other libraries and can embed request URLs (with tokens), file paths,
#: or fragments of the payload that raised — none of which belongs in a
#: log that promises "metadata only". Clipping does not sanitize, but it
#: bounds the exposure and keeps rows reviewable.
_ERROR_CLIP = 200


def _clip(text: str, limit: int = _ERROR_CLIP) -> str:
    """Truncate ``text`` to ``limit`` chars, marking the cut."""
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"

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

    ``ok`` is the headline, but the flags below matter for an auditor:
    they state *which* guarantees were actually checked, so a passing
    result is never read as stronger than it is.
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
    #: When the head does not match the anchor but the anchor IS one of
    #: the chain's row hashes: how many rows sit after the anchored head.
    #: This distinguishes an *unanchored tail* (a crash between commit
    #: and anchoring, or rows appended without keychain access) from a
    #: *replacement/rollback*, where the anchor appears nowhere in the
    #: chain. None when that distinction does not apply.
    anchor_lag: int | None = None


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
        # Anchors are scoped to this database's path, so two logs on one
        # machine never overwrite each other's anchor (which would make an
        # honest log verify as "replaced" — and bury a real alarm in noise).
        self._anchor_scope = anchor_scope(self._path)
        #: Failed anchor writes since open. Exposed so operators can see
        #: that rows were chained but not anchored (see anchor_failures).
        self._anchor_failures = 0
        self._anchor_warned = False
        # The hash of the last row *this process* appended. None means we
        # have written nothing, and therefore have nothing to anchor: see
        # close(). Read-only use must not move the anchor.
        self._last_written: str | None = None
        self._conn = self._connect(key, allow_unencrypted=allow_unencrypted)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        # Best-effort owner-only permissions. Matters most for the
        # explicitly-permitted plaintext path; harmless elsewhere. Windows
        # ACLs don't map onto POSIX bits — failure is not an error.
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

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
        """Append one event, extending the hash chain. Timestamped in UTC.

        ``error_message`` is clipped to ``_ERROR_CLIP`` chars *before*
        hashing, so the stored text and the chained text are the same
        bytes regardless of whether the caller went through the
        ``@audited`` decorator or called ``record`` directly.
        """
        if error_message is not None:
            error_message = _clip(error_message)
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
            self._last_written = rh

            self._since_anchor += 1
            if self._since_anchor >= self._anchor_every:
                if store_head_anchor(rh, scope=self._anchor_scope):
                    self._since_anchor = 0
                else:
                    # The row is chained but NOT anchored. Silence here
                    # would quietly drop the wholesale-replacement guarantee
                    # mid-run, so count it and warn once per process.
                    self._anchor_failures += 1
                    if not self._anchor_warned:
                        self._anchor_warned = True
                        logger.warning(
                            "audit head anchor could not be stored in the OS "
                            "keychain; rows are chained but unanchored until "
                            "an anchor write succeeds (failures so far: %d)",
                            self._anchor_failures,
                        )

    @property
    def anchor_failures(self) -> int:
        """Anchor writes that failed since this log was opened.

        Non-zero means some recent rows are chained but not anchored:
        the hash chain still detects in-place edits, but a wholesale
        replacement of those rows' tail would not be caught until a
        later anchor write succeeds.
        """
        return self._anchor_failures

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

        Read-only. Verifying never writes to the log or the anchor.
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
        anchor = load_head_anchor(scope=self._anchor_scope)
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
            # Same verdict (not trustworthy), two very different diagnoses.
            # If the anchor names a row inside this chain, the chain simply
            # extends past the anchored head: a crash between commit and
            # anchoring, a keychain outage (see anchor_failures), or rows
            # appended by a writer without keychain access. If the anchor
            # appears nowhere, this is not the history that was anchored:
            # a replacement or a rollback to an older snapshot.
            positions = {r[10]: i for i, r in enumerate(rows)}  # row_hash -> idx
            if anchor in positions:
                lag = len(rows) - positions[anchor] - 1
                return VerifyResult(
                    ok=False,
                    rows_checked=len(rows),
                    head_anchored=True,
                    anchor_lag=lag,
                    reason=(
                        f"chain extends {lag} row(s) beyond the stored anchor — "
                        "an unanchored tail (interrupted anchoring or appended "
                        "rows), not a wholesale replacement"
                    ),
                )
            return VerifyResult(
                ok=False,
                rows_checked=len(rows),
                head_anchored=True,
                reason=(
                    "chain is internally consistent but the stored anchor names "
                    "no row in it — the history appears to have been replaced "
                    "or rolled back to an older snapshot"
                ),
            )
        return VerifyResult(ok=True, rows_checked=len(rows), head_anchored=True)

    def close(self) -> None:
        """Close the connection, anchoring only what this process wrote.

        If no row was appended in this session, the anchor is left exactly
        as it was. That matters: a read-only consumer — ``verify`` above
        all — must not re-anchor whatever chain is on disk, or it would
        bless a forged history and destroy the evidence it was asked to
        examine.
        """
        with self._lock:
            if self._last_written is not None:
                store_head_anchor(self._last_written, scope=self._anchor_scope)
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
    with _singleton_lock:
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
                        error_message=_clip(str(e)),
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
                        error_message=_clip(f"{type(e).__name__}: {e}"),
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
