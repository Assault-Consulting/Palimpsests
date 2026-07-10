"""Encryption key management for the audit log.

The audit log is encrypted at rest. This module owns the single
responsibility of producing and storing the symmetric key used for
that encryption, and — since v0.5 — the *head anchor* that makes the
log's hash chain resistant to wholesale rewriting.

Key lifecycle
-------------
- On first run, a fresh 256-bit key is generated and stored in the OS
  keychain (Keychain on macOS, Credential Manager on Windows, Secret
  Service on Linux) via ``keyring``.
- On subsequent runs, the key is read back from the keychain.
- Tests generate an ephemeral key per test and never touch the real
  keychain (see the test fixtures).

Why the OS keychain and not a file
----------------------------------
A key sitting in a dotfile next to the database is only as protected
as the filesystem permissions — which is to say, not much against a
process running as the same user. The OS keychain is the platform's
purpose-built secret store; delegating to it means we inherit the
platform's protections (biometric unlock, per-app ACLs) instead of
reinventing them badly.

The head anchor
---------------
The audit log is a hash chain: each row commits to the previous one,
so altering, deleting, or reordering any row breaks the chain and is
detected by ``AuditLog.verify()``. A chain alone, however, does not
detect *wholesale replacement*: an attacker holding the encryption key
can drop the table and build a fresh, internally-consistent chain.

To detect that, the current head hash is stored **outside the
database**, in the same keychain that holds the encryption key. On
verification the stored anchor is compared against the chain's actual
head; a mismatch means the history was replaced.

**Honest boundary.** This raises the bar; it does not make the log
unforgeable. An attacker who holds the encryption key *and* can write
to the keychain can rewrite both the chain and its anchor. Detecting
that requires committing the head to a store outside the host's trust
boundary (an append-only remote log, a notary, a transparency log),
which Palimpsests does not do. What the anchor buys is that tampering
must now compromise two separate stores rather than one file.

Graceful degradation
--------------------
Headless Linux CI runners often have no Secret Service daemon. When
the keychain is unavailable, callers may pass an explicit key (tests
do exactly this), and the head anchor is simply not maintained — in
which case ``verify()`` reports ``head_anchored=False`` so the caller
knows which guarantee was and was not in force. The module never
silently falls back to an unencrypted or on-disk key — the caller must
be explicit.
"""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

KEY_BYTES = 32  # 256-bit key
SERVICE_NAME = "palimpsests-audit"
KEY_USERNAME = "audit-db-key"
ANCHOR_USERNAME = "audit-head-anchor"


def anchor_scope(db_path: Path) -> str:
    """Derive a stable per-database scope from the log's resolved path.

    The anchor must be **per database**, not per machine: two audit logs
    on one host (two applications embedding palimpsests, or a test log
    next to a production one) would otherwise overwrite each other's
    anchors, making an honest log verify as "replaced". Worse, the noise
    of false alarms is exactly where a real tampering event would hide.

    The scope is the first 16 hex chars of SHA-256 over the resolved
    POSIX path — stable across runs, distinct across paths, and short
    enough for keychain entry names on every platform.
    """
    resolved = Path(db_path).resolve().as_posix()
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]


def _anchor_username(scope: str) -> str:
    """Keychain entry name for a scope; legacy unscoped name if empty."""
    return f"{ANCHOR_USERNAME}-{scope}" if scope else ANCHOR_USERNAME


def generate_key() -> bytes:
    """Return a fresh cryptographically-strong 256-bit key."""
    return secrets.token_bytes(KEY_BYTES)


def load_or_create_key() -> bytes:
    """Read the audit key from the OS keychain, creating it on first use.

    Raises
    ------
    RuntimeError
        If the OS keychain backend is unavailable. The caller is
        expected to either provide an explicit key or surface the
        error — we never silently degrade to a weaker key source.
    """
    try:
        import keyring
    except ImportError as e:  # pragma: no cover - import guard
        raise RuntimeError(
            "keyring is required to manage the audit key; "
            "install it or pass an explicit key"
        ) from e

    try:
        stored = keyring.get_password(SERVICE_NAME, KEY_USERNAME)
    except Exception as e:  # keyring raises backend-specific errors
        raise RuntimeError(
            "OS keychain is unavailable; pass an explicit key instead"
        ) from e

    if stored is not None:
        # Stored as hex so the keychain holds printable text.
        return bytes.fromhex(stored)

    key = generate_key()
    keyring.set_password(SERVICE_NAME, KEY_USERNAME, key.hex())
    # Read back what actually won. Two processes racing through first-run
    # would otherwise each hold a *different* generated key, and whichever
    # lost the set_password race would encrypt its database with a key the
    # keychain no longer holds. Converging on the stored value makes the
    # race harmless: both callers end up with the same key.
    stored = keyring.get_password(SERVICE_NAME, KEY_USERNAME)
    return bytes.fromhex(stored) if stored is not None else key


# ─── head anchor (tamper-evidence beyond the chain) ──────────────────────


def store_head_anchor(head_hash: str, *, scope: str = "") -> bool:
    """Persist the chain's current head hash to the OS keychain.

    ``scope`` isolates the anchor per database (see ``anchor_scope``);
    the empty default keeps the legacy machine-global entry name for
    callers that predate scoping.

    Returns True if the anchor was stored, False if no keychain backend
    is available. A False return is not an error: it means the anchor
    guarantee is not in force, which ``verify()`` reports honestly
    rather than papering over — but callers should surface it (the
    AuditLog counts these and warns once).
    """
    try:
        import keyring
    except ImportError:
        return False

    try:
        keyring.set_password(SERVICE_NAME, _anchor_username(scope), head_hash)
    except Exception:  # backend-specific failures (no Secret Service, etc.)
        return False
    return True


def load_head_anchor(*, scope: str = "") -> str | None:
    """Read the stored head hash, or None if absent/unavailable.

    None is returned both when no keychain exists and when no anchor has
    ever been written (a fresh log). Callers distinguish "never anchored"
    from "anchor mismatch" — only the latter is evidence of tampering.
    """
    try:
        import keyring
    except ImportError:
        return None

    try:
        return keyring.get_password(SERVICE_NAME, _anchor_username(scope))
    except Exception:
        return None


def clear_head_anchor(*, scope: str = "") -> None:
    """Remove the stored anchor for one scope. Used when starting a fresh log."""
    try:
        import keyring
    except ImportError:
        return

    try:
        keyring.delete_password(SERVICE_NAME, _anchor_username(scope))
    except Exception:
        # Nothing stored, or no backend — either way there is nothing
        # to clear and nothing to report.
        return
