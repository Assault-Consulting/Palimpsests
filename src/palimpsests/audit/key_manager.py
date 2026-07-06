"""Encryption key management for the audit log.

The audit log is encrypted at rest. This module owns the single
responsibility of producing and storing the symmetric key used for
that encryption.

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

Graceful degradation
--------------------
Headless Linux CI runners often have no Secret Service daemon. When
the keychain is unavailable, callers may pass an explicit key (tests
do exactly this). The module never silently falls back to an
unencrypted or on-disk key — the caller must be explicit.
"""
from __future__ import annotations

import secrets

KEY_BYTES = 32  # 256-bit key
SERVICE_NAME = "palimpsests-audit"
KEY_USERNAME = "audit-db-key"


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
    return key
