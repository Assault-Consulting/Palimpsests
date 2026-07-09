"""Audit subsystem — encrypted, append-only, tamper-evident operation log.

Public surface:

- ``AuditLog``       — the encrypted store.
- ``AuditEvent``     — one row read back.
- ``AuditDenied``    — raised by gating when a capability is disabled.
- ``AuditIntegrityError`` — the store cannot be opened in a trustworthy
  state (wrong key, or unencrypted when encryption was required).
- ``VerifyResult``   — the outcome of ``AuditLog.verify()``.
- ``audited``        — decorator that records an invocation.
- ``get_audit_log`` / ``set_audit_log`` — process-wide singleton access.
- ``generate_key`` / ``load_or_create_key`` — key management.
- ``store_head_anchor`` / ``load_head_anchor`` / ``clear_head_anchor`` —
  the out-of-database anchor that makes wholesale log replacement
  detectable.
"""
from __future__ import annotations

from .key_manager import (
    clear_head_anchor,
    generate_key,
    load_head_anchor,
    load_or_create_key,
    store_head_anchor,
)
from .log import (
    GENESIS,
    AuditDenied,
    AuditEvent,
    AuditIntegrityError,
    AuditLog,
    VerifyResult,
    audited,
    get_audit_log,
    set_audit_log,
)

__all__ = [
    "GENESIS",
    "AuditLog",
    "AuditEvent",
    "AuditDenied",
    "AuditIntegrityError",
    "VerifyResult",
    "audited",
    "get_audit_log",
    "set_audit_log",
    "generate_key",
    "load_or_create_key",
    "store_head_anchor",
    "load_head_anchor",
    "clear_head_anchor",
]
