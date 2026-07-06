"""Audit subsystem — encrypted, append-only operation log.

Public surface:

- ``AuditLog``       — the encrypted store.
- ``AuditEvent``     — one row read back.
- ``AuditDenied``    — raised by gating when a capability is disabled.
- ``audited``        — decorator that records an invocation.
- ``get_audit_log`` / ``set_audit_log`` — process-wide singleton access.
- ``generate_key`` / ``load_or_create_key`` — key management.
"""
from __future__ import annotations

from .key_manager import generate_key, load_or_create_key
from .log import (
    AuditDenied,
    AuditEvent,
    AuditLog,
    audited,
    get_audit_log,
    set_audit_log,
)

__all__ = [
    "AuditLog",
    "AuditEvent",
    "AuditDenied",
    "audited",
    "get_audit_log",
    "set_audit_log",
    "generate_key",
    "load_or_create_key",
]
