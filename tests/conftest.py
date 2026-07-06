"""Shared test fixtures.

Every global singleton gets a reset fixture so no test bleeds into
another. Autouse resets guarantee a clean slate even for tests that
don't request the setup fixture by name.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from palimpsests.audit import AuditLog, generate_key, set_audit_log
from palimpsests.registry import EngineRegistry, set_registry


@pytest.fixture
def audit_log(tmp_path: Path):
    """A fresh, isolated, per-test audit log with an ephemeral key.

    Never touches the real OS keychain or the user's real audit DB —
    each test gets its own key and its own tmp_path-backed database.
    Tests that assert on the log request this fixture by name.
    """
    key = generate_key()
    log = AuditLog(tmp_path / "audit.db", key)
    set_audit_log(log)
    try:
        yield log
    finally:
        log.close()
        set_audit_log(None)


@pytest.fixture(autouse=True)
def _reset_audit_log():
    """Drop the audit-log singleton between every test.

    Autouse complement to the explicit ``audit_log`` fixture: tests
    that don't request it still start with no log installed, and the
    singleton never leaks across tests.
    """
    yield
    set_audit_log(None)


@pytest.fixture
def registry(tmp_path: Path):
    """A fresh, isolated engine registry backed by tmp_path.

    The real registry config lives in the user's config dir; this must
    never be touched during tests. Yields the registry so tests can
    register engines and toggle the active choice.
    """
    reg = EngineRegistry(tmp_path / "registry.json")
    set_registry(reg)
    try:
        yield reg
    finally:
        set_registry(None)


@pytest.fixture(autouse=True)
def _reset_registry():
    """Drop the registry singleton between every test."""
    yield
    set_registry(None)
