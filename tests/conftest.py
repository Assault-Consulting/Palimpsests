"""Shared test fixtures.

Every global singleton gets a reset fixture so no test bleeds into
another. Autouse resets guarantee a clean slate even for tests that
don't request the setup fixture by name.
"""
from __future__ import annotations

import pytest
from palimpsests.audit import AuditLog, generate_key, set_audit_log
from palimpsests.registry import EngineRegistry, set_registry
from pathlib import Path


@pytest.fixture(autouse=True)
def _isolated_keychain(monkeypatch):
    """Keep every test off the real OS keychain.

    The audit log anchors its chain head in the keychain. Tests must
    never read or write the developer's real anchor, so the anchor
    helpers are redirected to an in-memory slot that resets per test.

    Patched at the point of use (``audit.log``) as well as at the source
    module, because ``log.py`` imports the names directly.
    """
    slot: dict[str, str | None] = {"anchor": None}

    def _store(head_hash: str) -> bool:
        slot["anchor"] = head_hash
        return True

    def _load() -> str | None:
        return slot["anchor"]

    def _clear() -> None:
        slot["anchor"] = None

    for module in ("palimpsests.audit.key_manager", "palimpsests.audit.log"):
        monkeypatch.setattr(f"{module}.store_head_anchor", _store, raising=False)
        monkeypatch.setattr(f"{module}.load_head_anchor", _load, raising=False)
        monkeypatch.setattr(f"{module}.clear_head_anchor", _clear, raising=False)
    yield slot


@pytest.fixture
def audit_log(tmp_path: Path):
    """A fresh, isolated, per-test audit log with an ephemeral key.

    Never touches the real OS keychain or the user's real audit DB —
    each test gets its own key and its own tmp_path-backed database.
    Tests that assert on the log request this fixture by name.

    ``allow_unencrypted=True`` is passed *explicitly*: CI runners have no
    native SQLCipher build, and the production default is now to refuse
    rather than silently write plaintext. Spelling it out here is the
    point — an unencrypted log is a deliberate test-only choice.
    """
    key = generate_key()
    log = AuditLog(tmp_path / "audit.db", key, allow_unencrypted=True)
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
