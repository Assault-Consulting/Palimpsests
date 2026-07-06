"""Tests for the engine registry (radio active-selection)."""
from __future__ import annotations

import pytest
from palimpsests.registry import (
    DEFAULT_ENGINE_ID,
    EngineRegistry,
    get_registry,
    set_registry,
)
from pathlib import Path

# ─── registration ────────────────────────────────────────────────────────


def test_register_and_known(registry: EngineRegistry) -> None:
    registry.register("ollama", control_level=1, installed=True)
    registry.register("llamacpp", control_level=2, installed=False)

    known = {r.engine_id: r for r in registry.known()}
    assert known["ollama"].control_level == 1
    assert known["ollama"].installed is True
    assert known["llamacpp"].installed is False


def test_register_is_idempotent(registry: EngineRegistry) -> None:
    """Re-registering updates installed-state — models a fresh probe."""
    registry.register("ollama", control_level=1, installed=False)
    registry.register("ollama", control_level=1, installed=True)

    assert len(registry.known()) == 1
    assert registry.is_installed("ollama") is True


def test_is_installed_false_for_unknown(registry: EngineRegistry) -> None:
    assert registry.is_installed("nonexistent") is False


# ─── radio active-selection ──────────────────────────────────────────────


def test_default_active_engine(registry: EngineRegistry) -> None:
    assert registry.active_engine_id == DEFAULT_ENGINE_ID


def test_set_active(registry: EngineRegistry) -> None:
    registry.register("llamacpp", control_level=2, installed=True)
    registry.set_active("llamacpp")
    assert registry.active_engine_id == "llamacpp"


def test_set_active_is_radio(registry: EngineRegistry) -> None:
    """Only one engine is active — switching replaces, doesn't add."""
    registry.register("ollama", control_level=1, installed=True)
    registry.register("llamacpp", control_level=2, installed=True)

    registry.set_active("ollama")
    assert registry.active_engine_id == "ollama"
    registry.set_active("llamacpp")
    assert registry.active_engine_id == "llamacpp"  # replaced, not added


def test_set_active_unknown_raises(registry: EngineRegistry) -> None:
    """Selecting an unregistered engine is a typo — fail early."""
    with pytest.raises(KeyError):
        registry.set_active("typo-engine")


def test_set_active_allows_not_installed(registry: EngineRegistry) -> None:
    """A user may select an engine before its daemon is up; routing-time
    code checks readiness. Selection itself doesn't require installed."""
    registry.register("llamacpp", control_level=2, installed=False)
    registry.set_active("llamacpp")  # must not raise
    assert registry.active_engine_id == "llamacpp"


# ─── persistence ─────────────────────────────────────────────────────────


def test_active_persists_across_reopen(tmp_path: Path) -> None:
    cfg = tmp_path / "registry.json"

    reg1 = EngineRegistry(cfg)
    reg1.register("llamacpp", control_level=2, installed=True)
    reg1.set_active("llamacpp")

    # A fresh registry reading the same config sees the choice.
    reg2 = EngineRegistry(cfg)
    assert reg2.active_engine_id == "llamacpp"


def test_installed_state_not_persisted(tmp_path: Path) -> None:
    """Installed-state is environmental, re-derived each run — a fresh
    registry does NOT remember which engines were registered."""
    cfg = tmp_path / "registry.json"

    reg1 = EngineRegistry(cfg)
    reg1.register("ollama", control_level=1, installed=True)
    reg1.set_active("ollama")

    reg2 = EngineRegistry(cfg)
    # Active choice persisted, but the engines map is empty until
    # something re-registers.
    assert reg2.active_engine_id == "ollama"
    assert reg2.known() == []


def test_corrupt_config_falls_back_to_default(tmp_path: Path) -> None:
    """A corrupt config must not crash startup."""
    cfg = tmp_path / "registry.json"
    cfg.write_text("{ this is not valid json")

    reg = EngineRegistry(cfg)
    assert reg.active_engine_id == DEFAULT_ENGINE_ID


def test_missing_config_uses_default(tmp_path: Path) -> None:
    reg = EngineRegistry(tmp_path / "does-not-exist.json")
    assert reg.active_engine_id == DEFAULT_ENGINE_ID


# ─── singleton ───────────────────────────────────────────────────────────


def test_singleton_get_set(registry: EngineRegistry) -> None:
    assert get_registry() is registry


def test_singleton_defaults_none() -> None:
    set_registry(None)
    assert get_registry() is None
