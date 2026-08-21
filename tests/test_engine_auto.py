# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Engine auto-selection: smart default, explicit override, no silent writes."""
from __future__ import annotations

import pytest
from palimpsests.core import AppContext, _best_installed_id, select_engine
from palimpsests.registry import EngineRegistry


class _Engine:
    def __init__(self, name):
        self.name = name


def _registry(tmp_path, rows):
    reg = EngineRegistry(tmp_path / "registry.json")
    for engine_id, level, installed in rows:
        reg.register(engine_id, control_level=level, installed=installed)
    return reg


def _ctx(tmp_path, rows):
    reg = _registry(tmp_path, rows)
    engines = {engine_id: _Engine(engine_id) for engine_id, _, _ in rows}
    return AppContext(config_dir=tmp_path, registry=reg, engines=engines)


def test_auto_selects_the_highest_installed_level(tmp_path):
    ctx = _ctx(
        tmp_path,
        [("ollama", 1, True), ("llamacpp", 2, True), ("pal-native", 3, False)],
    )
    select_engine(ctx, "auto")
    # persisted as the concrete id, never the word "auto"
    assert ctx.registry.active_engine_id == "llamacpp"


def test_auto_with_nothing_installed_raises_keyerror(tmp_path):
    ctx = _ctx(tmp_path, [("ollama", 1, False)])
    with pytest.raises(KeyError):
        select_engine(ctx, "auto")


def test_active_engine_falls_back_when_configured_one_is_not_installed(tmp_path):
    ctx = _ctx(tmp_path, [("ollama", 1, False), ("llamacpp", 2, True)])
    # configured (default) active is ollama, which is not installed this run
    assert ctx.registry.active_engine_id == "ollama"
    assert ctx.active_engine().name == "llamacpp"
    # the fallback is per-run only: nothing was persisted
    assert ctx.registry.active_engine_id == "ollama"


def test_explicit_choice_is_respected_when_installed(tmp_path):
    ctx = _ctx(tmp_path, [("ollama", 1, True), ("llamacpp", 2, True)])
    select_engine(ctx, "ollama")
    assert ctx.active_engine().name == "ollama"  # never second-guessed


def test_best_installed_prefers_control_level(tmp_path):
    reg = _registry(
        tmp_path, [("a", 1, True), ("b", 3, True), ("c", 2, True)]
    )
    assert _best_installed_id(reg) == "b"
