# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""selftest: the installed build reproduces the published expectations."""
from __future__ import annotations

from palimpsests.audit.pala.selftest import run_selftest
from palimpsests.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_selftest_passes_on_this_build():
    result = run_selftest()
    assert result.ok, "\n".join(result.lines)
    # both packaged sets were exercised, and the version line is present
    joined = "\n".join(result.lines)
    assert "core" in joined and "inference" in joined
    assert "version:" in joined


def test_selftest_fails_on_version_drift(monkeypatch):
    import palimpsests

    monkeypatch.setattr(palimpsests, "__version__", "0.0.0-drifted")
    result = run_selftest()
    assert result.ok is False
    assert any("FAIL" in ln and "version" in ln for ln in result.lines)


def test_cli_exit_code_and_verdict():
    result = runner.invoke(app, ["pala", "selftest"])
    assert result.exit_code == 0, result.output
    assert "sound" in result.output
