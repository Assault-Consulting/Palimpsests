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


def test_selftest_reports_the_characteristic_and_trips_on_the_slope(monkeypatch):
    from palimpsests.audit.pala import selftest as st

    result = run_selftest()
    line = next(ln for ln in result.lines if ln.strip().startswith("characteristic:"))
    assert "B/record" in line and "rec/s" in line and line.endswith("— ok")
    assert str(st.CHARACTERISTIC_RECORDS)[:2] in line  # the synthetic chain, not the vectors

    # the tripwire: a slope above the bound fails the selftest by name
    monkeypatch.setattr(st, "HEAP_BYTES_PER_RECORD_MAX", 1)
    tripped = run_selftest()
    assert tripped.ok is False
    tripped_line = next(ln for ln in tripped.lines if ln.strip().startswith("characteristic:"))
    assert tripped_line.endswith("— FAIL")
