# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The demo command produces a verifiable trail and says so honestly."""
from __future__ import annotations

from palimpsests.audit.reader import AuditReader
from palimpsests.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_demo_writes_a_green_chain_with_the_tool_loop(tmp_path):
    log = tmp_path / "demo.pala"
    result = runner.invoke(app, ["demo", "--log", str(log)])
    assert result.exit_code == 0, result.output
    assert "chain_ok: True" in result.output
    with AuditReader.open(log) as reader:
        ver = reader.verify()
        kinds = {dr.kind_name for dr in reader.records()}
    assert ver.chain.chain_ok is True
    assert {"MODEL_LOAD", "TOOL_CALL", "TOOL_RESULT"} <= kinds


def test_demo_overwrites_its_previous_artifact(tmp_path):
    log = tmp_path / "demo.pala"
    assert runner.invoke(app, ["demo", "--log", str(log)]).exit_code == 0
    assert runner.invoke(app, ["demo", "--log", str(log)]).exit_code == 0
