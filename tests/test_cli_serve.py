# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The serve subcommand is present and self-describing."""
from __future__ import annotations

from palimpsests.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_serve_help_describes_the_endpoint():
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    assert "OpenAI-compatible" in result.output
    assert "11435" in result.output
