# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The serve subcommand is present and self-describing."""
from __future__ import annotations

import pytest
from palimpsests.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def test_serve_help_describes_the_endpoint():
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    assert "OpenAI-compatible" in result.output
    assert "11435" in result.output


def test_serve_preflights_the_audit_log_before_binding(monkeypatch, capsys):
    """A serve that cannot open the audit log must say so and exit, not
    bind a port and fail on the first GET /v1/models.

    The OpenCode traffic run hit the old behaviour: the endpoint
    announced itself, then every model listing raised inside the request
    and the client showed nothing useful. The exception already carries
    the remedy; this test pins that the operator sees it.
    """
    import sys
    from palimpsests.audit import AuditIntegrityError
    from palimpsests.server import openai_api

    def boom():
        raise AuditIntegrityError(
            "SQLCipher unavailable\n\nInstall the encryption extra:\n"
            "    pip install 'palimpsests[encryption]'"
        )

    monkeypatch.setattr(openai_api, "_default_deps", boom)
    monkeypatch.setattr(sys, "argv", ["palimpsests-serve"])
    with pytest.raises(SystemExit) as excinfo:
        openai_api.main()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "SQLCipher unavailable" in err
    assert "palimpsests[encryption]" in err
