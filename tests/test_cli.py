"""Tests for the CLI shell.

The CLI is thin, so these tests mostly confirm wiring: commands resolve
app state, delegate to core, and format output. We point the config dir
at tmp via the env override and mock the Ollama wire.
"""
from __future__ import annotations

import json
import pytest
import sqlite3
from palimpsests.audit import AuditLog, generate_key, set_audit_log
from palimpsests.cli import app
from palimpsests.core import UNENCRYPTED_ENV
from palimpsests.registry import set_registry
from typer.testing import CliRunner

BASE = "http://localhost:11434"
runner = CliRunner()

_TEST_KEY = generate_key()


def _ndjson(*objs: dict) -> bytes:
    return ("\n".join(json.dumps(o) for o in objs) + "\n").encode()


@pytest.fixture(autouse=True)
def _tmp_config(tmp_path, monkeypatch):
    """Point every CLI run at a throwaway config dir, and reset the
    singletons after so runs don't leak into each other.

    The audit log refuses to open unencrypted unless told to, and CI
    runners have no native SQLCipher build — so the CLI, which builds a
    real app context, needs the opt-in set explicitly. Saying it here
    (rather than weakening the default) keeps the production posture
    fail-closed.

    ``load_or_create_key`` is stubbed so no test ever reaches the
    developer's real OS keychain for the encryption key. (The head anchor
    is already isolated by an autouse fixture in conftest.)
    """
    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(UNENCRYPTED_ENV, "1")
    monkeypatch.setattr("palimpsests.core.load_or_create_key", lambda: _TEST_KEY)
    yield
    set_audit_log(None)
    set_registry(None)


def test_models_command_lists(httpx_mock):
    # init_app probes availability, then the command lists.
    tags = {
        "models": [
            {
                "name": "qwen2.5:7b",
                "size": 4.7e9,
                "details": {"quantization_level": "Q4"},
            }
        ]
    }
    # init_app probes /api/tags, then the command lists via /api/tags.
    httpx_mock.add_response(url=f"{BASE}/api/tags", json=tags)
    httpx_mock.add_response(url=f"{BASE}/api/tags", json=tags)
    result = runner.invoke(app, ["models"])
    assert result.exit_code == 0
    assert "qwen2.5:7b" in result.output


def test_engine_list_command(httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    result = runner.invoke(app, ["engine", "list"])
    assert result.exit_code == 0
    assert "ollama" in result.output
    assert "*" in result.output  # active marker


def test_engine_use_unknown_fails(httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    result = runner.invoke(app, ["engine", "use", "ghost"])
    assert result.exit_code == 1
    assert "unknown engine" in result.output


def test_chat_command_streams(httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson(
            {"message": {"content": "2+2="}, "done": False},
            {"message": {"content": "4"}, "done": True, "done_reason": "stop"},
        ),
    )
    result = runner.invoke(app, ["chat", "qwen2.5:7b", "-m", "what is 2+2"])
    assert result.exit_code == 0
    assert "2+2=4" in result.output


def test_chat_reads_prompt_from_stdin(httpx_mock):
    """When -m is omitted, the prompt is read from piped stdin."""
    httpx_mock.add_response(url=f"{BASE}/api/tags", json={"models": []})
    httpx_mock.add_response(
        url=f"{BASE}/api/chat",
        content=_ndjson(
            {"message": {"content": "echo"}, "done": True, "done_reason": "stop"},
        ),
    )
    result = runner.invoke(app, ["chat", "m"], input="hello from stdin")
    assert result.exit_code == 0
    # The piped text became the prompt sent to the engine.
    request = next(
        r for r in httpx_mock.get_requests() if r.url.path == "/api/chat"
    )
    sent = json.loads(request.content)["messages"]
    assert sent[0]["content"] == "hello from stdin"


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert result.exit_code in (0, 2)
    assert "layered local-LLM" in result.output or "Usage" in result.output


# ─── audit verify ────────────────────────────────────────────────────────

# The exit codes are the command's contract with cron and CI, so each one
# is pinned by a test. `audit verify` never touches the network, so these
# need no httpx mock.


def _seed_log(tmp_path, rows: int = 2) -> None:
    """Write a real, anchored chain at the path the CLI will read."""
    log = AuditLog(tmp_path / "audit.db", _TEST_KEY, allow_unencrypted=True)
    for i in range(rows):
        log.record(operation="model.call", tool_name=f"c{i}", outcome="success")
    log.close()


def test_audit_verify_missing_log_is_unreadable(tmp_path):
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 3
    assert "no audit log" in result.output


def test_audit_verify_clean_log_exits_zero(tmp_path):
    _seed_log(tmp_path)
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "verified" in result.output
    assert "2 rows" in result.output


def test_audit_verify_detects_tampering(tmp_path):
    _seed_log(tmp_path)
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("UPDATE audit_events SET outcome='denied' WHERE id=1")
    conn.commit()
    conn.close()

    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 1
    assert "TAMPERED" in result.output
    assert "first bad row: 1" in result.output


def test_audit_verify_without_anchor_is_partial(tmp_path, monkeypatch):
    """Chain intact, anchor unavailable: not success, not tampering."""
    _seed_log(tmp_path)
    monkeypatch.setattr("palimpsests.audit.log.load_head_anchor", lambda *, scope="": None)

    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 2
    assert "PARTIAL" in result.output
    assert "would not have been detected" in result.output


def test_audit_verify_require_anchor_makes_partial_a_failure(tmp_path, monkeypatch):
    """--require-anchor is the strict gate: a partial pass becomes a failure."""
    _seed_log(tmp_path)
    monkeypatch.setattr("palimpsests.audit.log.load_head_anchor", lambda *, scope="": None)

    result = runner.invoke(app, ["audit", "verify", "--require-anchor"])
    assert result.exit_code == 1


def test_audit_verify_json_output(tmp_path):
    _seed_log(tmp_path, rows=3)
    result = runner.invoke(app, ["audit", "verify", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["rows_checked"] == 3
    assert payload["head_anchored"] is True
    assert payload["exit_code"] == 0


def test_audit_verify_json_reports_tampering(tmp_path):
    _seed_log(tmp_path)
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("DELETE FROM audit_events WHERE id=1")
    conn.commit()
    conn.close()

    result = runner.invoke(app, ["audit", "verify", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["exit_code"] == 1
    assert payload["reason"]


def test_audit_verify_does_not_disturb_the_anchor(tmp_path, _isolated_keychain):
    """Verifying a tampered log must leave the evidence intact."""
    _seed_log(tmp_path)
    anchored = _isolated_keychain["anchor"]

    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    conn.execute("UPDATE audit_events SET outcome='denied' WHERE id=1")
    conn.commit()
    conn.close()

    assert runner.invoke(app, ["audit", "verify"]).exit_code == 1
    # A second run must reach the same verdict, not a laundered one.
    assert runner.invoke(app, ["audit", "verify"]).exit_code == 1
    assert _isolated_keychain["anchor"] == anchored
