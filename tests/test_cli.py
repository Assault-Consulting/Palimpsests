"""Tests for the CLI shell.

The CLI is thin, so these tests mostly confirm wiring: commands resolve
app state, delegate to core, and format output. We point the config dir
at tmp via the env override and mock the Ollama wire.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit import set_audit_log
from palimpsests.cli import app
from palimpsests.core import UNENCRYPTED_ENV
from palimpsests.registry import set_registry
from typer.testing import CliRunner

BASE = "http://localhost:11434"
runner = CliRunner()


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
    """
    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv(UNENCRYPTED_ENV, "1")
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
