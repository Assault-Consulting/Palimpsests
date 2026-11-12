# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""R1 (0.15), part 3 — ``palimpsests doctor``.

The three silent losses this repository's own runs measured, each as a
finding with a code and a fix: Claude Code's empty bearer (run R1),
OpenCode without the key (run 3), Codex's untrusted hooks (run R2). And the
check itself writes nothing — not to the chain, not to a client's files.
"""
from __future__ import annotations

import json
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests import doctor  # noqa: E402
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

KEY = "sk-doctor"
AUTH = {"Authorization": f"Bearer {KEY}"}
URL = "http://127.0.0.1:11435"
HOOK = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "t1",
        "tool_input": {}}


def _chat(**kwargs):
    yield ChatChunk(delta="text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


@pytest.fixture
def served(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "serve.pala"))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit,
                                   api_key=KEY))
    yield client, audit
    audit.writer.close()


def _run(client, integration, tmp_path, *, api_key=KEY, env=None):
    return doctor.diagnose(integration, url=URL, api_key=api_key, http=client,
                           home=tmp_path / "home", cwd=tmp_path / "cwd", env=env or {})


def _codes(findings, level=None):
    return [f.code for f in findings if level is None or f.level == level]


def _claude_settings(tmp_path, *, allowed=True, failure=True):
    hook = {"type": "http", "url": f"{URL}/v1/pala/hooks/claude",
            "headers": {"Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY"}}
    if allowed:
        hook["allowedEnvVars"] = ["PALIMPSESTS_SERVE_API_KEY"]
    events = ["PreToolUse", "PostToolUse"] + (["PostToolUseFailure"] if failure else [])
    path = tmp_path / "home" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"hooks": {e: [{"matcher": "*", "hooks": [hook]}] for e in events}}))


# ── the check writes nothing ───────────────────────────────────────────────


@pytest.mark.parametrize("integration", sorted(doctor.ROUTES))
def test_the_dry_run_passes_for_every_integration_and_writes_nothing(
        served, tmp_path, integration):
    if integration == "otel":
        pytest.importorskip("opentelemetry.proto")
    client, audit = served
    before = (audit.writer.seq, audit.writer.head_hex)
    findings = _run(client, integration, tmp_path)
    assert "dry_run_ok" in _codes(findings, doctor.OK), findings
    assert (audit.writer.seq, audit.writer.head_hex) == before
    route = client.get("/v1/pala/status", headers=AUTH).json()["ingest"][
        doctor.ROUTES[integration]]
    assert route["accepted"] == 0 and route["dry_run"] == 1


# ── the three measured silent losses ───────────────────────────────────────


def test_claude_codes_empty_bearer_is_named_with_its_fix(served, tmp_path):
    """Run R1: 4 of 26 hook posts arrived with an empty bearer."""
    client, _ = served
    _claude_settings(tmp_path)
    client.post("/v1/pala/hooks/claude", json=HOOK)  # as Claude Code sent it
    findings = _run(client, "claude-code", tmp_path)
    f = next(f for f in findings if f.code == "reports_refused_empty_bearer")
    assert f.level == doctor.FAIL and "allowedEnvVars" in f.fix
    assert doctor.exit_code(findings) == 1


def test_a_refusal_followed_by_an_accepted_report_is_history_not_a_failure(served, tmp_path):
    client, _ = served
    _claude_settings(tmp_path)
    client.post("/v1/pala/hooks/claude", json=HOOK)
    client.post("/v1/pala/hooks/claude", json=HOOK, headers=AUTH)
    findings = _run(client, "claude-code", tmp_path)
    f = next(f for f in findings if f.code == "reports_refused_empty_bearer")
    assert f.level == doctor.WARN and "accepted since" in f.message
    assert "reports_arriving" in _codes(findings, doctor.OK)
    assert doctor.exit_code(findings) == 0


def test_opencode_with_another_key_is_named(served, tmp_path):
    """OpenCode run 3: without the serve's key every post is refused 401."""
    client, _ = served
    client.post("/v1/pala/events", json={"events": [{"type": "tool_call", "id": "a",
                                                     "name": "read"}]},
                headers={"Authorization": "Bearer something-else"})
    findings = _run(client, "opencode", tmp_path)
    assert "reports_refused_wrong_bearer" in _codes(findings, doctor.FAIL)
    assert "opencode_plugin_missing" in _codes(findings, doctor.FAIL)


def test_codex_silence_points_at_trust(served, tmp_path):
    """Run R2: Codex skips an untrusted hook without a word — nothing arrives."""
    client, _ = served
    hooks = tmp_path / "home" / ".codex" / "hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text('{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", '
                     '"command": "python3 /x/palimpsests_hook.py --client codex"}]}]}}')
    findings = _run(client, "codex", tmp_path)
    silent = next(f for f in findings if f.code == "reports_none")
    assert silent.level == doctor.WARN and "trust" in silent.fix
    assert "codex_trust_unverifiable" in _codes(findings, doctor.WARN)
    assert "codex_hooks_configured" in _codes(findings, doctor.OK)
    assert doctor.exit_code(findings) == 0  # nothing failed: it cannot be told from idle


# ── the serve itself ───────────────────────────────────────────────────────


def test_a_serve_that_does_not_answer(tmp_path):
    class Dead:
        def get(self, *a, **k):
            raise ConnectionError("connection refused")

    findings = _run(Dead(), "mcp", tmp_path)
    assert _codes(findings) == ["serve_unreachable"] and doctor.exit_code(findings) == 1


def test_no_key_and_a_wrong_key_are_told_apart(served, tmp_path):
    client, _ = served
    assert "serve_key_missing" in _codes(_run(client, "mcp", tmp_path, api_key=None))
    assert "serve_key_refused" in _codes(_run(client, "mcp", tmp_path, api_key="nope"))


def test_a_serve_older_than_the_status_route(tmp_path):
    class Reply:
        status_code = 404

    class Old:
        def get(self, *a, **k):
            return Reply()

    findings = _run(Old(), "litellm", tmp_path)
    assert _codes(findings) == ["serve_status_missing"]


def test_a_serve_without_a_key_is_a_warning(tmp_path):
    audit = NativeAudit(PalaWriter(tmp_path / "open.pala"))
    client = TestClient(create_app(chat_fn=_chat, models_fn=lambda: [], audit=audit))
    try:
        findings = _run(client, "mcp", tmp_path, api_key=None)
        assert "serve_without_key" in _codes(findings, doctor.WARN)
        assert "dry_run_ok" in _codes(findings, doctor.OK)
    finally:
        audit.writer.close()


# ── the client's configuration ─────────────────────────────────────────────


def test_claude_hooks_without_allowed_env_vars_fail_before_a_single_report(served, tmp_path):
    client, _ = served
    _claude_settings(tmp_path, allowed=False)
    findings = _run(client, "claude-code", tmp_path)
    f = next(f for f in findings if f.code == "claude_allowed_env_missing")
    assert f.level == doctor.FAIL and "empty bearer" in f.message


def test_claude_hooks_as_the_readme_gives_them(served, tmp_path):
    client, _ = served
    _claude_settings(tmp_path)
    assert "claude_hooks_configured" in _codes(_run(client, "claude-code", tmp_path), doctor.OK)
    _claude_settings(tmp_path, failure=False)
    missing = [f for f in _run(client, "claude-code", tmp_path)
               if f.code == "claude_hook_missing"]
    assert [f.level for f in missing] == [doctor.WARN] and "cancelled" in missing[0].message


def test_opencode_plugin_in_either_place(served, tmp_path):
    client, _ = served
    plugin = tmp_path / "cwd" / ".opencode" / "plugins" / "palimpsests-audit.js"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("// plugin")
    assert "opencode_plugin_installed" in _codes(_run(client, "opencode", tmp_path))


def test_otel_exporter_without_the_key_header(served, tmp_path):
    pytest.importorskip("opentelemetry.proto")
    client, _ = served
    env = {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"{URL}/v1/traces"}
    findings = _run(client, "otel", tmp_path, env=env)
    assert "otel_endpoint_set" in _codes(findings, doctor.OK)
    assert "otel_headers_no_key" in _codes(findings, doctor.FAIL)
    env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] = "Authorization=Bearer x"
    assert "otel_headers_no_key" not in _codes(_run(client, "otel", tmp_path, env=env))


# ── output ─────────────────────────────────────────────────────────────────


def test_json_carries_codes_and_the_verdict(served, tmp_path):
    client, _ = served
    out = doctor.to_json("mcp", _run(client, "mcp", tmp_path))
    assert out["format"] == "pala-doctor/1" and out["ok"] is True
    assert all({"level", "code", "message", "fix"} <= set(f) for f in out["findings"])


def test_an_unknown_integration_is_refused():
    with pytest.raises(ValueError, match="unknown integration"):
        doctor.diagnose("emacs")
    from palimpsests.cli import app
    from typer.testing import CliRunner

    r = CliRunner().invoke(app, ["doctor", "emacs"])
    assert r.exit_code == 2 and "unknown integration" in r.output
