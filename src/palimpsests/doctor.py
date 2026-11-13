# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``palimpsests doctor`` — are an integration's reports reaching the serve?

A client whose reports are refused, or never sent, looks normal from its own
side. This asks the three places that can tell (R1 of the 0.15 plan):

1. the serve's status route — what was accepted and refused on the
   integration's route since the serve started;
2. a dry run of that route — the real bearer check and the real ingestion
   code, with nothing written to the chain;
3. the client's own configuration, where a file or a variable can be read.

It writes nothing: not to the chain (the dry run), not to any client's
configuration. Each finding carries a ``code`` — the field to branch on —
a level, a sentence and, where there is one, what to do.

Limits, stated: a finding about a client's environment is about *this*
shell, which may not be the one the client was started from; whether Codex
has trusted a hook cannot be read from outside Codex; and a tool a client
never reports at all is invisible here — this detects loss on the way, not
absence at the source.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

OK, WARN, FAIL = "ok", "warn", "fail"
KEY_VAR = "PALIMPSESTS_SERVE_API_KEY"
DEFAULT_URL = "http://127.0.0.1:11435"

#: integration -> its ingestion route on the serve
ROUTES = {
    "claude-code": "/v1/pala/hooks/claude",
    "codex": "/v1/pala/hooks/codex",
    "opencode": "/v1/pala/events",
    "litellm": "/v1/pala/events",
    "mcp": "/v1/pala/events",
    "otel": "/v1/traces",
}
#: what a dry-run result must come back as, by each client's own rule
EXPECTED_OUTCOME = {"claude-code": "ok", "codex": "unobserved", "otel": "ok"}


@dataclass(frozen=True)
class Finding:
    level: str  # "ok" | "warn" | "fail"
    code: str  # the field to branch on; sentences may change
    message: str
    fix: str | None = None


def _headers(api_key: str | None, *, dry: bool = False) -> dict:
    h = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    if dry:
        h["X-Palimpsests-Dry-Run"] = "1"
    return h


# ── 1. the serve ────────────────────────────────────────────────────────────


def _status(http, api_key: str | None, env: dict) -> tuple[dict | None, list[Finding]]:
    try:
        r = http.get("/v1/pala/status", headers=_headers(api_key))
    except Exception as exc:  # connection refused, DNS, timeout
        return None, [Finding(
            FAIL, "serve_unreachable", f"no serve answered: {exc}",
            "start it — `palimpsests serve` — or pass --url if it listens elsewhere",
        )]
    if r.status_code == 401:
        if api_key:
            return None, [Finding(
                FAIL, "serve_key_refused",
                "the serve refused this shell's key",
                f"set {KEY_VAR} to the key the serve was started with",
            )]
        return None, [Finding(
            FAIL, "serve_key_missing",
            f"the serve requires a key and {KEY_VAR} is not set in this shell",
            f"export {KEY_VAR} with the key the serve was started with",
        )]
    if r.status_code == 404:
        return None, [Finding(
            FAIL, "serve_status_missing",
            "the serve has no status route — it is older than 0.14.1",
            "upgrade the serve: pip install -U 'palimpsests[serve]'",
        )]
    if r.status_code != 200:
        return None, [Finding(FAIL, "serve_status_error",
                              f"the status route answered {r.status_code}")]
    status = r.json()
    found: list[Finding] = []
    if status.get("chain") is None:
        found.append(Finding(
            FAIL, "serve_no_chain", "the serve runs without an audit chain: nothing is recorded",
            "start it with `palimpsests serve`, which opens its chain",
        ))
    else:
        found.append(Finding(
            OK, "serve_reachable",
            f"the serve answers; its chain holds {status['chain']['records']} record(s)",
        ))
    if not status.get("auth_required"):
        found.append(Finding(
            WARN, "serve_without_key",
            "the serve accepts reports without a key — anything that can reach the "
            "port can write to its chain",
            f"start it with --api-key or {KEY_VAR} unless it is strictly local",
        ))
    return status, found


# ── 2. what reached the route ───────────────────────────────────────────────

_REFUSAL_FIX = {
    "claude-code": (
        "in ~/.claude/settings.json, each hook whose header uses "
        f"${KEY_VAR} must list it in allowedEnvVars, and Claude Code must be "
        "started from a shell where it is set"
    ),
    "codex": f"export {KEY_VAR} in the shell Codex is started from",
    "opencode": f"export {KEY_VAR} in the window OpenCode is started from",
    "litellm": f"export {KEY_VAR} for the process that runs LiteLLM",
    "mcp": f"export {KEY_VAR} in the environment the MCP proxy runs in",
    "otel": (
        "set OTEL_EXPORTER_OTLP_TRACES_HEADERS to "
        f"\"Authorization=Bearer ${KEY_VAR}\" for the exporting process"
    ),
}
_SILENCE_HINT = {
    "claude-code": "are the three hooks in ~/.claude/settings.json, and was a tool used since?",
    "codex": (
        "Codex skips a hook it has not been told to trust, without a word — open "
        "/hooks in an interactive session and trust them"
    ),
    "opencode": "is palimpsests-audit.js in a plugins directory, and was a tool used since?",
    "litellm": "is PalimpsestsAudit registered in litellm.callbacks, and did a tool loop run?",
    "mcp": "is the server started through the proxy, and was a tool called since?",
    "otel": "is the trace exporter pointed at this serve's /v1/traces?",
}


def _history(status: dict, integration: str) -> list[Finding]:
    route = ROUTES[integration]
    entry = (status.get("ingest") or {}).get(route)
    if entry is None:
        return [Finding(FAIL, "route_unknown", f"the serve reports nothing for {route}")]
    refused = entry.get("refused") or {}
    empty, wrong = refused.get("empty_bearer", 0), refused.get("wrong_bearer", 0)
    accepted = entry.get("accepted", 0)
    newer_refusal = (entry.get("last_refused_ns") or 0) > (entry.get("last_accepted_ns") or 0)
    level = FAIL if newer_refusal else WARN  # refusals since fixed are history, not a state
    found: list[Finding] = []
    if empty:
        found.append(Finding(
            level, "reports_refused_empty_bearer",
            f"{empty} report(s) on {route} arrived with no key and were refused"
            + ("" if newer_refusal else " — earlier; reports have been accepted since"),
            _REFUSAL_FIX[integration],
        ))
    if wrong:
        found.append(Finding(
            level, "reports_refused_wrong_bearer",
            f"{wrong} report(s) on {route} carried a key that is not the serve's"
            + ("" if newer_refusal else " — earlier; reports have been accepted since"),
            f"the client's {KEY_VAR} differs from the serve's; make them the same",
        ))
    if accepted:
        found.append(Finding(OK, "reports_arriving",
                             f"{accepted} report(s) accepted on {route} since the serve started"))
    elif not (empty or wrong):
        found.append(Finding(
            WARN, "reports_none",
            f"nothing has reached {route} since the serve started",
            _SILENCE_HINT[integration],
        ))
    if entry.get("rejected"):
        found.append(Finding(
            WARN, "reports_rejected",
            f"{entry['rejected']} request(s) on {route} were refused as malformed",
        ))
    return found


# ── 3. the dry run ──────────────────────────────────────────────────────────


def _otlp_export() -> dict:
    def attr(key, value):
        return {"key": key, "value": {"stringValue": value}}

    return {"resourceSpans": [{"scopeSpans": [{"spans": [{
        "traceId": "00000000000000000000000000d0c702",
        "spanId": "00000000000d0c70",
        "name": "execute_tool doctor.check",
        "startTimeUnixNano": "1", "endTimeUnixNano": "2",
        "attributes": [attr("gen_ai.operation.name", "execute_tool"),
                       attr("gen_ai.tool.name", "doctor.check")],
        "status": {"code": 0},
    }]}]}]}


def _dry_run(http, api_key: str | None, integration: str) -> list[Finding]:
    route = ROUTES[integration]
    headers = _headers(api_key, dry=True)
    if route.startswith("/v1/pala/hooks/"):
        body = {"hook_event_name": "PostToolUse", "tool_name": "doctor.check",
                "tool_use_id": "palimpsests-doctor", "tool_input": {}, "tool_response": {}}
    elif route == "/v1/traces":
        body = _otlp_export()
    else:
        body = {"events": [
            {"type": "tool_call", "id": "palimpsests-doctor", "name": "doctor.check"},
            {"type": "tool_result", "call_id": "palimpsests-doctor", "outcome": "ok"},
        ]}
    try:
        r = http.post(route, headers=headers, json=body)
    except Exception as exc:
        return [Finding(FAIL, "dry_run_unreachable", f"the dry run did not get through: {exc}")]
    if r.status_code != 200:
        return [Finding(
            FAIL, "dry_run_refused",
            f"a dry run of {route} was answered {r.status_code}: the route would not "
            "record a report sent with this shell's key",
        )]
    reply = r.json()
    if reply.get("dry_run") is not True:
        return [Finding(
            FAIL, "dry_run_unsupported",
            "the serve does not know the dry run and may have recorded the check — "
            "it is older than 0.14.1",
            "upgrade the serve: pip install -U 'palimpsests[serve]'",
        )]
    would = reply.get("would_record") or []
    kinds = [w.get("record") for w in would]
    if kinds != ["TOOL_CALL", "TOOL_RESULT"]:
        return [Finding(FAIL, "dry_run_incomplete",
                        f"a dry run of {route} would record {kinds or 'nothing'}, "
                        "not a call and its result")]
    if any(w.get("source") != "reported-by-client" for w in would):
        return [Finding(FAIL, "dry_run_wrong_source",
                        "the route would record the pair without the reported-by-client mark")]
    outcome = would[1].get("outcome")
    expected = EXPECTED_OUTCOME.get(integration)
    if expected is not None and outcome != expected:
        return [Finding(FAIL, "dry_run_wrong_outcome",
                        f"the route would record outcome {outcome!r}, expected {expected!r}")]
    return [Finding(
        OK, "dry_run_ok",
        f"{route} would record a call and its result, marked reported-by-client, "
        f"outcome {outcome!r} — nothing was written",
    )]


# ── 4. the client's own configuration ───────────────────────────────────────


def _claude_config(home: Path, url: str) -> list[Finding]:
    path = home / ".claude" / "settings.json"
    if not path.is_file():
        return [Finding(FAIL, "claude_settings_missing", f"{path} does not exist",
                        "add the three hooks from integrations/agent-hooks/README.md")]
    try:
        hooks = json.loads(path.read_text(encoding="utf-8")).get("hooks") or {}
    except (ValueError, AttributeError) as exc:
        return [Finding(FAIL, "claude_settings_unreadable", f"{path} is not valid JSON: {exc}")]
    found: list[Finding] = []
    target = "/v1/pala/hooks/claude"
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        ours = [h for group in hooks.get(event) or [] if isinstance(group, dict)
                for h in group.get("hooks") or []
                if isinstance(h, dict) and str(h.get("url", "")).endswith(target)]
        if not ours:
            found.append(Finding(
                WARN if event == "PostToolUseFailure" else FAIL,
                "claude_hook_missing",
                f"no {event} hook posts to {target}"
                + (" — a failed tool is then never reported, and its call is closed "
                   "as cancelled at shutdown" if event == "PostToolUseFailure" else ""),
                "add it as in integrations/agent-hooks/README.md",
            ))
            continue
        for h in ours:
            if not str(h.get("url", "")).startswith(url):
                found.append(Finding(
                    WARN, "claude_hook_other_serve",
                    f"the {event} hook posts to {h.get('url')}, not to {url}",
                ))
            auth = str((h.get("headers") or {}).get("Authorization", ""))
            used = [w.lstrip("$").strip("{}") for w in auth.split() if w.startswith("$")]
            missing = [v for v in used if v not in (h.get("allowedEnvVars") or [])]
            if missing:
                found.append(Finding(
                    FAIL, "claude_allowed_env_missing",
                    f"the {event} hook's header uses ${missing[0]} but does not list it in "
                    "allowedEnvVars — Claude Code then sends an empty bearer, and every "
                    "report is refused without a sign on its side",
                    f"add \"allowedEnvVars\": [\"{missing[0]}\"] to that hook",
                ))
    if not found:
        found.append(Finding(OK, "claude_hooks_configured",
                             f"the three hooks in {path} post to this serve"))
    return found


def _codex_config(home: Path) -> list[Finding]:
    path = home / ".codex" / "hooks.json"
    if not path.is_file():
        return [Finding(FAIL, "codex_hooks_missing", f"{path} does not exist",
                        "add the two hooks from integrations/agent-hooks/README.md")]
    text = path.read_text(encoding="utf-8", errors="replace")
    found: list[Finding] = []
    if "palimpsests_hook" not in text:
        found.append(Finding(FAIL, "codex_hook_missing",
                             f"{path} names no palimpsests_hook.py command",
                             "add the two hooks from integrations/agent-hooks/README.md"))
    else:
        found.append(Finding(OK, "codex_hooks_configured", f"{path} names the forwarder"))
    found.append(Finding(
        WARN, "codex_trust_unverifiable",
        "whether Codex has trusted these hooks cannot be read from outside Codex; "
        "an untrusted hook is skipped without a word",
        "open /hooks in an interactive Codex session and confirm they are trusted",
    ))
    return found


def _opencode_config(home: Path, cwd: Path) -> list[Finding]:
    places = [cwd / ".opencode" / "plugins", home / ".config" / "opencode" / "plugins"]
    if any((p / "palimpsests-audit.js").is_file() for p in places):
        return [Finding(OK, "opencode_plugin_installed", "palimpsests-audit.js is installed")]
    return [Finding(
        FAIL, "opencode_plugin_missing",
        "palimpsests-audit.js is in neither .opencode/plugins/ nor ~/.config/opencode/plugins/",
        "copy integrations/opencode/palimpsests-audit.js into one of them",
    )]


def _otel_config(env: dict, url: str, auth_required: bool) -> list[Finding]:
    endpoint = env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
    found: list[Finding] = []
    if not endpoint:
        found.append(Finding(
            WARN, "otel_endpoint_unset",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not set in this shell",
            f"export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT={url}/v1/traces for the exporter",
        ))
    elif endpoint.rstrip("/") != f"{url}/v1/traces":
        found.append(Finding(WARN, "otel_endpoint_other",
                             f"the trace exporter points at {endpoint}, not {url}/v1/traces"))
    else:
        found.append(Finding(OK, "otel_endpoint_set", "the trace exporter points at this serve"))
    headers = env.get("OTEL_EXPORTER_OTLP_TRACES_HEADERS") or env.get(
        "OTEL_EXPORTER_OTLP_HEADERS", "")
    if auth_required and "authorization=" not in headers.lower():
        found.append(Finding(
            FAIL, "otel_headers_no_key",
            "the serve requires a key and the exporter's headers carry no Authorization",
            f"export OTEL_EXPORTER_OTLP_TRACES_HEADERS=\"Authorization=Bearer ${KEY_VAR}\"",
        ))
    return found


def _client_config(integration: str, home: Path, cwd: Path, env: dict, url: str,
                   auth_required: bool) -> list[Finding]:
    if integration == "claude-code":
        return _claude_config(home, url)
    if integration == "codex":
        return _codex_config(home)
    if integration == "opencode":
        return _opencode_config(home, cwd)
    if integration == "otel":
        return _otel_config(env, url, auth_required)
    return []  # litellm, mcp: wired in the user's own code or client config


# ── the whole check ─────────────────────────────────────────────────────────


def diagnose(integration: str, *, url: str = DEFAULT_URL, api_key: str | None = None,
             home: Path | None = None, cwd: Path | None = None, env: dict | None = None,
             http=None) -> list[Finding]:
    """Every finding for one integration. ``http`` is injectable for tests."""
    if integration not in ROUTES:
        raise ValueError(f"unknown integration {integration!r}; one of {', '.join(ROUTES)}")
    env = dict(os.environ) if env is None else env
    home = Path.home() if home is None else home
    cwd = Path.cwd() if cwd is None else cwd
    url = url.rstrip("/")
    if api_key is None:
        api_key = env.get(KEY_VAR) or None
    owned = http is None
    if owned:
        import httpx

        http = httpx.Client(base_url=url, timeout=10)
    try:
        status, found = _status(http, api_key, env)
        if status is not None and status.get("chain") is not None:
            found += _history(status, integration)
            found += _dry_run(http, api_key, integration)
        auth_required = bool(status and status.get("auth_required"))
        found += _client_config(integration, home, cwd, env, url, auth_required)
        return found
    finally:
        if owned:
            http.close()


def exit_code(findings: list[Finding]) -> int:
    """1 if anything failed; warnings do not fail the check."""
    return 1 if any(f.level == FAIL for f in findings) else 0


def to_json(integration: str, findings: list[Finding]) -> dict:
    return {"format": "pala-doctor/1", "integration": integration,
            "ok": exit_code(findings) == 0, "findings": [asdict(f) for f in findings]}
