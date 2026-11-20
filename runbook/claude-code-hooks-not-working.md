---
title: Claude Code hooks not working? Find where the reports go missing
slug: claude-code-hooks-not-working
group: record
order: 2
updated: 2026-11-16
description: A failing hook never stops the agent, so a broken hook looks exactly like a working one. The silent failures we measured, how to spot each, and one command that names them.
next: log-claude-code-tool-calls, mcp-tool-call-logging
seo_title: Claude Code hooks not working? Find where reports are lost
seo_description: A failing hook never stops the agent, so a broken hook looks like a working one. The silent failures we measured, and one command that names them.
---

A hook is built never to block the agent. That is good for your work and bad for your record: when a hook fails, the agent carries on and nothing tells you. The tools run, and the log stays empty.

## The silent failures we measured

### The key goes out empty

An HTTP hook in Claude Code can send a header with a variable in it, such as `Bearer $PALIMPSESTS_SERVE_API_KEY`. Claude Code fills in only the variables listed in that hook's `allowedEnvVars`. Any other becomes an empty string, without a warning, and the receiver refuses every report.

Fix: list the variable in `allowedEnvVars` of each hook, and start Claude Code from a shell where the variable is set.

### The two sides hold different keys

The client sends a key, but not the one the receiver was started with: a stale value in one shell, a second server, a typo. Every report is refused.

Fix: give both sides the same value.

### Nothing arrives at all

The hooks are missing from the settings file Claude Code reads, they point to another address or port, or the receiver was not running while the tools ran.

Fix: check the file and the URL, and start the receiver before the agent.

### A failed tool is never reported

Without a `PostToolUseFailure` hook, Claude Code reports a failed tool to nobody. The call stays open, and Palimpsests closes it as `cancelled` when the server stops.

Fix: add the third hook.

### Codex: hooks that were never trusted

Codex runs a new hook only after you trust it. An untrusted hook is skipped without a word: the tools run and nothing is reported, even with the hooks on disk and correctly written.

Fix: trust them when Codex asks at startup, or later in `/hooks`.

## One command that names each failure

If the receiver is the Palimpsests server, set up as in [log Claude Code tool calls](https://palimpsests.dev/runbook/log-claude-code-tool-calls/), run:

```bash
palimpsests doctor claude-code
```

It does three things. It asks the server what reached its route and what it refused, counting empty keys apart from wrong ones. It sends a test report through the real key check and parsing, with nothing written to the log. And it reads `~/.claude/settings.json`. A broken setup looks like this:

```text
ok    the serve answers; its chain holds 2 record(s)  [serve_reachable]
warn  nothing has reached /v1/pala/hooks/claude since the serve started  [reports_none]
      -> are the three hooks in ~/.claude/settings.json, and was a tool used since?
ok    /v1/pala/hooks/claude would record a call and its result, marked reported-by-client, outcome 'ok' — nothing was written  [dry_run_ok]
FAIL  the PreToolUse hook's header uses $PALIMPSESTS_SERVE_API_KEY but does not list it in allowedEnvVars — Claude Code then sends an empty bearer, and every report is refused without a sign on its side  [claude_allowed_env_missing]
      -> add "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] to that hook
```

The exit code is 1 if any line says `FAIL`. Warnings do not fail it. `--json` prints the findings for a script. The codes you are most likely to meet:

- `serve_unreachable`: no server answered. Start it, or pass `--url`.
- `serve_key_missing` and `serve_key_refused`: this shell has no key, or not the server's key.
- `reports_refused_empty_bearer`: reports arrived with no key. That is the `allowedEnvVars` case.
- `reports_refused_wrong_bearer`: reports carried a key that is not the server's.
- `reports_none`: nothing has reached the route since the server started.
- `claude_hook_missing`, `claude_hook_other_serve` and `claude_allowed_env_missing`: what is wrong in the settings file.
- `serve_without_key`: a warning that anything able to reach the port can write to the log.

The same command checks the other integrations: `codex`, `opencode`, `litellm`, `mcp` and `otel`. For Codex it cannot see from outside whether a hook is trusted, and it says so.

## Last checked

- The empty key: Windows 11, Claude Code 2.1.310, palimpsests 0.13.0, 26 October 2026. Four of 26 hook posts arrived without the key; why those four has not been established.
- The untrusted hooks: Windows 11, Codex 0.164.0, palimpsests 0.13.0, 26 October 2026. Nothing was recorded before the hooks were trusted.
- `palimpsests doctor` exists since 0.14.1, and the output above is its own.

## Reference

- [Claude Code and Codex hooks: README](https://github.com/Assault-Consulting/Palimpsests/blob/v0.14.1/integrations/agent-hooks/README.md)
- [The real Claude Code session, recorded](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/traffic-0.14-r1-claude-code/RUN-RECORD.md)
- [The real Codex session, recorded](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/traffic-0.14-r2-codex/RUN-RECORD.md)
