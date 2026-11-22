---
title: Log Claude Code tool calls on your own machine
slug: log-claude-code-tool-calls
group: record
order: 1
updated: 2026-11-22
description: Record every tool call Claude Code makes in a tamper-evident log on your own machine, with three hook entries and a local server. Fingerprints instead of content, and failures marked as failures.
next: claude-code-hooks-not-working, mcp-tool-call-logging
seo_title: Log Claude Code tool calls on your own machine
seo_description: Record every tool call Claude Code makes in a tamper-evident log on your own machine, with three hook entries and a local server. Digests, not content.
---

Claude Code thinks on a hosted model, but it acts on your machine: it reads files, edits them and runs commands. Its hooks can report each of those actions as it happens. Palimpsests receives the reports and writes them into a log that cannot be changed without the change showing. The log stays on your machine, and you do not need a local model for this.

## You need

- Claude Code.
- Python 3.11 or newer.

## Steps

### 1. Start the server with a key

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
palimpsests serve
```

The second line is explained on the [runbook's first page](https://palimpsests.dev/runbook/).

### 2. Add three hooks

Add this to `~/.claude/settings.json`. If the file already has `hooks`, merge these in.

```json
{
  "hooks": {
    "PreToolUse":         [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }],
    "PostToolUse":        [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }],
    "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }]
  }
}
```

Keep `allowedEnvVars`. Claude Code puts a variable into a header only if the variable is listed there. Without it the key goes out empty, every report is refused, and Claude Code works on as if nothing were wrong.

### 3. Start Claude Code

Start it from a shell where `PALIMPSESTS_SERVE_API_KEY` has the same value as for the server, and work as usual.

### 4. Check

```bash
palimpsests doctor claude-code
```

It asks the server what arrived, sends a test report that writes nothing, and reads your settings file. Each line ends with a code, and a `FAIL` line comes with a fix. After Claude Code has used a tool:

```bash
palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_'
```

Each line is a call or a result, marked `"source_name": "reported-by-client"`. In Windows PowerShell, use `Select-String` in place of `grep`.

## What is recorded, and what is not

- The tool's name, a fingerprint of its input and of its result, and whether it succeeded or failed. The content of files, commands and outputs never enters the log.
- A failed tool is recorded as `error`, because Claude Code reports failures.
- Prompts, replies and session events reach the server and are ignored.
- The record shows that Claude Code reported a call and a result, and when. It does not show that the tool ran.
- Claude Code runs many reads and searches through its shell tool, so the log often names `Bash` where you might expect more variety.
- A hook never stops Claude Code. If the server is not running, the agent carries on and nothing is recorded, so start the server first.

## Last checked

- Linux, Claude Code 2.1.329, `main` at `09c6f59` shortly before 0.15.0, 22 November 2026: one call and its result reached the log, in a [surface check](https://github.com/Assault-Consulting/Palimpsests/blob/main/results/surfaces-2026-11-22-2.md). On Windows the check cannot isolate Claude Code, so it was not checked there.
- The commands on this page: palimpsests 0.15.0 from PyPI, Linux, 22 November 2026, with hook reports sent by hand in place of the client.
- Linux, Claude Code 2.1.319, palimpsests 0.14.0, 13 November 2026: one call and its result reached the log, in a surface check.
- Windows 11, Claude Code 2.1.310, palimpsests 0.13.0, 26 October 2026: a real session, eleven calls with their results, the failed file read recorded as `error`. Four of the 26 hook posts arrived without the key, and why has not been established.
- [Every check, with its date and machine](https://github.com/Assault-Consulting/Palimpsests/blob/main/integrations/COMPATIBILITY.md)

## Reference

- [Claude Code and Codex hooks: README](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/integrations/agent-hooks/README.md)
- [The real Claude Code session, recorded](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/traffic-0.14-r1-claude-code/RUN-RECORD.md)
- [Recording agents that use cloud models](https://palimpsests.dev/notes/audit-log-for-agents-on-cloud-models/)
