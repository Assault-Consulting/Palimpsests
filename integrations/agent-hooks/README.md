# Agent tool hooks — probe

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Claude Code and Codex both expose a `PreToolUse` / `PostToolUse` hook
convention: a hook receives the tool name, its input, a call identifier
and — after the call — its result, as JSON. That is enough to record
the agent's tool loop as reported pairs on a local chain. The audit
record stays on the machine that deploys the agent, even when the model
does not.

This directory holds the **probe** that comes before any adapter. The
adapter is written against what the hook really sends on the version
installed today, not against documentation — and the documentation
already disagrees with itself on one field.

**Results for Claude Code 2.1.288 and Codex CLI 0.160.0 are in
[PROBE-RESULTS.md](PROBE-RESULTS.md)**, including two ways a hook fails
silently and one result the adapter must not record as a success.

## What the probe answers

| Question | Why it matters |
|---|---|
| Is the result field `tool_response` or `tool_output`? | sources disagree; the adapter must read the right one |
| Is the result a string, an object, or both depending on the tool? | two clients must produce the same digest for the same result |
| Is `tool_use_id` present on both `PreToolUse` and `PostToolUse`? | it is the key that binds a result to its call |
| Does `PostToolUseFailure` fire, and with what? | failed calls must close their pair as `error`, not leave it open |

[`probe_hook.py`](probe_hook.py) is a command hook that answers all four
by logging each event's **shape** — field names and JSON types — plus
four identifier fields. Tool inputs, results, prompts and paths are
recorded as type and size only, so the output can go into a run record
without redaction. It always exits 0: it never blocks a tool and never
changes one. Standard library only.

## Running it (≈10 minutes)

```bash
export PALIMPSESTS_PROBE_LOG=~/agent-hook-probe.jsonl
rm -f ~/agent-hook-probe.jsonl
```

Use an absolute path to `probe_hook.py` below. On Windows use `python`
instead of `python3`.

### Claude Code

Add to `~/.claude/settings.json` (merge with any `hooks` you already
have):

```json
{
  "hooks": {
    "PreToolUse":         [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /ABS/PATH/probe_hook.py --client claude-code" }] }],
    "PostToolUse":        [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /ABS/PATH/probe_hook.py --client claude-code" }] }],
    "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /ABS/PATH/probe_hook.py --client claude-code" }] }]
  }
}
```

Start Claude Code, run `/hooks` to confirm the three are registered, and
do one turn that reads a file, runs a command, and runs one command that
fails (a missing file is enough).

### Codex

Hooks are on by default in Codex 0.160.0. Put in `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /ABS/PATH/probe_hook.py --client codex" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "python3 /ABS/PATH/probe_hook.py --client codex" }] }]
  }
}
```

Restart Codex, then **open `/hooks` in an interactive session and trust
the new hooks** — Codex does not run a hook until it has been trusted,
and skips an untrusted one without a word. Then do the same turn: read,
run, run something that fails.

### Read the result

```bash
cat ~/agent-hook-probe.jsonl
```

Each line has `ids` (event, tool, call id, session) and `fields` (every
field's type). Paste the file, together with each client's `--version`.
If the file is empty, the hooks did not fire — check `/hooks` before
anything else.

**Remove the probe hooks afterwards.** They are harmless, but a hook you
forget about is one more thing that runs on every tool call.

## What comes next

The adapter: a `POST /v1/pala/hooks/claude` route in `palimpsests serve`
for HTTP hooks, and a `palimpsests-hook` command for clients that only
run command hooks (Codex). Both land the events as `TOOL_CALL` /
`TOOL_RESULT` marked `reported-by-client` — proof that the agent
reported a call and a result, and when; not that the tool ran.
