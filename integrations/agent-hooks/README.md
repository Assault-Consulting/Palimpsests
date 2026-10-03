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

## Claude Code — recording the tool loop

`palimpsests serve` accepts Claude Code's hooks directly: the route
`POST /v1/pala/hooks/claude` takes `PreToolUse`, `PostToolUse` and
`PostToolUseFailure` as Claude Code sends them, and writes each call and
its result as `TOOL_CALL` / `TOOL_RESULT` marked `reported-by-client`.
No script runs on your side — Claude Code posts the event itself.

1. Run the serve with a key:

   ```bash
   export PALIMPSESTS_SERVE_API_KEY=sk-…        # any secret of your choosing
   palimpsests-serve --api-key "$PALIMPSESTS_SERVE_API_KEY"
   ```

2. Add to `~/.claude/settings.json` (merge with any `hooks` you have),
   and start Claude Code from a shell where the same variable is set:

   ```json
   {
     "hooks": {
       "PreToolUse":         [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }],
       "PostToolUse":        [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }],
       "PostToolUseFailure": [{ "matcher": "*", "hooks": [{ "type": "http", "url": "http://127.0.0.1:11435/v1/pala/hooks/claude", "headers": { "Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY" }, "allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"] }] }]
     }
   }
   ```

   **`allowedEnvVars` is not optional.** Claude Code fills `$VAR` in a
   header only for variables listed there; for any other it sends an
   empty value, says nothing, and — since a hook never blocks the agent —
   every report is refused while the agent works normally. The serve
   names this case in its own log: `hook report refused: empty bearer`.

3. Check the chain:

   ```bash
   palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_'
   ```

   Every line carries `"source": 1`, `"source_name": "reported-by-client"`.

**What lands, and what it proves.** The call's input and the result
are digested — JSON with sorted keys, compact, UTF-8, SHA-256, the
profile's canonical form — and only the digests are written; content
never enters the chain. A failed call (`PostToolUseFailure`) closes its
pair as `error`. A result whose call the serve never saw is recorded as
a call followed by its result, so nothing is left unpaired. The chain
proves that Claude Code reported a call and a result, and when — not
that the tool ran.

**Contract.** The route never blocks a tool and never changes one:
every reply carries no decision. Other hook events (prompts, sessions)
are accepted and ignored. Re-delivered events do not create duplicates.

**Where the record lives.** On the machine running the serve, which is
the machine running the agent — wherever the model itself runs.

**Watched by** the `claude-code` probe in `scripts/check_surfaces.py`:
the real client, a stand-in model, these exact hook settings. It goes
red if either side of the arrangement changes.

## Codex

Codex sends the same hook shape, but only as a command hook, and a
failed call reaches the hook exactly like a successful one
([probe results](PROBE-RESULTS.md)). Its adapter waits on how such a
result is recorded: not as `ok`, which nothing in the hook supports.
