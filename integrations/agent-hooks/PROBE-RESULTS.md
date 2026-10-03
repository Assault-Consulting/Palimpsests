# Agent hooks — probe results

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

**Date:** 2026-10-03 · **Clients:** Claude Code 2.1.288, Codex CLI 0.160.0
(both installed from npm) · **Probe:** [`probe_hook.py`](probe_hook.py)
at the commit that adds this file · **Run by:** Andrii Sparysh, with AI
assistance.

## Method

What is under test is the **hook surface** — which events fire and what
fields they carry — not a model. So each client ran against a scripted
stand-in model on a loopback port: Claude Code through
`ANTHROPIC_BASE_URL` (Messages API), Codex through a custom
`model_providers` entry (Responses API). The stand-in asks for one tool
call that succeeds (read a small file), then one that fails (read a file
that does not exist), then answers. The clients themselves planned
nothing — but they executed both tools and fired their hooks exactly as
they would for a real model, which is the part this run measures.

The probe logs field names and JSON types only. The one place content
was read is the Codex failure case below, on a harmless file, to answer
whether the failure is visible inside the result; it is quoted there.

## Claude Code 2.1.288

| Event | Fires | `tool_use_id` | Result |
|---|---|---|---|
| `PreToolUse` | yes, per call | present | — |
| `PostToolUse` | yes, on success | present, equal to the Pre event's | `tool_response`, **object** (`Read`: `{file, type}`) |
| `PostToolUseFailure` | yes, on failure | present, equal to the Pre event's | no `tool_response`; `error` (**string**) and `is_interrupt` (boolean) |

Every event also carries `session_id`, `prompt_id`, `cwd`,
`transcript_path`, `permission_mode` and `effort`; the two post-call
events add `duration_ms`. There is no field named `tool_output` — one
secondary source claimed there was.

**HTTP hooks.** Configured with `"type": "http"`, all four events arrive
as `POST` with the same JSON body and `Content-Type: application/json`.
A header such as `"Authorization": "Bearer $PALIMPSESTS_SERVE_API_KEY"`
is interpolated **only if the variable is listed in the hook's
`allowedEnvVars`**. Without that, the header arrives as `Bearer` with
nothing after it — no warning to the user, and since HTTP hooks never
block the agent, nothing else shows that every report is being refused.
With `"allowedEnvVars": ["PALIMPSESTS_SERVE_API_KEY"]` the key arrives on
all four events.

## Codex CLI 0.160.0

| Event | Fires | `tool_use_id` | Result |
|---|---|---|---|
| `PreToolUse` | yes, per call | present (the model's `call_id`) | — |
| `PostToolUse` | yes, **for success and failure alike** | present, equal to the Pre event's | `tool_response`, **string** — the command's output |
| `PostToolUseFailure` | not observed | — | — |

The model's `exec_command` tool reaches the hooks normalised: `tool_name`
is `Bash` and `tool_input` is `{command: …}`, the same shape Claude Code
uses. Every event also carries `session_id`, `turn_id`, `model`, `cwd`,
`transcript_path` and `permission_mode`.

**A failed call is not distinguishable from a successful one.** For the
missing file the `PostToolUse` result was
`cat: does-not-exist: No such file or directory\n`, for the existing one
`hello\n`: both plain strings, no exit code, no error field, no separate
event.

**Hooks need trust.** Hooks are enabled by default in 0.160.0 (feature
`hooks`, stable). But a newly added hook does not run until it has been
trusted — reviewed once in an interactive session with `/hooks`.
Untrusted hooks are skipped **silently**: the first run here executed
both tools and the probe recorded nothing. `codex exec
--dangerously-bypass-hook-trust` runs them for one invocation; it was
used for this probe, of our own hook, and is not something to recommend
to users.

## What this decides for the adapter

1. **The result field is `tool_response` on both clients.** Its type
   differs — an object on Claude Code, a string on Codex — so the
   adapter digests a canonical form, and the rule is stated in the
   profile.
2. **`tool_use_id` binds a result to its call on both clients.**
3. **A Claude Code failure closes its pair as `error`**, from
   `PostToolUseFailure`.
4. **A Codex result cannot be recorded as `ok`.** The hook does not say
   whether the call succeeded, and writing `ok` would put a claim on the
   chain that nothing supports. It needs an outcome that says the result
   was reported and its success is unknown — a decision for the profile,
   taken before the adapter is written.
5. **Two silent failures belong in the README and the surface
   checker:** a Claude Code HTTP hook without `allowedEnvVars` sends an
   empty bearer, and a Codex hook that was never trusted never runs.
   The serve should also say, in its own log, when the hook route
   receives an empty bearer.
