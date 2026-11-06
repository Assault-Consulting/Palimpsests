# Palimpsests audit reporter for OpenCode

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

A dependency-free OpenCode plugin that reports every tool the client
executes to `palimpsests serve`, so the audit chain shows the tool loop
even when the model ran it in text.

## Why it exists

`palimpsests serve` records **structured** tool loops — calls it parsed
off the wire it mediated. When a client negotiates the loop in prose and
executes tools locally (OpenCode under its own system prompt does this
with every small local model tried; see
[ADR-0005](../../docs/adr/0005-text-mode-tool-loops-and-audit-visibility.md)),
the serve, correctly, records nothing — and the terminal shows both modes
identically. The serve now names that boundary in-chain (kind 10,
`TOOLS_OFFERED_NO_CALL`); this plugin is the constructive half: the
client reports what it ran.

## What lands on the chain

Each executed tool becomes a `TOOL_CALL` / `TOOL_RESULT` pair (profile
kinds 8/9) carrying **`EVT_SOURCE = reported-by-client`** — an
evidence-quality mark that keeps these records forever distinguishable
from ones the serve parsed from its own wire. The distinction is
honest, not decorative:

| Record | What the chain proves |
|---|---|
| wire-parsed pair (no `EVT_SOURCE`) | the runtime itself observed the dispatch and the returned result |
| reported pair (`EVT_SOURCE = 1`) | the client asserted a call and a result; the serve recorded the assertion, its digests, and when — **not** that the tool ran |

Arguments and outputs are sent to the serve, which stores **only their
digests** (`EVT_PAYLOAD_DIGEST`) — content never enters the log. A
reported result binds to its call by seq + hash exactly as wire-parsed
pairs do, so the reader's referential-integrity advisory applies to
both without caring about source.

## Status on OpenCode 1.18.x — read this before installing

Three maintainer traffic runs, recorded in
`docs/specs/pala-1/independent-runs/`; every run and every surface check
is also listed in [`../COMPATIBILITY.md`](../COMPATIBILITY.md):

| | run 1 (`opencode-traffic-1`) | run 2 (`opencode-traffic-2`) | run 3 (`traffic-0.14-opencode-3`) |
|---|---|---|---|
| versions | 1.18.25 → 1.18.31 | 1.18.31 | 1.18.31, `palimpsests` 0.13.1 |
| reported pairs on the chain | 0 | **1** — `read`, outcome `error`, bound by seq and hash | **6 and 6** in two ten-prompt sessions, none left without a result; **3 `ok`** in the second |
| `tool.execute.before` | no report arrived | **fired** (probe) | — |
| `tool.execute.after` | — | **did not fire** | — |
| path the result took | — | the `message.part.updated` fallback | — |

So on 1.18.31 **the plugin works, but not through its primary path**:
the call arrives from `tool.execute.before`, the result through the
fallback, and the pair lands correctly bound. Keep the fallback — it is
the only reason the result arrived. Run 3 shows the same path delivering
**successful** results as well as failed ones, with the real tool names
(`read`, `task`, `write`, `webfetch`).

Three limits, stated rather than generalised:

- **Without `PALIMPSESTS_SERVE_API_KEY` in the window OpenCode starts
  from, nothing is recorded, and nothing says so.** The plugin's posts are
  refused `401`, it logs the failure and lets the tool run, so the turn
  looks normal from the client's side. Measured in run 3; it is
  sufficient to produce run 1's zero, but whether it is what happened in
  run 1 cannot be established from run 1's record.
- **Small local models rarely call a tool.** In run 3 most prompts were
  answered with tool-call JSON as plain text, so no tool ran at all. That
  is a model floor, not a recording loss: in both ten-prompt sessions the
  chain carried one more tool than the client's own transcript showed (a
  sub-agent call inside `task`).
- **An external skills catalogue makes it worse.** OpenCode 1.18.31 loads
  skills from the user's home directory into its system prompt; in run 2
  the prompt grew from ~9.6k to ~16.6k characters and small models
  declined OpenCode's own tools. Run 3's second session, with the
  catalogue moved aside, produced 6 pairs, 3 of them `ok`. Upstream
  behaviour, not this plugin.

What works regardless of the client is the serve's own boundary record:
a `TOOLS_OFFERED_NO_CALL` event for every turn where tools were offered
and nothing structured came back (9 of 9 in run 1, 19 in run 2). That
path needs no plugin.

To see what fires on *your* version, run
[`probe-hooks.js`](probe-hooks.js) beside this plugin for five minutes:
it records which callbacks arrive, into a JSONL file, touching nothing
else.

## Install

Copy [`palimpsests-audit.js`](palimpsests-audit.js) into one of:

- `.opencode/plugins/` — this project only
- `~/.config/opencode/plugins/` — every project

No `package.json`, no dependencies. Then run the serve and point
OpenCode's provider at it as usual
(`palimpsests-serve --print-opencode-config`).

## For your coding agent — paste this

If an agent (OpenCode itself, or any other) is setting this up for you,
give it the block below verbatim. It says what to do and, just as
importantly, what not to claim.

```text
Install the Palimpsests audit reporter for OpenCode.

1. Copy `integrations/opencode/palimpsests-audit.js` from the
   Assault-Consulting/Palimpsests repository into `.opencode/plugins/`
   (project) or `~/.config/opencode/plugins/` (global). No package.json,
   no dependencies — do not run npm.
2. Start the serve: `pip install 'palimpsests[serve]' && palimpsests serve`
   (default http://127.0.0.1:11435). Point OpenCode's provider at it with
   `palimpsests-serve --print-opencode-config`.
3. If the serve runs with `--api-key`, export PALIMPSESTS_SERVE_API_KEY
   with the same value; export PALIMPSESTS_SERVE_URL only if the port
   differs from the default.
4. Run one short session, then check:
   `palimpsests pala export serve.pala | grep -c '"kind_name":"TOOL_CALL"'`
   should be > 0 and those lines carry `"source":1`.

Rules: the plugin never blocks or alters a tool; a failed report is logged
and the tool proceeds. Reported records prove that the client asserted a
call and a result — not that the tool ran. Do not describe this as
"tamper-proof tool execution" or "verified tool calls"; describe it as a
hash-chained record of what the client reported, marked as such.
```

## Configure

| Variable | Meaning | Default |
|---|---|---|
| `PALIMPSESTS_SERVE_URL` | base URL of the serve | `http://127.0.0.1:11435` |
| `PALIMPSESTS_SERVE_API_KEY` | bearer key when the serve runs with `--api-key` — the same variable the serve reads | unset |
| `PALIMPSESTS_AUDIT_REPORT` | `0` disables the plugin entirely | enabled |

## Contract

- **Never blocks, never alters.** A failed report is logged
  (`client.app.log`, service `palimpsests-audit`) and the tool proceeds.
  The audit layer records what it is told; it does not gate the client.
- **One result per call.** `tool.execute.before` reports the call;
  `tool.execute.after` reports the result. The plugin also watches
  `message.part.updated` for the tool part reaching `completed` or
  `error` and reports from there if the hook did not — whichever
  arrives first wins, the other is a no-op.
- **Abandonment is recorded as abandonment.** A call whose result never
  arrives stays pending on the serve and is written `cancelled` at serve
  shutdown. No outcome is ever invented.
- **Ordering is preserved.** A result report awaits its call report, so
  the serve sees the pair in order even if OpenCode's events race.

## Known upstream caveats (why the fallback path exists)

OpenCode's tool hooks have not behaved uniformly across versions:

- [anomalyco/opencode#25918](https://github.com/anomalyco/opencode/issues/25918)
  — `tool.execute.after` declared but not invoked in some releases.
- [anomalyco/opencode#27900](https://github.com/anomalyco/opencode/issues/27900)
  — on 1.15.x `after` fires for successful calls only; failures bypass
  it.

The `message.part.updated` fallback covers both. If neither path fires
for a call on your version, the chain still shows the call and a
`cancelled` result at serve shutdown — visible, not silent.

## Verify

```bash
palimpsests pala verify serve.pala        # the serve chain in the config dir; verifies without keys
palimpsests pala export serve.pala        # JSONL, one record per line
```

In the export, every `TOOL_CALL` / `TOOL_RESULT` line carries `source`
(`0` parsed-from-wire, `1` reported-by-client) and `source_name`, and
the decoded record exposes the same two fields (`DecodedRecord.source`
/ `source_name`). The `0` is stated, not implied: an absent
`EVT_SOURCE` tag on a kind 8/9 body *means* parsed-from-wire (profile
§3.1, r5), and the reader says so rather than leaving the field empty.
The raw tag `0x0011` is still visible in `body_tlvs` when present.

## Tested

`tests/test_opencode_plugin.py` drives the plugin under Node against a
live serve on a loopback port with the hook payloads OpenCode passes,
and asserts: two calls, two results (the duplicate did not land), every
record marked `reported-by-client`, results bound by seq + hash, `ok`
via the `after` hook and `error` via the fallback. That is a test of the
plugin's logic given the hooks; whether a given OpenCode version calls
those hooks at all is the question the status section above answers.
