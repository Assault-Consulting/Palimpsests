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

## Install

Copy [`palimpsests-audit.js`](palimpsests-audit.js) into one of:

- `.opencode/plugins/` — this project only
- `~/.config/opencode/plugins/` — every project

No `package.json`, no dependencies. Then run the serve and point
OpenCode's provider at it as usual
(`palimpsests-serve --print-opencode-config`).

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

In the export, reported records are the `kind_name: TOOL_CALL` /
`TOOL_RESULT` lines whose `body_tlvs` include tag `0x0011` (`EVT_SOURCE`)
with value `0100` (u16 LE = 1). Wire-parsed pairs carry no `0x0011` tag
at all — absence is the default, by design (profile §3.1, r5). A named
`source` field in the reader's decoded records is not there yet; the
raw tag is the contract.

## Tested

`tests/test_opencode_plugin.py` drives the plugin under Node against a
live serve on a loopback port with the hook payloads OpenCode passes,
and asserts: two calls, two results (the duplicate did not land), every
record marked `reported-by-client`, results bound by seq + hash, `ok`
via the `after` hook and `error` via the fallback.
