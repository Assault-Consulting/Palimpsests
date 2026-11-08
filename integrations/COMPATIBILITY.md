<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compatibility

Which client versions were checked against which integration, on what
machine, when, and with what result. **Generated** by
`scripts/build_compatibility.py` from the surface checker's dated reports
in `results/` and the real-traffic run records; do not edit by hand.

Read it as evidence, not as a promise. A row says what one check on one
machine showed on one date. ⚪ SKIP means the surface was not checked, and
🟠 ERROR means the checker failed; neither is a pass. How the checker
works and what its states mean: [`docs/SURFACE-CHECKER.md`](../docs/SURFACE-CHECKER.md).

## Surface checks

One probe per client, against a stand-in model: does the client's surface
still deliver a call and its result with the expected mark.

| Integration | Client version | Machine | Date | State | Checker's detail | Report |
|---|---|---|---|---|---|---|
| claude-code | 2.1.319 (Claude Code) | Linux 6.18.44-fc-v310, Python 3.12.3, palimpsests 0.13.1 (git 79d07c1) | 2026-11-08 | 🟢 GREEN [1] | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-08.md](../results/surfaces-2026-11-08.md) |
| litellm | 1.106.6 | Windows 11 10.0.26200, Python 3.12.10, palimpsests 0.13.1 | 2026-11-07 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-07.md](../results/surfaces-2026-11-07.md) |
| mcp | stdio / JSON-RPC 2.0 | Windows 11 10.0.26200, Python 3.12.10, palimpsests 0.13.1 | 2026-11-07 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-07.md](../results/surfaces-2026-11-07.md) |
| opencode | 1.18.31 | Windows 11 10.0.26200, Python 3.12.10, palimpsests 0.13.1 | 2026-11-07 | 🟢 GREEN | 1 call(s), 1 result(s), sources [0, 1]; not judged: 1 record(s) with source 0 | [surfaces-2026-11-07.md](../results/surfaces-2026-11-07.md) |
| claude-code | 2.1.310 (Claude Code) | Windows 11 10.0.26200, Python 3.12.10, palimpsests 0.13.1 | 2026-11-07 | ⚪ SKIP | not isolable on Windows yet — the client cannot be pointed at a temporary home without failing to start a turn; not evidence about the surface (see run R1 for a manual check) | [surfaces-2026-11-07.md](../results/surfaces-2026-11-07.md) |
| otel | pydantic-ai 2.64.0, otlp-http 1.45.2 | Windows 11 10.0.26200, Python 3.12.10, palimpsests 0.13.1 | 2026-11-07 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-07.md](../results/surfaces-2026-11-07.md) |
| litellm | 1.106.6 | Windows 11 Pro 10.0.26200, Python 3.12.10 | 2026-11-02 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-02.md](../results/surfaces-2026-11-02.md) |
| mcp | stdio / JSON-RPC 2.0 | Windows 11 Pro 10.0.26200, Python 3.12.10 | 2026-11-02 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-02.md](../results/surfaces-2026-11-02.md) |
| opencode | 1.18.31 | Windows 11 Pro 10.0.26200, Python 3.12.10 | 2026-11-02 | ⚪ SKIP [2] | the client never reached the serve (0 completions) — an environment problem on this machine, not evidence about the surface | [surfaces-2026-11-02.md](../results/surfaces-2026-11-02.md) |
| claude-code | 2.1.310 (Claude Code) | Windows 11 Pro 10.0.26200, Python 3.12.10 | 2026-11-02 | 🔴 RED [3] | 0 call(s), 0 result(s), sources [] | [surfaces-2026-11-02.md](../results/surfaces-2026-11-02.md) |
| otel | pydantic-ai 2.64.0, otlp-http 1.45.2 | Windows 11 Pro 10.0.26200, Python 3.12.10 | 2026-11-02 | 🟢 GREEN | 1 call(s), 1 result(s), sources [1] | [surfaces-2026-11-02.md](../results/surfaces-2026-11-02.md) |

Notes on rows above, from the run's own notes file:

1. run by the AI assistant in its own Linux sandbox VM, not on a machine of the team; one probe only. Source: results/surfaces-2026-11-08-notes.md
2. checker defect, not the surface: on Windows the probe's temporary home was ignored (USERPROFILE), and the verdict demanded that every record carry source 1, which this probe cannot meet. Fixed in #332. Source: results/surfaces-2026-11-02-notes.md
3. checker defect, not the surface: on Windows the probe ran against the user's real settings, not its own. Fixed in #332, where this probe is SKIP on Windows. Source: results/surfaces-2026-11-02-notes.md

## Real traffic

A real client and a real model, on one machine, with what reached the
chain and what did not. Each record states its own limits.

| Integration | Client | Machine | Date | Palimpsests | What reached the chain | Record |
|---|---|---|---|---|---|---|
| claude-code | Claude Code 2.1.310 | Windows 11 Pro 10.0.26200 | 2026-10-26 | 0.13.0 | 11 reported pairs, ok and error; 4 of 26 hook posts refused for an empty bearer, cause not established | [traffic-0.14-r1-claude-code](../docs/specs/pala-1/independent-runs/traffic-0.14-r1-claude-code/RUN-RECORD.md) |
| codex | codex-cli 0.164.0 | Windows 11 Pro 10.0.26200 | 2026-10-26 | 0.13.0 | 13 reported pairs, all unobserved; none before the hooks were trusted | [traffic-0.14-r2-codex](../docs/specs/pala-1/independent-runs/traffic-0.14-r2-codex/RUN-RECORD.md) |
| otel | pydantic-ai-slim 2.61.0, OTLP/HTTP exporter 1.45.1 | Windows 11 Pro 10.0.26200 | 2026-10-26 | 0.13.0 | 3 pairs per run, ok and error, on a local model | [traffic-0.14-r3-opentelemetry](../docs/specs/pala-1/independent-runs/traffic-0.14-r3-opentelemetry/RUN-RECORD.md) |
| litellm | litellm 1.106.4 (with mcp 2.3.0) | Windows 11 Pro 10.0.26200 | 2026-10-26 | 0.13.0 | 10 reported pairs, all unobserved, on a local model | [traffic-0.14-r4-litellm](../docs/specs/pala-1/independent-runs/traffic-0.14-r4-litellm/RUN-RECORD.md) |
| mcp | Claude Code 2.1.310 through the stdio proxy | Windows 11 Pro 10.0.26200 | 2026-10-26 | 0.13.0 | 11 reported pairs with the real tool names; the server's isError recorded as error | [traffic-0.14-r5-mcp](../docs/specs/pala-1/independent-runs/traffic-0.14-r5-mcp/RUN-RECORD.md) |
| opencode | OpenCode 1.18.31 | Windows 11 Pro 10.0.26200 | 2026-11-02 | 0.13.1 | 6 and 6 pairs in two ten-prompt sessions, none left without a result, 3 ok in the second; without the serve key, 401 and nothing recorded | [traffic-0.14-opencode-3](../docs/specs/pala-1/independent-runs/traffic-0.14-opencode-3/RUN-RECORD.md) |
| opencode | OpenCode 1.18.31 | Windows 11 Pro 10.0.26200 | recorded 2026-09-22 | 0.11.0 (unreleased main) | 1 reported pair, a failed read, through the message.part.updated fallback | [opencode-traffic-2](../docs/specs/pala-1/independent-runs/opencode-traffic-2/RUN-RECORD.md) |
| opencode | OpenCode 1.18.25 to 1.18.31 | Windows 11 Pro 10.0.26200 | recorded 2026-09-17 | 0.11.0 (unreleased main) | no reported pair reached the chain | [opencode-traffic-1](../docs/specs/pala-1/independent-runs/opencode-traffic-1/RUN-RECORD.md) |
