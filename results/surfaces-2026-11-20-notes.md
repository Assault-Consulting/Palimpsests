<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Notes on the surface checks of 2026-11-20

**Who and where.** Both reports of this date were produced by the AI assistant
that works on this repository with the maintainers (Claude), in its own
ephemeral Linux sandbox — a virtual machine (`Linux 6.18.44-fc-v726`), not a
machine of the team. They are evidence about the surfaces on that machine, as
every report is, and are labelled so that nobody mistakes them for a run on a
deployment.

**Why.** The Linux half of the surface check before 0.15. Since the check of
2026-11-14 everything that receives a client's reports has changed: the
reporting routes read the request body themselves (#391), a refused or
rejected report is recorded on the chain (#387, #389), the writer records its
own opening and closing (#384), and events derived from telemetry carry their
own source mark (#382).

**What was run.**

- `main` at `f9ed15f`, installed editable with the `[serve]` extra into a
  fresh virtual environment; Python 3.13.18.
- LiteLLM 1.110.2 with `mcp`; pydantic-ai-slim 2.71.0 with the OTLP/HTTP
  exporter 1.45.2; Claude Code 2.1.329 from npm, with no Anthropic account —
  the probe's stand-in model answers on a loopback port.
- `python scripts/check_surfaces.py litellm mcp claude-code otel --report results/`,
  twice.

**The first run: `surfaces-2026-11-20.md`, `claude-code` 🔴 RED — a checker
defect, not the surface.** The serve's status after the probe showed no hook
post at all on `/v1/pala/hooks/claude`: none accepted, none refused, none
rejected. The client had reached the stand-in model twice and had run its
tool. Its own debug log gave the reason:

> Mods and hooks you set up aren't running in this session […] This session
> can't read your organization's settings, so it isn't known whether your
> organization allows them. Hooks not running: PostToolUse,
> PostToolUseFailure, PreToolUse.

The checker had been started from inside a Claude Code session. That session
exports its state to its children — which session it is, whose organization,
that it is remote — and `_isolated_env` passed the whole environment on,
replacing only the home directory. The probe's own Claude Code inherited
those variables, took itself for part of the managed session and held every
hook. With the same client, the same commit and those variables removed, the
probe delivered one call and one result.

The checker is corrected in the same pull request: a probe's client no longer
inherits the variables of a client session the checker happens to run in
(`CLAUDECODE`, `CLAUDE_*`, `CCR_*`, `AI_AGENT`); what a probe sets for its own
client is still passed. The report is left as the checker wrote it.

**The second run: `surfaces-2026-11-20-2.md`.** Four probes, four 🟢 GREEN:
`/v1/pala/events` (LiteLLM, the MCP proxy) and `/v1/pala/hooks/claude`
(Claude Code's HTTP hooks) each with one call and one result marked
reported-by-client; `/v1/traces` (pydantic-ai through the stock exporter) with
one pair marked derived-from-telemetry — source 2, where the reports before
0.15 show source 1 (#382). Its `Machine:` line names `f9ed15f`: that is the
commit of the serve under test; the checker itself carried the correction
above, not yet committed.

**What the first run does say.** Not about the surface — but a user who starts
Claude Code where it cannot read its organization's settings will see the
same thing: hooks held, nothing posted, and nothing on the chain to show for
it. The serve cannot record a report that was never sent
(inference profile §3.4).

**Not covered.** The `opencode` probe was not run: OpenCode needs its own
model catalogue at startup, which this sandbox cannot reach. The
`/v1/pala/hooks/codex` route has no probe. Windows is not covered here at
all: that is the Windows run's to cover before the release.
