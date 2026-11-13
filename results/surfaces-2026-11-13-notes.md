<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Notes on the surface check of 2026-11-13

**Who and where.** This report was produced by the AI assistant that works on
this repository with the maintainers (Claude), in its own ephemeral Linux
sandbox — a virtual machine (`Linux 6.18.44-fc-v445`), not a machine of the
team. It is evidence about the surfaces on that machine, as every report is,
and it is labelled so that nobody mistakes it for a run on a deployment.

**Why.** It is the surface check before the 0.14.1 release. Between 0.14.0
and this commit the serve's ingestion routes were refactored so that a
request can be a dry run (#354): `/v1/pala/hooks/claude`,
`/v1/pala/hooks/codex`, `/v1/pala/events` and `/v1/traces` now take the
request object and choose between the real recorder and one that writes
nothing. The unit tests cover that; this run sends real clients through the
refactored routes.

**What was run.**

- `main` at `7b81e29` (after #357 and #358), installed editable with the
  `[serve]` extra into a fresh virtual environment; Python 3.12.3.
- LiteLLM 1.109.1 with `mcp`; pydantic-ai-slim 2.68.0 with the OTLP/HTTP
  exporter 1.45.2; Claude Code 2.1.319 from npm, with no Anthropic account —
  the probe's stand-in model answers on a loopback port.
- `python scripts/check_surfaces.py litellm mcp claude-code otel --report results/`
  — exit status 0.

**Result.** Four probes, four 🟢 GREEN, each with one call and one result
marked reported-by-client: `/v1/pala/events` (LiteLLM, the MCP proxy),
`/v1/pala/hooks/claude` (Claude Code's HTTP hooks) and `/v1/traces`
(pydantic-ai through the stock exporter). The client versions are newer than
in the reports of 2026-11-07 and 2026-11-08.

**Not covered.** The `opencode` probe was not run: OpenCode needs its own
model catalogue at startup, which this sandbox cannot reach. The
`/v1/pala/hooks/codex` route has no probe yet (see
`integrations/agent-hooks/README.md`). Windows is not covered here at all.
Those are the Windows run's to cover before the release.
