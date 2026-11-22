<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Notes on the Linux surface check of 2026-11-22

**Who and where.** `surfaces-2026-11-22-2.md` was produced by the AI assistant
that works on this repository with the maintainers, in its own ephemeral Linux
sandbox — a virtual machine (`Linux 6.18.44-fc-v726`), not a machine of the
team. Same environment as the checks of 2026-11-20.

**Why a second Linux run.** The Windows check of the same day
(`surfaces-2026-11-22.md`) could not load LiteLLM on that machine and cannot
isolate Claude Code on Windows, so both verdicts for 0.15 rest on Linux. The
Linux check they rested on was taken at `f9ed15f`. Since then the serve's
start has changed (it now decides which segment of the chain to continue,
#393) and eighteen Python dependencies were raised (#400). This run repeats
the check at `09c6f59`, the commit the release is cut from unless something
else lands.

**What was run.**

- `main` at `09c6f59`, installed editable with the `[serve]` extra; Python
  3.13.18.
- LiteLLM 1.110.2; pydantic-ai-slim 2.71.0 with the OTLP/HTTP exporter 1.45.2;
  Claude Code 2.1.329 from npm, with no Anthropic account.
- `python scripts/check_surfaces.py --report results/`, once. Exit code 0.

**Result.** `litellm`, `mcp`, `claude-code`, `otel`: 🟢 GREEN.

**Not covered.** `opencode` is ⚪ SKIP: the client is not installed in this
sandbox. Its verdict for 0.15 is the GREEN on Windows in
`surfaces-2026-11-22.md` (OpenCode 1.19.6, `e44fe8f`). No Codex probe exists.

**Taken together, at the state being released.** Each of the five surfaces is
GREEN on at least one platform: `mcp` and `otel` on both, `opencode` on
Windows only, `litellm` and `claude-code` on Linux only. The two that are
unchecked on Windows are named in the release notes.
