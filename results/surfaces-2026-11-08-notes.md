<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Notes on the surface check of 2026-11-08

**Who and where.** This report was produced by the AI assistant that works on
this repository with the maintainers (Claude), in its own ephemeral Linux
sandbox — a virtual machine (`Linux 6.18.44-fc-v310`), not a machine of the
team. It is evidence about the surface on that machine, as every report is,
and it is labelled so that nobody mistakes it for a run on a deployment.

**Why.** On Windows the `claude-code` probe is SKIP by construction (#332): the
client cannot be pointed at a temporary home there. The 2026-11-07 Windows
report (#344) tried WSL, which had no Linux distribution with Python or Node.
This run supplies the probe's real verdict on Linux.

**What was run.**

- `main` at `79d07c1` (after #345), installed editable with the `[serve]`
  extra; Python 3.12.3.
- Claude Code 2.1.319, installed from npm into the sandbox for this run; no
  Anthropic account — the probe's stand-in model answers on a loopback port.
- `python3 scripts/check_surfaces.py claude-code --report results/` — one
  probe only; exit status 0.

**Result.** 🟢 GREEN — one call and one result, both marked
reported-by-client, through the HTTP hooks the README configures.

**Not covered.** The other four probes were not run here; their latest
verdicts are in `surfaces-2026-11-07.md` (Windows). The checker and the
adapters are unchanged by this run.
