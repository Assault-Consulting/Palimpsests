### Fixed

- `scripts/check_surfaces.py`: a probe's client no longer inherits the
  variables of a client session the checker is started from. Run from inside a
  Claude Code session, the `claude-code` probe went RED with no hook post at
  all: the probe's own client took itself for part of that managed session and
  held every hook. The surface was intact.

### Documentation

- Surface check on Linux before 0.15 (`results/surfaces-2026-11-20-2.md`):
  LiteLLM 1.110.2, the MCP proxy, Claude Code 2.1.329 and pydantic-ai 2.71.0
  over OTLP, four GREEN. The first run of the day and its false RED are kept
  and explained in `results/surfaces-2026-11-20-notes.md`.
- Surface checks at the state being released (2026-11-22): Windows
  (`results/surfaces-2026-11-22.md`) — the MCP proxy, OpenCode 1.19.6 and
  OTLP GREEN; LiteLLM and Claude Code not checked there. Linux
  (`results/surfaces-2026-11-22-2.md`) — LiteLLM 1.110.2, the MCP proxy,
  Claude Code 2.1.329 and OTLP GREEN; OpenCode not checked there. Every
  surface is GREEN on at least one platform; **LiteLLM and Claude Code are
  unchecked on Windows in this release.**
