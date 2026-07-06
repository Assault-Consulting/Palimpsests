# Contributing to Palimpsests

Early-stage but contributions are welcome. This document is short on purpose.

## Ground rules

- **Read [ARCHITECTURE.md](ARCHITECTURE.md) first.** The three-level model and the
  stateless/stateful split are load-bearing. A change that breaks the abstraction
  (e.g. leaking `isinstance` checks on engines) will be sent back regardless of
  how well it works.
- **We do not modify the attention kernel.** Everything lives as engine launch
  parameters, orchestration above the engine, or the native serving service. If a
  change needs kernel access, it does not belong here.
- **We do not claim novelty.** See the Prior art section of the README. Describe
  what a change does, not how revolutionary it is.

## Workflow

- **Python code lands via pull request — never a direct push to `main`.** Docs and
  bootstrap files are the only exception.
- Branch from `main`, open a PR, link an issue where one exists.
- CI must be green on all three platforms (macOS/Linux/Windows) before merge.
  Windows path-separator and absolute-path behavior differs from POSIX — do not
  assume a POSIX-only fix is complete.

## Code style

- **ruff** with `["E", "F", "I", "B", "UP"]`, line length **100**, target
  **py311**. Run `ruff check .` before pushing.
- **Type hints** on public functions. Comments in English.
- **pytest** for tests; `pytest-httpx` for HTTP-facing adapters. Prefer wire-level
  mocking over patching internals.
- **No SDK retry layers** in engine adapters — plain `httpx`, `max_retries=0`.
  Retry policy is a caller concern, not an adapter default.

## Tests

- Every behavioral change ships with tests in the same PR.
- Isolate global state: engines, registry, and the workspace singleton each get a
  reset fixture so no test bleeds into another.
- Path-safety and capability-gating code is security-sensitive — test the escape
  and denial paths explicitly, not just the happy path.

## Scope

Palimpsests core is a **library + CLI**, not an application. Desktop packaging,
GUI, and cloud-provider integrations are downstream consumers in separate repos,
not part of this one. PRs that pull application concerns into the core will be
redirected.
