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
- **We describe what a change does, not how revolutionary it is.** See the "Prior
  art & the gap we close" section of the README: the project's novelty is the
  *composition*, and it is stated honestly. Describe a change's effect plainly.

## Workflow

- **Python code lands via pull request — never a direct push to `main`.** Docs and
  bootstrap files are the only exception.
- Branch from `main`, open a PR, link an issue where one exists.
- CI must be green on all three platforms (macOS/Linux/Windows) before merge.
  Windows path-separator and absolute-path behavior differs from POSIX — do not
  assume a POSIX-only fix is complete.

## Building and running the tests

The test suite is public FLOSS (pytest) and runs with no model and no native
build — the level-3 scheduler is exercised against a fake backend.

```bash
python -m pip install -e ".[dev]"   # ruff (pinned), pytest, pytest-httpx, numpy
python -m pytest                     # the full suite
ruff check .                         # lint (E/F/I/B/UP, line length 100, py311)
```

The same suite runs in CI (`.github/workflows/ci.yml`) on macOS, Linux, and
Windows across Python 3.11 and 3.12. The `[native]` extra (the real
`LlamaCppBackend`) is deliberately **not** part of CI: it needs a GGUF model and
a build toolchain, and is validated separately on hardware.

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

## Reporting vulnerabilities

Please **do not** report security issues in public issues or pull requests. Use a
[private security advisory](https://github.com/Assault-Consulting/Palimpsests/security/advisories/new)
or the contact in **[SECURITY.md](SECURITY.md)**, which also describes the
disclosure process and the supported-versions policy. We aim to acknowledge a
report within a few business days and to agree a disclosure timeline with the
reporter.

## Licensing of contributions

Contributions are **inbound = outbound**: by contributing, you license your
work under the project's [Apache-2.0](LICENSE) license — the same license the
project ships under. The tree is single-licensed; see `REUSE.toml`. There is
**no CLA** — no copyright assignment and no separate agreement to sign.

Instead, we use the **Developer Certificate of Origin** (DCO,
<https://developercertificate.org>): a short, standard attestation that you
wrote the patch or otherwise have the right to submit it under the project's
license. You certify it by signing off your commits:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line — matching the
commit author, with a real name and a reachable email. That line is your DCO
certification. If you forget, `git commit --amend -s` fixes the latest commit
and `git rebase --signoff <base>` fixes a branch. Sign-off applies to
contributions from here on; it is not applied retroactively to history.

## Scope

Palimpsests core is a **library + CLI**, not an application. Desktop packaging,
GUI, and cloud-provider integrations are downstream consumers in separate repos,
not part of this one. PRs that pull application concerns into the core will be
redirected.
