# Code review standards

Every change to Palimpsests — code **and** documentation — lands through a
pull request that a **non-author** approves before merge. `main` is protected:
green required checks plus one non-author approval are enforced, not just
requested. This document states how that review is conducted and what
"acceptable" means, so the bar is explicit rather than folkloric.

See also [CONTRIBUTING.md](../CONTRIBUTING.md) (contributor workflow) and
[GOVERNANCE.md](../GOVERNANCE.md) (who may merge).

## What a reviewer checks

A reviewer does not approve until each of these holds, or the PR explains why
it does not apply:

- **Tests ship with behavior.** New or changed behavior comes with tests;
  bug fixes come with a test that fails before the fix. Coverage must stay
  above the gate (statement ≥ 90%, branch ≥ 80%) — the CI `coverage` job
  enforces it, but the reviewer confirms the tests are *meaningful*, not
  coverage padding.
- **Lint is clean.** `ruff` (E/F/I/B/UP) passes; the reviewer does not
  hand-wave a lint failure through.
- **No new dependency without justification.** A new runtime dependency is
  called out in the PR and justified (why it's needed, why this one, license).
  Build/test-only additions are held to the same explanation, lighter bar.
- **Security-sensitive paths get extra scrutiny.** Changes touching the audit
  chain, key management, the crypto boundary, deserialization of untrusted
  input (KV-state, the PALA-1 codec), or the process/capability boundary are
  reviewed against [SECURITY.md](../SECURITY.md), [docs/THREAT_MODEL.md](THREAT_MODEL.md),
  and [docs/ASSURANCE-CASE.md](ASSURANCE-CASE.md). "Looks fine" is not a
  review of these paths.
- **Public surface is deliberate.** API or CLI changes are intentional and
  documented; wire-format and PALA-1 changes respect the freeze and the
  forward-compatibility discipline (§7.6), and reproduce the published test
  vectors.
- **Docs match the change.** User-facing behavior changes update the relevant
  docs in the same PR.

## Release artifacts

Changes that produce or affect released artifacts get one more check:

- **Byte-verification.** Files committed via tooling are confirmed
  byte-for-byte against the intended content before the PR is trusted.
- **Reproducible build stays reproducible.** The CI `reproducible-build` job
  must be green; a change that introduces build non-determinism is not
  acceptable (see [docs/REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md)).

## What "acceptable" means

Approval means the reviewer believes the change is correct, tested, within the
project's security and design boundaries, and free of known issues that would
argue against inclusion. A reviewer who is unsure asks rather than approves.
Disagreements are resolved on the merits per [GOVERNANCE.md](../GOVERNANCE.md);
"the author is confident" is not, by itself, grounds to merge.

## Scope discipline

Reviews judge the cumulative effect of a change, not each line in isolation.
A series of individually-small PRs that together alter a security boundary is
reviewed as the boundary change it is.
