<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Distribution — 2026-09

Snapshot taken 2026-09-06 11:26 UTC by `scripts/distribution_metrics.py`. Numbers are this month's observation from the named source; the trend is the diff against last month's note, never a claim inside one.

## PyPI

| Metric | Value | Source |
|---|---|---|
| downloads | unavailable — HTTP 403 | pypistats.org |
| releases on PyPI | 10 (latest 0.11.0, 2026-09-02) | pypi.org |

## GitHub

| Metric | Value | Source |
|---|---|---|
| stars / forks / watchers | 0 / 3 / 0 | api.github.com |
| open issues (incl. PRs) | 1 | api.github.com |
| views, 14 days | unavailable — GITHUB_TOKEN not set (traffic and inbound need it) | traffic API |
| clones, 14 days | unavailable — GITHUB_TOKEN not set (traffic and inbound need it) | traffic API |
| inbound, all time (non-team issues / PRs) | 0 / 10 — bakaev-rodion, satyamadhav9104, snowfreetrack, yinshang369 | api.github.com |

Repository description as shown to a visitor: *Layered local-LLM inference engine for agentic workloads: Ollama and llama.cpp behind one abstraction, context-memory (sink/window/evict + block retrieval), encrypted audit log. Native L3 serving layer in progress.*

## Hand-kept ledger

| What | Count | Items |
|---|---|---|
| listings (upstream docs, awesome-lists, registries) | 0 | — |
| external verifier runs on record | 3 | Turak — external verifier, run 5 + bridge runs B1/B2; Kurdybaylo — external verifier; Sharyar Naseem — Perl 5 verifier (fifth implementation, third external) |
| integrators (someone embedded an adapter) | 0 | — |
| publications / talks | 3 | draft-sparysh-pala-audit-00 (IETF I-D, posted 2026-09-03); Zenodo article (DOI 10.5281/zenodo.21978107); SSRN whitepaper |

## Not claimed

Downloads include mirrors and CI installs; stars are not users; traffic is 14 days, not the month. None of these is evidence of adoption — an integrator on the ledger or an external run on record is.

## Baseline note (first run, 2026-09-06)

Taken from a shared container: `pypistats.org` is not reachable from it,
and `api.github.com` rate-limits the shared address between calls — the
GitHub rows above were captured on the one call that answered; the
traffic rows need `GITHUB_TOKEN`. Rerun from a workstation to fill them:

    GITHUB_TOKEN=… python scripts/distribution_metrics.py --out results/distribution-2026-09.md

What this baseline says: **0 stars, 3 forks, 0 watchers** after ten
releases — the project has been built in public without being *seen*
in public, which is exactly the finding the distribution plan starts
from. **10 external pull requests from four logins** is inbound to be
looked at one by one: real contributions belong on the ledger as
integrators or verifiers; drive-by PRs do not count. Three external
verifier runs on record; no listings; no integrators. And the repository
description shown on GitHub still reads *"Native L3 serving layer in
progress"* — a visitor's first sentence, four releases out of date; the
cheapest item on the plan.
