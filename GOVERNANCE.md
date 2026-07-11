# Governance

How decisions are made on Palimpsests, and who makes them. Short on
purpose, and honest about scale: this is a small, commercially-backed
open-source project, and the governance described here is the real one —
not a committee structure it does not have.

This document covers the **core library + CLI** in this repository.
Downstream consumers (desktop packaging, GUI, cloud integrations) live in
separate repositories and are governed there.

## Stewardship

Palimpsests is developed and maintained by **Assault Consulting** (Kyiv).
It is free and open-source under **Apache-2.0**. The commercial entity
behind the project is stated plainly rather than obscured; where a
commercial interest and the open-source project could diverge, the
boundary is kept explicit (see *Scope* in
[CONTRIBUTING.md](CONTRIBUTING.md)).

The project is maintainer-led. Authority rests with the maintainers, and a
**lead maintainer** holds the final decision — the honest model for a team
this size.

## Roles

- **Users** — anyone using the library or CLI. Open issues, request
  features, ask questions.
- **Contributors** — anyone who opens a pull request or issue. No formal
  status is required; start with [CONTRIBUTING.md](CONTRIBUTING.md).
- **Maintainers** — hold merge rights. They review pull requests, cut
  releases, and triage security reports. The project currently has a lead
  maintainer and one co-maintainer (who also runs the hardware
  benchmarks).
- **Lead maintainer** — final decision authority on architecture, scope,
  and releases, and steward of the project's stated boundaries.

## Becoming a maintainer

By sustained, quality contribution and demonstrated alignment with the
project's boundaries — the three-level abstraction, the no-kernel rule,
and the honest-claims discipline (describe what a change *does*, not how
revolutionary it is). New maintainers are invited by existing maintainers.
On a team this small this is a matter of trust, not a quota.

## How decisions are made

- **Lazy consensus.** For most changes, a proposal (an issue or PR) with no
  sustained objection proceeds. Disagreement is worked out in discussion;
  if it cannot be resolved, the lead maintainer decides.
- **Architecture and scope.** Decisions that touch the load-bearing
  abstraction are recorded as ADRs in [`docs/adr/`](docs/adr/). Two
  constraints are settled and are not re-litigated per PR: **no attention-
  kernel modification**, and **the core is a library + CLI, not an
  application** (both in [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Code review.** Python code lands via pull request with CI green on all
  three platforms; docs and bootstrap files may land directly. As a small
  team, a change may be authored and reviewed within a narrow group — a
  structural limit of a one-/two-person maintainer team that is
  acknowledged openly (see [`docs/BADGE-STATUS.md`](docs/BADGE-STATUS.md)),
  not misrepresented.

## Decisions that need special care

- **Security.** Vulnerabilities are reported privately per
  [SECURITY.md](SECURITY.md) and handled by the maintainers, who agree a
  disclosure timeline with the reporter. The supported-versions policy is
  in SECURITY.md.
- **Releases.** A release is cut by a maintainer following
  [RELEASING.md](RELEASING.md). Artifact provenance is automated (PyPI
  Trusted Publishing + Sigstore); pushing the version tag is the
  maintainer's authenticated action and the point of release authority.
- **Project boundaries.** The stated commitments — no kernel changes, no
  overclaiming, library scope — are governance-level. Changing any of them
  is a lead-maintainer decision, documented here or in an ADR.

## Licensing of contributions

Inbound equals outbound: contributions are licensed under the project's
**Apache-2.0** license. The tree is single-licensed (`REUSE.toml`). **There
is no CLA** — by contributing you license your work under Apache-2.0
([CONTRIBUTING.md](CONTRIBUTING.md)).

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to all project spaces and
is enforced by the maintainers.

## Funding and independence

The project is backed by Assault Consulting. No external sponsor directs
the roadmap. Priorities are set by the maintainers in the open (issues,
`docs/ROADMAP.md`).

## Changing this document

Governance changes are made by pull request like any documentation change,
and are a lead-maintainer decision. Material changes are noted in
[CHANGELOG.md](CHANGELOG.md).
