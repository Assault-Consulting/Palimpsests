# OpenSSF Best Practices Badge — answer reference

A record of how each Best Practices criterion — **passing and silver** — was
answered for Palimpsests, with the one-line justification and the evidence in
the repo.
Kept so the submission can be re-checked or updated, and as supporting
material for grant/IP review (it shows a systematic security-and-quality
posture rather than a set of assertions).

Legend: **Met** = satisfied; **N/A** = not applicable (with reason);
**Unmet** = honestly not done (only ever on SUGGESTED criteria, which do
not block the passing badge).

## Basics

| Criterion | Status | Basis |
|---|---|---|
| description_good | Met | README describes the layered engine and its purpose. |
| interact | Met | README (access), GitHub Issues (feedback), CONTRIBUTING.md (contribute). |
| contribution | Met | CONTRIBUTING.md documents the workflow. |
| contribution_requirements | Met | CONTRIBUTING.md states ground rules + ruff coding standard. |
| floss_license | Met | Apache-2.0 (LICENSE). |
| floss_license_osi | Met | Apache-2.0 is OSI-approved. |
| license_location | Met | LICENSE in repo root. |
| documentation_basics | Met | README + docs/USAGE.md. |
| documentation_interface | Met | docs/USAGE.md documents CLI + Python API, inputs and outputs. |
| english | Met | All docs and comments in English; CONTRIBUTING.md requires it. |

## Change control

| Criterion | Status | Basis |
|---|---|---|
| repo_public | Met | Public GitHub repository. |
| repo_track | Met | Git tags v0.1.0 / v0.2.0 / v0.3.0. |
| repo_interim | Met | Full interim history via per-feature PRs, not release-only. |
| repo_distributed | Met | Git. |
| version_unique | Met | Unique SemVer per release. |
| version_semver | Met | SemVer (CHANGELOG.md). |
| release_notes | Met | CHANGELOG.md + GitHub Releases. |
| release_notes_vulns | N/A | No CVE-tagged vulnerabilities in the project's own outputs. |

## Reporting

| Criterion | Status | Basis |
|---|---|---|
| report_process | Met | Issues + SECURITY.md. |
| report_tracker | Met | GitHub Issues. |
| report_responses | Met | Young project; incoming reports acknowledged (no backlog). |
| enhancement_responses | Met | Few/no enhancement requests; addressed as they arrive. |
| report_archive | Met | GitHub Issues is a public, searchable archive. |
| vulnerability_report_process | Met | SECURITY.md publishes the private-disclosure procedure. |
| vulnerability_report_private | Met | GitHub private advisories + maintainer email. |
| vulnerability_report_response | Met | No reports in window; SECURITY.md commits to a few-business-day response. |

## Quality

| Criterion | Status | Basis |
|---|---|---|
| build | Met | PEP 517/518, hatchling; `python -m build`. |
| build_common_tools | Met | pip / build / hatchling. |
| build_floss_tools | Met | Entire build chain is FLOSS. |
| test | Met | pytest suite; run steps in CONTRIBUTING.md and CI. |
| test_invocation | Met | `python -m pytest` (standard Python). |
| test_most | Met | 86% statement coverage measured in CI (pytest-cov `coverage` job, gated at 80%). The one low module is the hardware-only ctypes backend (`llamacpp_backend.py`), validated on hardware per benchmarks/RUNBOOK.md, not CI. Branch coverage not yet gated. |
| test_continuous_integration | Met | CI on push/PR, 3 OS × py3.11/3.12. |
| test_policy | Met | CONTRIBUTING.md: tests ship with every behavioral change. |
| tests_are_added | Met | Each L3 feature landed with its own tests/test_native_*.py. |
| tests_documented_added | Met | Policy documented in CONTRIBUTING.md. |
| warnings | Met | ruff (E/F/I/B/UP), merge-blocking in CI. |
| warnings_fixed | Met | Lint failure blocks merge; main stays clean. |
| warnings_strict | Met | Curated strict ruleset, pinned + enforced (strict where practical). |

## Security

| Criterion | Status | Basis |
|---|---|---|
| know_secure_design | Met | OIDC no-secrets, SQLCipher + keychain, capability gating, denial-path tests. |
| know_common_errors | Met | Vulnerability classes mapped to implemented mitigations (SECURITY.md). |
| crypto_published | Met | SQLCipher/AES-256, TLS, OIDC, Sigstore — all published. |
| crypto_call | Met | Delegates to SQLCipher/keyring/httpx; no hand-rolled crypto. |
| crypto_floss | Met | All crypto deps are FLOSS. |
| crypto_keylength | Met | AES-256 default; no weak-length option exposed. |
| crypto_working | Met | No broken algorithms (no MD5/DES/RC4). |
| crypto_weaknesses | Met | No SHA-1-for-security; no SSH/CBC. |
| crypto_pfs | N/A | No key-agreement protocol implemented by the project. |
| crypto_password_storage | N/A | No external-user passwords stored (local library/CLI). |
| crypto_random | Met | Delegates to CSPRNGs (SQLCipher/keychain/TLS); no insecure RNG for security. |
| delivery_mitm | Met | HTTPS + Trusted Publishing (OIDC) + Sigstore attestations. |
| delivery_unsigned | Met | No hash fetched over plain HTTP and used unverified. |
| vulnerabilities_fixed_60_days | Met | No known medium/high vulnerabilities; Dependabot monitors. |
| vulnerabilities_critical_fixed | Met | No outstanding critical; documented response process. |
| no_leaked_credentials | Met | OIDC (no stored token); repo scanned — no credential files. |

## Analysis

| Criterion | Status | Basis |
|---|---|---|
| static_analysis | Met | Bandit SAST on src/, every push/PR (.github/workflows/sast.yml). |
| static_analysis_common_vulnerabilities | Met | Bandit targets common Python vulnerability patterns. |
| static_analysis_fixed | Met | Bandit is a merge-blocking gate; no outstanding medium/high. |
| static_analysis_often | Met | Runs on every push and PR. |
| dynamic_analysis | Met | Atheris (libFuzzer) coverage-guided fuzzing of the KV-state validator; per-change regression + nightly budget (.github/workflows/fuzz.yml). |
| dynamic_analysis_unsafe | N/A | Pure Python; no memory-unsafe code developed in-project. |
| dynamic_analysis_enable_assertions | Met | The fuzz harness runs the pure-Python validator under CPython with assertions enabled (no -O). |
| dynamic_analysis_fixed | Met | Validator hardened ahead of the harness (PR #49/#50); no outstanding fuzzer findings. |

## Silver

*Silver builds on the passing badge (which must be earned first) and adds the
criteria below; the same legend applies. Passing is answered in full above; the
one procedural item outstanding is `achieve_passing` — submit on
bestpractices.dev (project 13534) to obtain the passing badge, then complete the
Silver questionnaire. This section drafts those answers; the live questionnaire
is authoritative.*

### Prerequisite and project oversight

| Criterion | Status | Basis |
|---|---|---|
| achieve_passing | Pending | All passing criteria answered above; submit to obtain the badge before Silver can be granted. |
| dco | Met | CONTRIBUTING.md requires a DCO `Signed-off-by` on every commit (`git commit -s`), with amend/rebase recovery documented. |
| governance | Met | docs/GOVERNANCE.md — roles, merge rights, decision process. |
| code_of_conduct | Met | CODE_OF_CONDUCT.md in the repo root. |
| roles_responsibilities | Met | GOVERNANCE.md names maintainers and their responsibilities. |
| access_continuity | Met | Two maintainers with repository admin; continuity documented in GOVERNANCE.md. |
| bus_factor | Met | ≥ 2 maintainers: @andreysparish and @olksandrvertel-arch. |
| contributors_unassociated | Met | Two significant contributors who are **unassociated**: both are 50/50 co-owners of Assault Consulting, but neither is employed by nor paid by the other for contributions — independent judgement, not a shared-employer economic dependence. (35+ commits from the co-maintainer, including the hardware-isolation suite and the role of independent PALA-1 verifier.) |
| copyright_per_file | Met | Per-file `SPDX-FileCopyrightText` on every source file; REUSE-compliant (`reuse lint` green, 143/143). |
| license_per_file | Met | Per-file `SPDX-License-Identifier` on every source file (Apache-2.0; the two PALA-1 reference impls CC0-1.0); LICENSES/ complete. |

### Quality and review

| Criterion | Status | Basis |
|---|---|---|
| test_statement_coverage80 | Met | 87% statement coverage, gated at 80% in CI. (90% is a **Gold** criterion, not Silver — see Silver notes.) |
| test_policy_mandated | Met | CONTRIBUTING.md mandates tests with every behavioral change. |
| tests_documented_added | Met | Each feature landed with its own tests; visible in per-PR history. |
| two_person_review | Met | `main` is branch-protected: one **non-author** approval + green checks required before merge (GOVERNANCE.md) — genuine with two maintainers. |
| code_review_standards | Met | CONTRIBUTING.md + GOVERNANCE.md document the review requirement (non-author approval, green lint/tests/coverage) for every change, including documentation. |
| installation_common | Met | pip / PEP 517 build; standard install. |

### Security

| Criterion | Status | Basis |
|---|---|---|
| hardening | Met | Memory-safe language (Python) for all in-project code; the one memory-unsafe boundary — the llama.cpp C library — is isolated behind the optional `[native]` extra, and its untrusted-input surface (the KV-state validator guarding `load_state`) is coverage-guided fuzzed (Atheris). No hardcoded secrets: audit keys via OS keychain or explicit injection; the at-rest audit log is encrypted (SQLCipher/AES-256). Not a network service, so transport/hardening-header controls are N/A. |
| input_validation | Met | Untrusted persisted state validated before use (the magic-`PALKV1` KV-state validator; the PALA-1 codec bounds-checks every field and TLV). |
| crypto_algorithm_agility | Met | Published algorithms (AES-256-GCM, SHA-256); the PALA-1 wire format carries `format_version` with a frozen-field forward-compatibility discipline (§7.6). |
| static_analysis | Met | Bandit SAST, merge-blocking, on every push/PR. |
| dynamic_analysis | Met | Atheris coverage-guided fuzzing of the KV-state validator; per-change regression + nightly budget. |
| security_review | Met | Documented internal security review — docs/security/AUDIT-2026-07.md (manual review of the audit subsystem, key management, and process boundary; no injection, unsafe-deserialization, or weak-RNG findings), backed by docs/THREAT_MODEL.md and docs/ASSURANCE-CASE.md. |
| warnings_strict | Met | ruff gate; strict lint on every change. |
| vulnerability_report_credit | Met | SECURITY.md commits to crediting reporters in release notes (opt-out). |
| signed_releases | Met | Sigstore keyless signing + PEP 740 attestations on PyPI; SLSA Build L2 provenance. |
| hardened_site | Met | The project site (palimpsests.dev) is served over HTTPS. |
| require_2FA | Met | Both maintainers have GitHub 2FA enabled. *(Account-level setting — confirm in GitHub account/org settings before submitting.)* |

### Silver notes

- **Gold, not Silver — not claimed here.** Three criteria people associate with
  "high assurance" are **Gold**, and are deliberately not asserted: 90%
  statement coverage (Silver requires 80%; the project is at 87%), 80% **branch**
  coverage (only statement coverage is measured today), and reproducible builds.
  These are tracked for a later Gold pass rather than stretched now.
- **`contributors_unassociated`** is the one criterion a single-entity project
  usually cannot meet. It is met honestly here by two independent co-owners, not
  stretched. Were that ever to change, Silver would wait for a genuinely
  independent significant contributor — the external PALA-1 verification runs
  (docs/specs/pala-1/INDEPENDENT-VERIFICATION.md) are a natural channel for one.

## Notes

- **Unmet items are all SUGGESTED**, not required — they do not block the
  passing badge. They are recorded honestly rather than stretched, which is
  the same measurement discipline the project applies to performance claims
  (see docs/POSITIONING.md and docs/BENCHMARKING.md).
- **Dynamic analysis** landed in v0.4: an Atheris (libFuzzer) harness fuzzes
  the untrusted-input **KV-state validator** that guards `load_state` — the
  surface that becomes meaningful once real persisted blobs can reach it. It
  runs a short deterministic regression on every change and a budget nightly
  (`.github/workflows/fuzz.yml`). The C parser the validator guards is
  deliberately out of the harness's scope (it needs `[native]`, and proving
  the wrapper's parser is a separate boundary — see SECURITY.md).
- **Two-person review is now in effect.** With a co-maintainer
  ([@olksandrvertel-arch](https://github.com/olksandrvertel-arch)), `main`
  requires a **non-author** approval plus green checks before merge — the
  `two_person_review` criterion is genuinely met, not a solo-project
  limitation. Earlier releases (v0.1–v0.3, before the co-maintainer) were
  necessarily single-author; the current process is not.
