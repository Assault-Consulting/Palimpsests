# OpenSSF Best Practices Badge — answer reference

A record of how each Best Practices (passing) criterion was answered for
Palimpsests, with the one-line justification and the evidence in the repo.
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
- **Solo-project structural limits** (e.g. human code review before merge)
  are inherent to a one-person team and are not misrepresented.
