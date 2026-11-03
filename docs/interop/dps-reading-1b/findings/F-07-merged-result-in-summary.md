# F-07 — Lemonnier repository: a merged result in `summary.json`

For: `Laurent-Lemonnier/dps-scitt-decision-layer`. Not filed.

**Minimised:** `interop/aqta/approval-record/out/summary.json`, member `all_verified: true`.

**At fault:** the example.

**Draft:**
`all_verified` merges the DPS dimensions (`dps_action_binding`, `dps_person_approval`, `dps_trust_policy`) with checks outside the extensions (`policy_checks`, `section_8_2_properties`, `seal_action_record`). The extensions' reports keep every dimension separate and have no overall result. The summary is not a report under their schemas, but a reader may take `all_verified` as one. Proposed: drop it, or rename it so it does not read as a verdict.
