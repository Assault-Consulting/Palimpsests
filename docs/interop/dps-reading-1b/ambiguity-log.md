# Ambiguity log

Each entry gives the section, the readings, the reading chosen and why.

| # | Section | Readings | Chosen, and why |
|---|---|---|---|
| A-01 | AB `tests/cases.json`, binding cases: "every dimension is expected verified" | (a) every report dimension; (b) the binding dimensions | (b): `record_statements`, `action_binding`, `stage_order`, `authorisation_recheck`, `observed_results`, `rationale_provenance`, specification digests and statements (aggregated: failed > unavailable > not_checked), and `execution_state` attempted. |
| A-02 | AB cases, `standing` tuples | Field order not stated | `[stage_id, bounds.status, requests_recorded, max_requests, revocation]`, the report schema's order. |
| A-03 | AB "The verifier and its report", third bullet | One sentence lists the binding checks; no dimension is named for each | A wrong-kind or missing reference fails the dimension owning the relation (`recheck_ref` and a recheck's `request_ref` → `authorisation_recheck`; `attempt_ref` → `observed_results`); a duplicate `stage_id` → `stage_order`; the rest → `action_binding`. |
| A-04 | AB, `authorisation_recheck` | `not_checked` when no attempt is recorded, or when neither a recheck nor an attempt is | Neither a recheck nor an attempt. Only the base report's finding wording supports it. |
| A-05 | AB verifier, first bullet: "Where it cannot read them" | Which `representation.media_type` values are readable | `application/json` and `*+json`. |
| A-06 | AB: "each stage comes after the stages it names" | List order, time, or both; equal times allowed or not | Both; a time equal to the named stage's is allowed. |
| A-07 | AB report, `executed_specifications` | Order not fixed | Order of first attempt. |
| A-08 | AB "Rationale provenance" | What `later_supplemented` requires of `recorded_at` | Strictly after the outcome's time. |
| A-09 | AB verifier, first bullet | Statements compared with bytes that fail their digest, or not | Compared anyway. |
| A-10 | AB item 4: a rejection or escalation whose `core_ref` is `affirmation_record` | Allowed, or a mismatch | `record_statements` failed (an affirmation is an approval). No case exercises it. |
| A-11 | AB signature cases, defaults | What `time_basis` and `time_assurance` are expected when the case lists none | `stated_time` and `not_checked`, when the expected status and key state are verified. |
| A-12 | Signatures "The organisation's seal", `embedded_copy` | Its value when the attachment carries no copy | `not_checked`. |
| A-13 | Anchoring and signatures: "one reference (a key's, an authority's or a source's) to two entries" | One namespace for every reference, or one per collection | One per collection (keys, authorities, sources). |
| A-14 | Anchoring key states, with an independent timestamp | Which time is compared with `not_after` | `not_before` with the stated time; `not_after` with T when a timestamp covers the signature, else the stated time. |
| A-15 | Signatures, identity; the cases' `identity_reason` | The vocabulary is in neither the text nor the report schema | `not_held` (no document held), `not_read` (the document names a member twice), `none_read` (no actor read). |
| A-16 | AB W07, "byte for byte" | `findings` wording is not fixed by the text | Compared without `findings`. |
| A-17 | Signatures cases: bytes as received for documents given parsed | Not stated in signatures | Action binding's convention (compact JSON, UTF-8); the export's seal verified under it. |
| A-18 | AB item 5, the per-specification count | Whether requests under a standing approval count | Only requests resting on approvals or changes. |
| A-19 | AB item 7, "the seal ... beside this one" | Matched by `decision_id`, or by sealed digest | By sealed digest (changes, entry 11; G37). |
