# PALA-1 profile run (r9) — record (fill in)

Return this file together with your reader's source. The ambiguity log
is part of this record.

## Run metadata

| Field | Value |
|---|---|
| Date of run | |
| Revision read | Inference profile **r9** (tag `v0.15.0`) — *confirm that the SHA-256 of all six inputs matched the digests in `PROFILE-R9.md` §P1* |
| Implementer (name / handle) — *as it should appear in the public record* | |
| Contact (email or GitHub) — *published with the record unless you write "do not publish"* | |
| Association with the project | *e.g. "None — no association; never seen the repository internals."* |
| Other reading | *What else you read about PALA-1, before or during the run — the website, a note, the Internet-Draft, nothing. It does not disqualify (kit README §1.3); list it.* |
| Eligibility attestation | *Confirm in your own words: you used only what kit README §1.1 and `PROFILE-R9.md` §P1 allow, and read nothing that kit README §1.2 lists — not the repository, the package, the documents next to the specification, earlier runs, or other people's implementations and reports.* |
| Core verifier used | *Your own from an earlier core run (name it), or written during this run.* |
| Method disclosure | *Language, approx. size, dependencies. State that RFC 8785 canonicalization is your own code.* |
| AI assistance | *"None", or: the tool and the model; that it worked under the same boundary; and whether the model's training could include this repository, public since 2026-07-06 — "ends before", "ends after" or "not known" (kit README §1.5).* |
| Time spent (optional) | |

## The pass bar — reproduced values

Mark each item **MATCH** or **DIVERGE**. For a divergence, give what your
reader computed and the `seq` or case id where it first differs.

| # | Item | Result | Computed (if diverged) |
|---|---|---|---|
| P1 | Core answers for the profile chain: `chain_ok`, 32 records, no breaks, gaps or violations, `chain_head`, complete against `anchor_head` | | |
| P2 | All 32 `record_hash` values; all 22 body digests | | |
| P3 | Three boots, beginning at `seq` 0, 24 and 27 | | |
| P4 | All 18 numbered `semantics` entries, field by field, from the body bytes | | |
| P5 | Every `ref_seq` / `ref_hash` pair names the record with that hash | | |
| P6 | `seq` 19: predecessor head equals `prev_hash`; prior root recomputed | | |
| P7 | Lifecycle check: no boot reported | | |
| P8 | Payload digests: 22 digested as published, 15 with no canonical form for the reason given | | |

For P4, list any entry or field that diverged:

| `seq` | Field | Published | Computed |
|---|---|---|---|
| | | | |

For P8, list any case that diverged:

| Case id | Published | Computed |
|---|---|---|
| | | |

## Cases you constructed (SHOULD — a run that skips them still passes)

| Case | Ran? | What your reader reported |
|---|---|---|
| `unclosed_boot` | | |
| `last_boot_unclosed` | | |
| `continuation_wrong_predecessor` | | |
| `unknown_kind` | | |

Cases of your own are worth describing.

## The rules in words

`semantics` holds five rules written as sentences. For each, say whether
it says the same as the profile's text.

| Rule | Agrees with the profile? | If not, where |
|---|---|---|
| `outcome_rule` | | |
| `continuation_rules` | | |
| `lifecycle_rule` | | |
| `reports_refused_rule` | | |
| `source_rule` | | |

## Ambiguity log

Every point where the profile's text made you stop and make a choice,
including in sections the vectors do not exercise. "None" is a valid and
valuable answer.

| # | Profile section | What was ambiguous | Your documented choice |
|---|---|---|---|
| | | | |

## Defects (if any)

Anything where you believe the profile or its vectors are internally
inconsistent, or where the profile contradicts the core.

| # | Location | Description |
|---|---|---|
| | | |

## Free-form notes (optional)

- 
