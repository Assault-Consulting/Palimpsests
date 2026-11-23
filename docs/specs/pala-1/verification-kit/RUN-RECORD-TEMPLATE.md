# PALA-1 verification run — record (fill in)

Return this file together with your verifier source. The ambiguity log
is part of this record.

## Run metadata

| Field | Value |
|---|---|
| Date of run | |
| Spec version verified | PALA-1 v1.0 (tag `pala1-v1.0`) — *confirm that the SHA-256 of all four inputs matched the digests in the kit README §1.6* |
| Implementer (name / handle) — *as it should appear in the public record* | |
| Contact (email or GitHub) — *published with the record unless you write "do not publish"* | |
| Association with the project | *e.g. "None — no association; never seen the repository internals."* |
| Other reading | *What else you read about PALA-1, before or during the run — the website, a note, the Internet-Draft, nothing. It does not disqualify (kit README §1.3); list it.* |
| Eligibility attestation | *Confirm in your own words: you used only what kit README §1.1 allows, and read nothing that §1.2 lists — not the repository, the package, the documents next to the specification, earlier runs, or other people's implementations and reports.* |
| Method disclosure | *Language, approx. size, dependencies (stdlib-only? optional crypto lib for the §4.4 extra?).* |
| AI assistance | *"None", or: the tool and the model; that it worked under the same boundary (no repository, no search for other implementations); and whether the model's training could include this repository, public since 2026-07-06 — "ends before", "ends after" or "not known" (kit README §1.5).* |
| Time spent (optional) | |

## §8 Expected results — reproduced values

Mark each value **MATCH** or **DIVERGE**. For a divergence, give the
value your verifier computed, minimized to the first differing byte
where possible.

| # | Value | Result | Computed (if diverged) |
|---|---|---|---|
| 1 | `chain_head` | | |
| 2 | `chain_ok` | | |
| 3 | `record_count` | | |
| 4 | `breaks` (empty) | | |
| 5 | `gaps` (empty) | | |
| 6 | `violations` (empty) | | |
| 7 | `complete_to_anchor` (against the top-level `anchor_head` of `test-vectors.json`) | | |
| 8 | `anchor_head` | | |
| 9 | `merkle_tree_hash` (recomputed from `merkle.leaves`, not echoed from the record TLV) | | |
| 10 | `merkle_leaf_count` | | |
| 11 | Leaf-7 inclusion proof (length 5) verifies against the recomputed root | | |

Extras beyond the pass bar (optional, note what you ran): per-record
`record_hash` recomputation, `body_digest` checks, §4.4 decryption of
the seq-3 body to the published plaintext.

## §8 Mutation demos (SHOULD — a run that skips them still passes; fill in what you ran)

| Demo | Ran? | Diagnosis matched the spec's promise? |
|---|---|---|
| `body_bitflip` | | |
| `unknown_record_type` | | |
| `tail_truncation` | | |
| `stale_anchor` | | |
| `seq_gap` | | |
| `missing_genesis` | | |
| `unknown_time_with_clock` | | |

Demo inputs you constructed differently from (or more aggressively
than) the published ones are worth describing — a prior run's strongest
finding came from exactly that.

## Ambiguity log

Every point where the specification text made you stop and make a
choice. "None" is a valid and valuable answer. For each item: the
section, what was unclear, and the documented choice you made.

| # | Spec section | What was ambiguous | Your documented choice |
|---|---|---|---|
| | | | |

## Defects (if any)

Anything where you believe the specification or the vectors are
internally inconsistent — a value that cannot be reproduced as
published, a contradiction between sections, a demo that encodes
something other than what its prose claims.

| # | Location | Description |
|---|---|---|
| | | |

## Free-form notes (optional)

- 
