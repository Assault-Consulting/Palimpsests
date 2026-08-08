# PALA-1 freeze-candidate run — record (fill in)

Return this file together with your verifier source and your ambiguity log.

## Run metadata

| Field | Value |
|---|---|
| Date of run | 2026-08-08 |
| Spec commit verified | `ff2720a` |
| Implementer (name / handle) | Vladyslav Kurdybaylo (v.kurdybailo@gmail.com) |
| Association with the project | None — no association with the project; never seen the repository or its internals. |
| Eligibility attestation | I have not read the reference implementations, the production codec, the codec tests, or any earlier run's verifier or logs, and will not until this record is submitted. Only the package files (`PALA-1.md`, `profiles/`, `test-vectors.json`, cover note) were used. |
| Verifier | `pala_verify.py`, Python 3.14, ~300 lines, stdlib only (optional `cryptography` for the §7.5 decryption extra) |
| Time spent (optional) | ~1.5 hours |

## §8 Expected results — reproduced values

Mark each value **MATCH** or **DIVERGE**. For a divergence, give the value
your verifier computed.

| # | Value | Result | Computed (if diverged) |
|---|---|---|---|
| 1 | `chain_head` | **MATCH** (`3a1a3673…7af813`) | |
| 2 | `chain_ok` | **MATCH** (true) | |
| 3 | `record_count` | **MATCH** (12) | |
| 4 | `breaks` (empty) | **MATCH** | |
| 5 | `gaps` (empty) | **MATCH** | |
| 6 | `violations` (empty) | **MATCH** | |
| 7 | `complete_to_anchor` (against published `anchor_head`) | **MATCH** (true) | |
| 8 | `anchor_head` | **MATCH** (== `chain_head`) | |
| 9 | `merkle_tree_hash` (independently recomputed from `merkle.leaves`) | **MATCH** (`518f5be5…f468db`; both §4.3 constructions — recursive RFC 6962 split and iterative promotion — agree, and the value equals the seq-4 record's `MERKLE_TREE_HASH` TLV) | |
| 10 | `merkle_leaf_count` | **MATCH** (30 leaves published == 30 in the record's `MERKLE_LEAF_COUNT` TLV) | |
| 11 | Leaf-7 inclusion proof (length 5) verifies against the recomputed root | **MATCH** (verifies) | |

Extras beyond the pass bar: every per-record `record_hash` in the vectors was
recomputed and matched; both bodies' `body_digest` values matched (§7.5); the
seq-3 body decrypted under §4.4 (derived nonce confirmed equal to
`4 zero bytes || seq LE`, AAD as specified) to exactly the published plaintext
`"clear path ahead, one pedestrian at 12m, static"`.

## §8 Mutation demos (SHOULD — fill in what you ran)

| Demo | Ran? | Diagnosis matched the spec's promise? |
|---|---|---|
| `body_bitflip` | yes | yes — `body_digest` mismatch detected, chain still verifies |
| `unknown_record_type` | yes | yes — `chain_ok=true`, `count=13`, `uninterpretable=[12]` |
| `tail_truncation` | yes | yes — `chain_ok=true` without anchor; with anchor: "names no record — replaced, rolled back, or truncated" |
| `stale_anchor` | yes | yes — `anchor_lag=3`, unanchored tail, not a replacement |
| `seq_gap` | yes | yes — `chain_ok=false`, `gaps=[99]`, `breaks=[]` |
| `missing_genesis` | yes | yes — `chain_ok=false`, `breaks=[]`, single violation "chain does not start with a GENESIS record" — **but only under the documented choice in ambiguity 1 / defect 1** |
| `unknown_time_with_clock` | yes | yes — `chain_ok=false`, violation at the appended record |

## Ambiguity log

Every point where the specification text made you stop and make a choice.
"None" is a valid and valuable answer. For each item: the section, what was
unclear, and the documented choice you made.

| # | Spec section | What was ambiguous | Your documented choice |
|---|---|---|---|
| 1 | §7.1 vs §4.2 | For a chain whose first record is not a `GENESIS`, the §7.1 pseudocode read literally produces **two** violations (not-GENESIS, `prev_hash != 0` at index 0) **and a break** at the first record's `seq` (initial `prev` is 32 zero bytes and the break check is unconditional). §4.2's prose says "the record is the wrong kind; **the links around it may be perfectly sound**", and the §8 `missing_genesis` demo publishes `breaks=[]` with a single violation. | Followed §4.2 prose + the published demo: at index 0 a non-GENESIS first record yields one violation and no break; the zero-`prev_hash` check applies only when the first record **is** a `GENESIS`. See Defect 1. |
| 2 | §7.1 | `breaks` and `gaps` are explicitly reported "at `h.seq`", but the pseudocode never says what keys a **violation**. The published demos use `[0, …]` for the chain-start violation (where the first record's `seq` is 1) and `[12, …]` for a per-record violation (where seq and index coincide). | Per-record violations keyed by `seq`; the chain-does-not-start-with-GENESIS violation reported at position 0 (it is a property of the chain, not of the record's `seq`). Reproduces both published demo outputs. |
| 3 | §4.3 / §8 | The inclusion-proof **entry format** (`["L", hash]` / `["R", hash]`) exists only in `test-vectors.json`; the spec text never defines what `L`/`R` mean. | Interpreted `"L"` as "sibling is the **left** operand of `node()`" (`node(sib, h)`), `"R"` as the right (`node(h, sib)`). The proof then verifies; the opposite reading does not. Worth one sentence in §4.3 before freeze. |

## Defects (if any)

Anything where you believe the specification or the vectors are internally
inconsistent — a value that cannot be reproduced as published, a
contradiction between sections, a demo that encodes something other than
what its prose claims.

| # | Location | Description |
|---|---|---|
| 1 | §7.1 pseudocode | Internally inconsistent with §4.2 and with the published `missing_genesis` demo (see Ambiguity 1). As written, `MUST h.prev_hash == 32 zero bytes else violation` at index 0 is unconditional, and the break check `if h.prev_hash != prev` also runs at index 0 against the zero initial `prev` — so a chain missing its `GENESIS` reports 2 violations + 1 break, while the demo publishes exactly 1 violation and `breaks=[]`. Fix before freeze: scope the zero-`prev_hash` check to `record_type == GENESIS`, and start the break check at index 1 (or initialise `prev` from the first record's own `prev_hash`). |

## Free-form notes (optional)

- The container, header layout, TLV rules, chain rules and Merkle sections were
  unambiguous in practice: every §8 value reproduced on the verifier's **first
  run**, including both Merkle constructions agreeing with each other, with the
  published root and with the record's own TLV.
- §2.3's warning about the nonce being *inside* `body_len` is well placed — the
  vector confirms it (`body_len=75 = 12 + 47 + 16`).
- Method disclosure: the verifier was implemented with the assistance of an AI
  coding agent (Claude), working strictly and only from the files in this
  package; no project code, tests, prior runs or repository content were read
  by either the implementer or the agent.
- Verifier source: `run/pala_verify.py`; machine-readable output: `run/results.json`
  (both returned alongside this record).
