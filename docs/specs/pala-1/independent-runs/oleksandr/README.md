# Independent PALA-1 verification runs — oleksandr

The §11 exit test, run per `../../INDEPENDENT-VERIFICATION.md`. This directory is
the archived evidence; the result rows are in that document's §5.

- **Run #1** (spec `776aa15a`, 2026-08-03): chain/anchor axes reproduced
  independently; Merkle axis blocked (leaves absent); 2 spec defects filed.
- **Run #2** (spec `ce877e4`, 2026-08-04): Merkle axis reproduced independently
  after the maintainer published the leaves; both run-#1 defects confirmed
  resolved. Both axes now pass — PALA-1 meets the §11 exit criterion.

## Contents

- `verify.py` — a second PALA-1 implementation (Python, stdlib + `hashlib`
  only), written from `PALA-1.md`, both profile documents, and
  `test-vectors.json` **alone**. No reference code (`palaudit_ref.py`,
  `gen_vectors.py`, `src/palimpsests/audit/pala/`, the pala tests) was read
  while writing it, per the §1 contamination boundary.
- `ambiguity-log.md` — the two spec defects the run surfaced, each with exact
  §-citations. Per the protocol (§2/§4) every logged item is a spec text fix
  before v1.0 freeze.

## Result (summary; full rows in §5)

- **Core envelope §8 reproduced independently, byte-for-byte** (run #1): all 12
  `record_hash` values, `chain_head`, `chain_ok`/`record_count`/empty
  `breaks`–`gaps`–`violations`, `complete_to_anchor`, `anchor_head`,
  `merkle_leaf_count`, and all seven §8 mutation demos.
- **Merkle axis reproduced independently** (run #2): `merkle_tree_hash`
  recomputed from the 30 published leaf digests (`merkle.leaves`) per §4.3,
  matching the §8 value byte-for-byte and the record's own `MERKLE_TREE_HASH`
  TLV; the leaf-7 proof (depth 5) folds to that root. In run #1 this was blocked
  — the `MERKLE` record carries `body_len = 0` and the leaves were absent from
  every allowed file, so the root could only be echoed (a tautology). The
  maintainer then published the leaves.
- **Both run-#1 defects resolved** (see `ambiguity-log.md`): leaves published
  (Finding 1) and the `break`→`violation` prose aligned (Finding 2).

## Running

From the repository root:

```
python docs/specs/pala-1/independent-runs/oleksandr/verify.py
```

It reads `../../test-vectors.json` and prints a per-value verdict tagged
`REPRODUCED` / `TAUTOLOGY` / `UNVERIFIABLE`.

## Note for a future independent run

This is already-run evidence — effectively a worked answer. A *future* second
implementer taking the §1 eligibility condition should treat this directory the
way §1 treats the reference code: do not read `verify.py` before filling in your
own §5 row, or the run tests this file rather than the specification.
