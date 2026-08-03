# Independent PALA-1 verification run — oleksandr, 2026-08-03

The §11 exit test, run per `../../INDEPENDENT-VERIFICATION.md`. This directory
is the archived evidence of one run; the result row is in that document's §5.

## Contents

- `verify.py` — a second PALA-1 implementation (Python, stdlib + `hashlib`
  only), written from `PALA-1.md`, both profile documents, and
  `test-vectors.json` **alone**. No reference code (`palaudit_ref.py`,
  `gen_vectors.py`, `src/palimpsests/audit/pala/`, the pala tests) was read
  while writing it, per the §1 contamination boundary.
- `ambiguity-log.md` — the two spec defects the run surfaced, each with exact
  §-citations. Per the protocol (§2/§4) every logged item is a spec text fix
  before v1.0 freeze.

## Result (summary; full row in §5)

- **Core envelope §8 reproduced independently, byte-for-byte:** all 12
  `record_hash` values, `chain_head`, `chain_ok`/`record_count`/empty
  `breaks`–`gaps`–`violations`, `complete_to_anchor`, `anchor_head`,
  `merkle_leaf_count`, and all seven §8 mutation demos.
- **Merkle axis NOT independently verifiable:** the `MERKLE` record carries
  `body_len = 0`, so the 30 leaf digests are absent from the container and from
  every allowed file. `merkle_tree_hash` can only be echoed from the record's
  own embedded TLV (a tautology, not a verification) and the leaf-7 inclusion
  proof cannot be checked. See defect 1.
- **Two spec defects filed** (see `ambiguity-log.md`).

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
