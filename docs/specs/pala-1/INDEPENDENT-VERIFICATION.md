# PALA-1 independent verification — test protocol

The exit test of the specification (core, §11): **a second implementation,
written by someone who has not read the reference code, reproduces the §8
hashes from the specification text and the test vectors alone.** This
document pre-registers how that test is run, before it is run, so the
eventual result is evidence rather than anecdote — the same discipline the
project applies to benchmarks (`docs/BENCHMARKING.md`, Rule 0).

| | |
|---|---|
| **Tests** | `PALA-1.md` at the commit recorded in §5 below |
| **Status** | **Registered, not yet run.** §5 is filled in when it is. |
| **Implementer** | The co-maintainer, who attests to the eligibility condition in §1. Merging pull requests without reading the changed files' contents does not disqualify. |

## 1. Eligibility and the contamination boundary

The implementer MUST NOT have read, and MUST NOT read until §5 is filled
in:

- `docs/specs/pala-1/palaudit_ref.py` and `gen_vectors.py`
- `src/palimpsests/audit/pala/` — `codec.py`, `merkle.py`, `verify.py`,
  `bodies.py`
- `tests/test_pala_codec.py`, `test_pala_bodies.py`,
  `test_pala_differential.py`, `test_pala_cli.py`
- pull-request diffs or discussions quoting those files

Reviewing code that merely *calls* the codec (a future writer's call
sites) does not reveal the wire layout and is not forbidden — but the
cheap way to keep the boundary clean is to run this test **before**
Phase 3 lands, and that is the plan of record.

## 2. Allowed inputs

`PALA-1.md`, the profile documents under `profiles/`, and
`test-vectors.json`. Nothing else from this repository. Public external
references the specification itself cites (RFC 2119, RFC 6962, RFC 3161,
AES-GCM) are allowed.

**Questions are logged, not answered.** If the text is ambiguous, the
implementer records the ambiguity and makes a documented choice; the
authors do not clarify out-of-band. Every logged ambiguity is a
specification defect by the spec's own standard ("where the prose is
ambiguous, the specification is defective — not the implementer") and is
fixed in the spec text afterwards, before freeze. Out-of-band answers
would test the conversation, not the document.

## 3. The task

In any language, with no code from this repository:

1. Build the §2.4 file container from `test-vectors.json` (concatenate
   `header_hex` and, where present, `body_hex`).
2. Implement §7.1 header-only verification and §7.2 completeness.
3. Implement the §4.3 Merkle tree (either construction).
4. Reproduce, from that container, every value in the §8 **Expected
   results** block: `chain_head`, `chain_ok` / `record_count` / empty
   `breaks`–`gaps`–`violations`, `complete_to_anchor` against the
   published head, `anchor_head`, `merkle_tree_hash`,
   `merkle_leaf_count`, and a verifying inclusion proof for leaf 7 of
   length 5.

Reproducing the §8 mutation demos (bitflip, truncation, gap, stale
anchor…) is a SHOULD: each one exercises a diagnosis the format
promises, but the pass bar is the Expected-results block.

## 4. Outcomes

- **Every value matches** — the test has passed; §5 is filled in, and the
  result becomes citable evidence when Draft status is lifted at v1.0.
  Passing does not by itself lift Draft: the field set may still change
  for the writer's needs, and the test is re-run (cheaply, the verifier
  exists by then) against the freeze candidate if the wire format changed
  after the run.
- **A value diverges** — the second implementation is wrong, or the
  specification is (§8's own words). The divergence is minimized to the
  first differing byte and resolved; if the specification was at fault,
  the fix is a spec change logged like any other.
- **In both cases**, the ambiguity log from §2 is worked through: each
  entry becomes a spec clarification before freeze. An empty log is a
  strong result; a long log is a useful one.

## 5. Record of the run

*Filled in after the run; empty means not yet run.*

| | |
|---|---|
| Date | — |
| Spec commit tested | — |
| Verifier (link) | — |
| Result | — |
| Ambiguities logged | — |
