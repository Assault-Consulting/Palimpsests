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
| **Status** | **Run #1 (2026-08-03) and Run #2 (2026-08-04) complete — see §5.** Both axes were reproduced from an independent implementation and both run-#1 defects were closed at `ce877e4`, so the §11 exit criterion is met. This does **not** lift Draft: Draft lifts at v1.0, tested against the freeze candidate (§4), for which a fresh external run (§6) is the strongest evidence. |
| **Implementer** | Runs #1–#2: the co-maintainer, who attests to the eligibility condition in §1 (merging pull requests without reading the changed files' contents does not disqualify). A future run by an unaffiliated external implementer follows §6. |

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
| Run | #1 — first independent run |
| Date | 2026-08-03 |
| Spec commit tested | `776aa15a` |
| Verifier (link) | [`independent-runs/oleksandr/verify.py`](independent-runs/oleksandr/verify.py) (Python, stdlib + `hashlib`; written from the spec text and vectors alone — see [`independent-runs/oleksandr/README.md`](independent-runs/oleksandr/README.md)) |
| Result | **PASS** (chain/completeness axes: 12 record hashes, `chain_head`, completeness, `anchor_head`, 7/7 mutation demos reproduced independently) · **BLOCKED** (Merkle axis: vectors incomplete, leaf digests absent, `body_len = 0`) · 2 defects filed. The chain and completeness axes are self-sufficient; the Merkle axis cannot be reproduced from the allowed files — `merkle_tree_hash` is only echoable from the record's own embedded TLV (tautology), and the leaf-7 inclusion proof is unverifiable without the leaf. |
| Ambiguities logged | **2** — see [`independent-runs/oleksandr/ambiguity-log.md`](independent-runs/oleksandr/ambiguity-log.md). **(1)** Merkle leaf digests absent from spec + vectors → §8 `merkle_tree_hash` / leaf-7 proof unreproducible independently; leaf capture-point itself undefined (robotics profile §6 issue 1); requires vector completion before freeze. **(2)** `break`-vs-`violation` contradiction: §4.2 and §7.1 pseudocode classify a chain whose first record is not `GENESIS` as a *break*, but §8 and `demos.missing_genesis` classify it as a *violation* (the §8 row even cross-references §4.2 while contradicting it); resolve to *violation*, align the prose before freeze. |

| | |
|---|---|
| Run | #2 — Merkle axis re-verification |
| Date | 2026-08-04 |
| Spec commit tested | `ce877e4` |
| Verifier (link) | [`independent-runs/oleksandr/verify.py`](independent-runs/oleksandr/verify.py) — Merkle section now recomputes from the published leaves (`mth` / `verify_inclusion` unchanged since run #1, written before the leaves existed). |
| Result | **Merkle axis PASS.** `merkle_tree_hash` **independently recomputed** from the 30 published leaf digests (`merkle.leaves`), matching the §8 value `518f5be5…d9f468db` byte-for-byte **and** the record's own `MERKLE_TREE_HASH` TLV (§8 requires both). The leaf-7 inclusion proof (depth 5) folds through the five published siblings to that independently computed root — verifies. `merkle_leaf_count = 30` matches (computed = vectors = record TLV). §4.3 is self-sufficient: domain bytes `0x00` (leaf) / `0x01` (node) explicit; unpaired node **promoted, never duplicated** (CVE-2012-2459); `MERKLE_LEAF_COUNT` is u32 **little-endian** (§2.1) — all read from the spec, none assumed. **0 new ambiguities.** Closes the Merkle **BLOCKED** from run #1 — the vectors were completed by the maintainer (`merkle.leaves` / `merkle.proof`), so the axis is now independently verifiable. |
| Defect status | Both run-#1 defects **resolved** at `ce877e4` (confirmed from the allowed `PALA-1.md` only). **(1)** Merkle leaves now published (Finding 1). **(2)** `break`→`violation` prose aligned in §4.2 ("MUST report as a violation…") and the §7.1 pseudocode ("…else violation"), matching §8 (Finding 2). With both axes now reproduced independently (chain/anchor run #1, Merkle run #2) and both defects closed, PALA-1 meets the §11 exit criterion. |

## 6. Conducting an external run

The runs on record are the co-maintainer's, which the §11 exit criterion
accepts. The strongest evidence for lifting Draft at freeze, though, is a
run by someone with **no association to the project** — it removes the
maintainer-in-the-loop question entirely. This section is only the
logistics of receiving such a run. It adds nothing to the task (§3) or the
boundary (§1–§2); it describes how an outsider is given the inputs and how
their result comes back.

1. **Eligibility (external).** As §1, applied to someone outside the
   project: they must not have seen the reference implementations, the
   codec, the tests, the verifiers from the runs already recorded, or any
   discussion quoting them. An outsider has no reason to have seen those,
   so the condition is easy to attest — and the package they receive
   (below) is assembled so they *cannot* reach them.

2. **The sealed input package — what they receive.** Only the allowed
   inputs of §2, copied out of the repository into a standalone folder:
   `PALA-1.md`, everything under `profiles/`, and `test-vectors.json`.
   Nothing else from the repository travels with them — not the reference
   implementations, not `src/`, not the tests, not the repository history.
   Extracting the inputs rather than granting repository access is the
   point: the boundary is enforced by what they hold, not by their
   restraint.

3. **What they must not be given.** No access to the source tree, the
   reference verifiers, the vector generator, or any channel where those
   are quoted. Treat the runs already recorded under `independent-runs/`
   as reference material for this purpose: a fresh run that reads an
   earlier verifier is testing that file, not the specification.

4. **The task and the ambiguity rule are unchanged.** They carry out §3
   and follow the §2 rule — questions are logged, not answered. The
   project does not clarify the text out of band for them either; a run
   that needed a private clarification would show only that the
   conversation was followable, which is not what is being tested.

5. **What they return.** Their verifier (in any language), the values they
   reproduced, and their ambiguity log — the same three things §5 records
   — together with their attestation of the eligibility condition above.
   Nothing about their internal method has to resemble ours; only the
   reproduced values have to agree.

6. **Recording it.** The submission lands as a new run row in §5 and a
   folder under `independent-runs/<name>/` beside the existing ones. From
   that point it, too, is off-limits to the next external run.
