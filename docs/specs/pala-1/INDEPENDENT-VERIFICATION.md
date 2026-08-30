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
| **Status** | **Runs #1–#4 complete — the exit test and the freeze gate are both passed; see §5.** Runs #1–#2 (co-maintainer) reproduced both axes and closed two defects. Run #3 (first external, unaffiliated) reproduced them independently and exposed a third — a `complete_to_anchor` vector defect — fixed and confirmed by the same external verifier at `1294bd0`. **Run #4 (second external) was the freeze-candidate run:** all 11 §8 values reproduced blind on the verifier's first execution, spec defect #4 found (a pseudocode/prose contradiction that had propagated into both in-repo implementations), resolved with the vectors byte-identical, and the implementer's alignment confirmation is on record in the run's Status cell. Four independent implementations, two external. **Draft is lifted: the specification is Frozen at v1.0** (`PALA-1.md` §11); this document is the permanent record of how the freeze was earned. |
| **Implementer** | Runs #1–#2: the co-maintainer, who attests to the eligibility condition in §1 (merging pull requests without reading the changed files' contents does not disqualify). Run #3: an unaffiliated external implementer, per §6. |

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

| | |
|---|---|
| Run | #3 — first **external** run (unaffiliated implementer) |
| Date | 2026-08-05 |
| Spec commit tested | `c8e8247` — the sealed package as sent, before the anchor fix |
| Implementer | Rodion Bakaev (@Bakaev-Rodion) — no association with the project or Assault Consulting; attests to §1 eligibility (did not read the reference code, tests, or the earlier runs' verifiers). Verifier: `pala1_verifier.py`, Python stdlib, written from `PALA-1.md` + `profiles/` + `test-vectors.json` alone. |
| Result | **8 of 9 §8 values reproduced blind** — `chain_head`, `record_count`, empty `breaks`/`gaps`/`violations`, `merkle_tree_hash`, `merkle_leaf_count`, and the leaf-7 proof — plus four mutation demos. **1 divergence:** `complete_to_anchor` computed **`false`** where the vectors published `true`. The verifier read the published `anchor_head`, found it named a record three back from the tip, and reported an unanchored tail — exactly what §7.2 mandates. |
| Defect found | **Vector defect #3.** The verifier was right; the vectors were internally inconsistent — `verify.complete_to_anchor` was computed against `FINAL_HEAD` (the tip → `true`) while the published `anchor_head` was the in-chain `ANCHOR` record's noted head (seq 8, lag 3), which the vectors' own `stale_anchor` demo encodes as `false`. Runs #1–#2 had masked it (they checked completeness against `chain_head`, trivially `A == H`). An external run exercised the anchor exactly as §7.2 directs and caught what two prior runs did not. |
| Ambiguities logged | **5** — most minor and resolved by reading (byte order → §2.1; Merkle node promotion → RFC 6962). Item **(4)**, anchor provenance, was the root of the divergence, resolved by the §7.2 clarification. Two remained as *"the spec should say"* items, since closed by clarification: **(3)** whether `GENESIS` is subject to the §7.4 semantic checks (the implementer applied them to all records — which §7.1 already implies); **(5)** whether `MERKLE_LEAF_COUNT` must be validated against the actual leaf count (the implementer treated it as metadata). |

| | |
|---|---|
| Run | #3 re-run — confirmation against the fixed vectors |
| Date | 2026-08-05 |
| Spec commit tested | `1294bd0` — the merged anchor fix (PR #99) |
| Verifier (link) | `pala1_verifier.py` — **unchanged** from the run-#3 verifier; the change from `false` to `true` is the vector fix, not the verifier. |
| Result | **All §8 values match**, including `complete_to_anchor = true` (`anchor_head == chain_head` after the fix). Independently re-run by the maintainer against the merged vectors — every value the external verifier reports is correct. The `stale_anchor` demo still exercises the lagging case (`false`, `anchor_lag = 3`); the two stale-anchor tests were re-pointed at the seq-8 head accordingly. |
| Defect status | **Vector defect #3 resolved at `1294bd0`** (§7.2 clarified, §8 aligned, `anchor_head` = the store's current head). Ambiguity items (3) and (5) closed by §7.4 / §4.3 clarifications in the same cycle. The exit test is now satisfied by **three independent implementations** — two co-maintainer, one external — agreeing on every §8 value. Draft remains held (§4): the freeze re-run against the eventual freeze candidate is still owed. |

| | |
|---|---|
| Run | #4 — the **freeze-candidate** run (second external implementer) |
| Date | 2026-08-08 |
| Spec commit tested | `ff2720a` — the freeze-candidate sealed package (post-Phase-3 main) |
| Implementer | Vladyslav Kurdybaylo (v.kurdybailo@gmail.com) — no association with the project or Assault Consulting; attests to §1 eligibility. Method disclosure: implemented with the assistance of an AI coding agent (Claude), working strictly from the sealed package; the repository was created 2026-07-06 — after the agent's training cutoff — so training-data contamination for this repository is not possible. Verifier: `pala_verify.py` (~390 lines, Python stdlib; optional `cryptography` for the §4.4 extra), archived under `independent-runs/kurdybaylo/`. |
| Boundary note | First run conducted **after** Phase 3 landed (the §1 plan of record was before). The §1 boundary held by construction: the implementer worked from the sealed package alone (§6.2 — enforced by what they hold), and the wire was not changed by Phase 3. |
| Result | **All 11 §8 values reproduced blind, on the verifier's first run** — including both §4.3 constructions agreeing with each other, the published root, and the record's own TLV — plus **all 7 mutation demos** matching the published outputs, plus extras beyond the pass bar: every per-record `record_hash` recomputed and matched, both `body_digest` values matched, and the seq-3 body decrypted under §4.4 to exactly the published plaintext with the derived-nonce rule confirmed. Independently re-run by the maintainer against the sealed vectors: every reported value reproduced. |
| Defect found | **Spec defect #4 — deeper than text.** The §7.1 pseudocode, read literally, contradicted §4.2 prose: on a chain whose `GENESIS` was removed (first record carrying a non-zero `prev_hash`) it produced two violations — including a bogus zero-`prev_hash` demand against a record that is not a `GENESIS` — plus a spurious break. Maintainer adjudication then found the literal reading had propagated into **both in-repo implementations** (the production verifier and `palaudit_ref.py`), a common-mode defect the differential test could not see. It survived the published demo because the demo's input was synthetic (a single seq-0, zero-`prev_hash` record) and sat in the zone where both readings agree; the freeze-run implementer independently constructed the **discriminating** input — the real chain minus its `GENESIS` — which is where the divergence lives. Fixed in this cycle: §7.1 pseudocode aligned to §4.2; both in-repo implementations corrected (one violation at position 0, no break, zero-`prev` demanded only of an actual `GENESIS`); the demo input strengthened to the discriminating construction; two strict regression tests added. **`test-vectors.json` is byte-identical** after regeneration — the published outputs were already the intended semantics. No wire change. |
| Ambiguities logged | **3** — (1) the pseudocode inconsistency above (became defect #4); (2) what keys a violation — closed by the §7.1 keying sentence; (3) the `["L"/"R", hash]` proof-entry encoding existed only in the vectors — closed by the §4.3 inclusion-proof paragraph. |
| Status | The freeze-candidate gate is **passed, with findings resolved in this cycle**: every published §8 value reproduced blind by a fourth independent implementation, and the run's central finding — a pseudocode/prose contradiction that had silently propagated into both in-repo implementations — fixed with the vectors byte-identical and the wire untouched. This is the §11 exit test doing exactly what it was designed to do: a fresh implementation, working from the text alone, caught what the differential test structurally could not (common-mode) and what three prior runs' demo checks had not discriminated. Implementer's re-confirmation of the alignment diff **received** (2026-08-09): *"I have read the §7.1/§4.3 alignment diff (PR #104); the corrected text matches the documented choices A1–A3 of my run. My verifier is unchanged."* — Vladyslav Kurdybaylo. With that, the freeze gate closed; the spec change following this record is Draft → Frozen (v1.0). |

## 6. Conducting an external run

**Self-service:** everything an outside implementer needs — the boundary
rules, the task, the sealed-input fetch script with pinned digests, and
the run-record template — is packaged under
[`verification-kit/`](verification-kit/README.md). A run can be
conducted and submitted without contacting the maintainers first.

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

## 7. Bridge runs — the SCITT Signed Statement

Sections 1-6 govern the wire-format exit test of PALA-1 §11. The SCITT
bridge is a second, later surface: not the record format, but the
COSE_Sign1 Signed Statement a producer registers with a transparency
service (RFC 9943) over a chain head. Its task, its boundary and its
vector are separate — `docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md`
and `docs/interop/scitt-statement-vector.json` — and runs against it are
recorded here rather than in §5, so that neither record is read as
evidence for the other. A bridge run says nothing about the wire format,
and the runs in §5 say nothing about the bridge.

| | |
|---|---|
| Run | **B1** — first bridge run |
| Date | 2026-08-30 |
| Vector tested | `docs/interop/scitt-statement-vector.json` at `296f331`, SHA-256 `bf810261…54bf9491` |
| Implementer | Oleksii Turak (olexii.turak@gmail.com) — **maintainer, not an unaffiliated external run** (§6). Method disclosure: produced with an AI coding agent (Claude) under the implementer's direction and review, as with run #4; the repository postdates the agent's training cutoff. The run's own record discloses every file read. |
| Verifier (link) | [`independent-runs/turak/scitt-statement/`](independent-runs/turak/scitt-statement/) — 1027 lines of Python across three files, standard library only. No COSE, CBOR or cryptographic library: `cbor.py` from RFC 8949, `ed25519.py` from RFC 8032 §5.1 (self-checked against §7.1 TEST 1, which is also the vector's key), `scitt_verify.py` from RFC 9052 §4.4, RFC 9597 §2 and RFC 9943 §6. |
| Result | **PASS on every pass-bar check, and the stretch goal met.** The 202-byte statement parses as a tagged COSE_Sign1, its Ed25519 signature verifies over the §4.4 Sig_structure, its payload commits to the published `chain_head` with the stated sequence range and format id, and the whole message was **reproduced byte-for-byte** from the vector's stated inputs by independent construction. 45 checks, 0 pass-bar failures. All 3 `tamper_expectations` held. 11 adversarial cases constructed. Provenance confirmed in both directions: the key is RFC 8032's published test key, and the subject is the `chain_head` of `test-vectors.json`. |
| Findings | **4 — one of them a MUST violation.** **F1 (conformance, open):** the protected header carries only `alg` and CWT claims, so it has no `kid`, `x5t` or `x5chain` — RFC 9943 §6 requires `kid` when the other two are absent, leaving a transparency service no in-band way to resolve the issuer's key. **F2 (ambiguity):** with no `content type` declared, a payload keyed 1..4 is not distinguishable from a CWT Claims Set, which RFC 9597 §2 would oblige a verifier to reject on mismatch. **F3 (malleability):** RFC 9052 §9 scopes its minimum-length rule to the Sig_structure, not to the message, so a re-encoded 203-byte variant carries the same valid signature — `statement_sha256` identifies a serialisation, not a statement. **F4 (design):** `sub` truncates the chain head to 8 bytes, so two chains collide in the SCITT subject at a 64-bit birthday bound. |
| Ambiguities logged | **9** — see [`scitt-statement/ambiguity-log.md`](independent-runs/turak/scitt-statement/ambiguity-log.md). Three became findings (A5 → F3, A7 → F2, A8 the context for F1). The rest are places the published material could state rather than imply: the external AAD (A3), the outer encoding rule (A5), the payload's format id, which exists only inside an English sentence (A2), and two files the task's rationale depends on but its reading list omits — RFC 9943 itself (A1) and `test-vectors.json`, which the vector names as its own provenance (A6). |
| Status | **Reported, not resolved.** F1 is a defect in the published statement; correcting it means adding `kid` to the *protected* header — adversarial case A10 shows an unprotected `kid` is unauthenticated — which changes the statement bytes, its length and `statement_sha256`, so the vector is reissued with it. That work touches bridge code the run's boundary put off-limits and is deliberately left to a separate change. F1 turns on one sentence of RFC 9943 prose that the same RFC's CDDL does not enforce (A8), so an unaffiliated confirmation is worth having before it is acted on. **Superseded by B2:** F1, F2 and F4 were resolved in vector v2 and confirmed fixed by the run below; F3's rescoping was confirmed correct. |

| | |
|---|---|
| Run | **B2** — second bridge run, against the reissued vector |
| Date | 2026-08-30 |
| Vector tested | `docs/interop/scitt-statement-vector.json` at `d84be55a`, SHA-256 `e51575d0…d1570ec7` — the **v2** reissue that resolves B1's F1/F2/F4 |
| Implementer | Oleksii Turak (olexii.turak@gmail.com) — **maintainer, not an unaffiliated external run** (§6), and additionally the B1 implementer, which disqualifies this run from an external label on this surface under §6.1/§6.3. Method disclosure as for run #4 and B1: produced with an AI coding agent (Claude) under the implementer's direction and review; the repository postdates the agent's training cutoff. **Boundary posture differs from B1 and is weaker:** the run was conducted against a live repository checkout rather than a §6.2 sealed package, so `src/` and `tests/` were reachable throughout and were not read — an assertion about conduct, not a property of the setup. The run's own record discloses this, plus two further contamination disclosures. |
| Verifier (link) | [`independent-runs/turak/scitt-statement-b2/`](independent-runs/turak/scitt-statement-b2/) — 837 lines of Python across three files, standard library only. Written fresh, not derived from the B1 verifier: `cbor.py` from RFC 8949 (strict by default — rejects non-minimal heads, indefinite lengths and trailing data, and preserves encoded key bytes so §4.2.1 ordering is checked rather than assumed), `ed25519.py` from RFC 8032 (self-checked against §7.1 TEST 1 **and** TEST 2, with the `0 ≤ S < L` check switchable), `scitt_verify.py` from RFC 9052 §4.4, RFC 9597, RFC 9679 and RFC 8392. |
| Result | **PASS on every check, and the stretch goal met. 61 checks, 0 failures.** The 331-byte v2 statement parses as a tagged COSE_Sign1 under a strict decoder, its Ed25519 signature verifies over the §4.4 Sig_structure, its payload commits to the published `chain_head` over seq 0–11, all four parameters sit in the protected bucket in deterministic order, and the whole message was **reproduced byte-for-byte** by independent construction — stable across three runs. `kid` was recomputed from scratch as an RFC 9679 thumbprint and matched. All **5** `tamper_expectations` held; 11 adversarial cases constructed. Provenance confirmed in both directions: the key is RFC 8032 §7.1 TEST 1, and `test-vectors.json` has 12 records, seq 0–11, with the committed `chain_head`. |
| B1 findings | **F1, F2, F4 confirmed fixed** in v2 — `kid` present in the protected bucket and equal to the RFC 9679 thumbprint, content type declared and not `application/cwt`, CWT `sub` carrying the full 64-hex head. **F3's rescoping confirmed correct**, and its mechanism reproduced directly: re-encoding the protected bstr's length head (`58cd` → `5900cd`) leaves the signature valid while changing the bytes, `statement_sha256` and length — and a strict RFC 8949 §4.2.1 decoder rejects it. |
| Findings | **4 — none contradicting the published bytes**; all are refinements to the vector's prose and tamper list. **F-2 (the substantive one):** the tamper expectations miss Ed25519 signature malleability. Replacing the scalar `S` with `S + L` yields a *second, distinct* valid 64-byte signature over the identical Sig_structure — rejected under RFC 8032 §5.1.7's `0 ≤ S < L` check, accepted without it. Not a forgery but a signature-*uniqueness* failure, which matters for a transparency service that deduplicates or indexes registrations by signature bytes. **F-1:** moving `kid` to the unprotected bucket is exactly **length-neutral** here (−35 protected, +35 unprotected; 331 B either way, `58cd` → `58aa`), so `statement_length_bytes` does not detect the move `byte_stability.2` describes — only the sha256 does, though the two fields are published side by side as apparent peers. **F-3:** the detached-payload case (payload → `nil`) is a fifth artifact-identity/validity split — the published signature verifies over a different 277-byte artifact — and belongs beside modes 2 and 3. **F-4:** `kid_note` should pin the raw-digest form and the §4.2.1 **bytewise** member ordering; the intuitive numeric ordering `{-2,-1,1}` yields `d21c7849…` instead of `866eefbd…`, and the mismatch gives no diagnostic pointing at ordering. |
| Ambiguities logged | **10** — see [`scitt-statement-b2/ambiguity-log.md`](independent-runs/turak/scitt-statement-b2/ambiguity-log.md). The two that cost most: **A1/A3**, "ascending order" stated as equivalent to RFC 8949 §4.2.1 when the two are different predicates that merely coincide for labels `{1,3,4,15}` — and diverge in the RFC 9679 thumbprint, where §4.2.1 decides the answer; and **A4**, `external_aad` never stated, assumed `h''` and confirmed only by the signature verifying, which is circular if the goal is to check the vector rather than match it. |
| Status | **Reported.** The v2 statement is verified and reproduced; B1's open F1 is closed. The four findings are vector-prose and tamper-list refinements, not byte defects, and are left for a separate change. F-2 is the one worth acting on: it is a property of Ed25519 verification that the tamper list does not currently exercise, and — like B1's F1 — an unaffiliated confirmation is worth having, since this run is a maintainer run by the B1 implementer and carries the weaker boundary posture noted above. |
