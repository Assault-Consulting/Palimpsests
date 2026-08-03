# PALA-1 independent-verifier ambiguity / defect log

Spec commit: `776aa15a1427495c2b59d717f80e3ab82e9ad7c7`
Verifier: `verify.py` (this directory), written from `PALA-1.md`, both profiles,
and `test-vectors.json` alone — no reference code read.

Each entry is a place where the specification text plus the committed vectors were
**not sufficient** to produce the §8 result by following the text, OR where the
normative text contradicts the §8 expected result. Neither was patched silently
with CT / RFC 6962 convention; each is recorded here as a spec defect to fix
before freeze.

Two entries. The core envelope §8 values reproduced cleanly (see `verify.py`
output); both defects sit in the Merkle axis and in one prose/table contradiction.

---

## Finding 1 — Merkle tree hash and inclusion proof cannot be reproduced from the allowed files (leaves absent)

**Category: incompleteness of the vectors — strikes the exit criterion directly.**

### Exact quotes

§8, the values the exit test requires an independent implementation to reproduce
(PALA-1.md, "One of these is wrong, or this specification is:"):

> ```
> merkle_tree_hash    = 518f5be5173250f705e3bda029ec1c11ac5c4459115c07dde5bc1021d9f468db
> merkle_leaf_count   = 30     proof(index 7) verifies   proof_len = 5
> ```

§11 defines what reproduction means:

> a second implementation, written by someone who has not read the reference
> code, reproduces the §8 hashes **from this text and the vectors alone.**

§4.3 defers the leaf **source** to the profile:

> High-rate digests are aggregated per window into one `MERKLE` record — the
> digest **source** and rate are profile-defined (§3.4)

robotics profile §3 defines what a leaf digests, but gives no values:

> this profile defines the leaves: **digests of captured frame and audio buffers,
> aggregated per second into one `MERKLE` record.** At a 30 Hz sensor rate that
> is 30 leaves per record

robotics profile §6, open issue 1 — the leaf definition is itself still open:

> **Merkle leaf capture point.** Whether a frame digest covers the raw sensor
> buffer or the post-codec bytes changes what a disclosed frame proves.
> Undefined in the pre-split draft; must be fixed before v1.0.

### The ambiguity / defect

`merkle_tree_hash` is `MTH(leaf_0 … leaf_29)`, where each `leaf_i` is a frame /
audio buffer digest. To recompute it independently the 30 leaf digest **values**
are required. They are:

- not in `test-vectors.json` — the `MERKLE` record (seq 4) has **`body_len = 0`**
  (confirmed by parsing: no `body_hex`, no body), so the container carries only
  the *root* (the `MERKLE_TREE_HASH` TLV) and the *count* (the `MERKLE_LEAF_COUNT`
  TLV), never the leaves;
- not in either profile — robotics §3 says what a leaf *is* but publishes no
  values, and §6 issue 1 says the leaf's exact capture point is *undefined*;
- present only in the reference generator (`gen_vectors.py`), which the exit test
  forbids reading.

The inclusion proof for leaf 7 has the same gap: verifying a proof folds
`leaf(frame_7)` up through the five siblings to the root, and `frame_7`'s digest
is not in the allowed files. The published `proof` gives only the five *sibling*
hashes, not the leaf.

### Choice made (no silent patch)

The verdict is split into three honest categories — never collapsed to "PASS":

| §8 value | Category | Basis |
|---|---|---|
| `merkle_leaf_count = 30` | **REPRODUCED** | read from the `MERKLE_LEAF_COUNT` TLV (0x0012) in the seq-4 header; independent of leaves |
| `proof_len = 5` | **REPRODUCED (structural)** | the published proof has 5 entries; consistent with a 30-leaf RFC 6962 tree (⌈log₂30⌉ = 5) |
| `merkle_tree_hash = 518f…` | **TAUTOLOGY, not verification** | the value equals the `MERKLE_TREE_HASH` TLV embedded *in the very record being checked*. Confirming a record contains the root it claims proves nothing about that root. Recomputing it from leaves is impossible (leaves absent). **Reported as tautology; NOT counted as reproduced.** |
| `proof(index 7) verifies` | **UNVERIFIABLE** | leaf-7 digest absent. Folding the proof to the root requires the leaf; supplying "whatever leaf makes it fold" is circular. **NOT counted as reproduced.** |

`verify.py` implements the full RFC 6962 tree (`mth`) and proof check
(`verify_inclusion`) per §4.3 (promotion of the unpaired node, not duplication),
so that *if* the leaves were published the recomputation would run. They are not,
so those functions have no input.

### Why this is a defect

§8 and §11 name `merkle_tree_hash` and "`proof(index 7) verifies`" among the
hashes an independent implementation must reproduce "from this text and the
vectors alone." The inputs to those two values are in neither the text nor the
vectors. As the vectors stand, **the Merkle axis of the exit test is unpassable
by construction** — an independent verifier can only echo the root the record
already carries. Fix: publish the 30 leaf digests (and leaf 7's value) in
`test-vectors.json`, and resolve robotics §6 issue 1 so the leaf source is
defined, before v1.0 freeze.

---

## Finding 2 — first-record-not-GENESIS: normative prose says "break", §8 expected result says "violation" (direct contradiction)

**Category: contradiction between normative prose and the §8 expected output —
not an ambiguity. Per the exit test, §8 is authoritative; the prose needs fixing.**

### Exact quotes

§4.2:

> A verifier MUST reject as a **break** any chain whose first record is not a
> `GENESIS`, and MUST report a `GENESIS` at any position other than the first as
> a violation.

§7.1 pseudocode:

> ```
> if index == 0:
>     MUST h.record_type == GENESIS              else break
> ```

§8 expected result (the seventh demo) — which even cites §4.2 while contradicting
it:

> | **Chain with no `GENESIS`** | `chain_ok = false`, **violation** *"chain does
> not start with a GENESIS record"* — §4.2 |

`test-vectors.json` agrees with §8, not with the prose:

> `demos.missing_genesis`: `chain_ok = false`,
> `violations = [[0, "chain does not start with a GENESIS record"]]`

### The contradiction

For a first record that is not `GENESIS`, §4.2 and the §7.1 pseudocode both
classify the fault as a **break**; §8 and the vectors classify it as a
**violation** with a specific message. The boolean `chain_ok` is `false` either
way (breaks and violations both falsify it), so the top-level result agrees — but
the **categorisation** and the **diagnostic list the fault lands in** disagree.
An implementer following §7.1 literally emits a break and an empty `violations`
list, and fails to reproduce `demos.missing_genesis`.

(Note: this is distinct from the *`GENESIS` at a non-first position* case, where
§4.2, §7.1 and the vectors all agree it is a violation.)

### Choice made (no silent patch — both sides cited)

Per the exit-test standard the §8 table and the committed vectors are the source
of truth (they are what §11 requires reproducing). `verify.py` therefore reports
first-record-not-GENESIS as a **violation** with the message
`"chain does not start with a GENESIS record"`, reproducing `demos.missing_genesis`
exactly. The §7.1 pseudocode and §4.2 prose (`… reject as a break …` / `else
break`) are flagged as the text that must change: "break" → "violation" in both
places, to match the expected output they themselves point at.

### Why this is a defect

The reference text disagrees with the reference vectors on a normative
classification. Two independent implementers, one following §7.1's `else break`
and one following the §8 table, produce different `breaks`/`violations` lists for
the same input. Fix: change §4.2 and the §7.1 pseudocode to classify
first-record-not-GENESIS as a **violation**, aligning the prose with §8 before
freeze.

---

## Summary

- **Core envelope §8 (chain_head, chain_ok, record_count, breaks, gaps,
  violations, complete_to_anchor, anchor_head, merkle_leaf_count): REPRODUCED
  independently**, byte-for-byte, from the vectors alone.
- **merkle_tree_hash: NOT reproduced** — only a tautological echo of the embedded
  TLV is possible; leaves are absent (Finding 1).
- **inclusion proof (leaf 7): UNVERIFIABLE** — leaf digest absent (Finding 1).
- **missing-GENESIS categorisation: prose/vector contradiction** — reproduced by
  siding with §8 over the §7.1 prose, which is flagged for a fix (Finding 2).

Both findings are text/vector defects surfaced *because* the verifier refused to
supply the missing pieces from convention. That refusal is the exit test working
as intended.
