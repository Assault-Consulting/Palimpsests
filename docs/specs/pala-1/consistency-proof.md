<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# PALA-1 companion — prefix-consistency proofs (`pala-consistency-proof/1`)

| | |
|---|---|
| **Status** | Companion to the frozen core. **Derived** from bytes the chain hash already covers; nothing is added to the wire and `test-vectors.json` is untouched. Shipped in the package (`palimpsests.audit.pala.proofs`; the `pala consistency` / `pala consistency-verify` commands follow in the next change) with its own companion vectors, `consistency-vectors.json`, and their regeneration gate. |
| **Answers** | *Is the archived prefix still the prefix of the live chain?* — with O(log n) nodes, without the archived records, and without re-hashing them. |
| **Builds on** | Core §4.3 (the tree), RFC 6962 §2.1.2 (proof construction), RFC 9162 §2.1.4.2 (verification). Referenced by `RETENTION.md` §3 (pruning with a formal consistency check) and the retention-continuation profile (`SEG_PRIOR_ROOT`). |

## 1. The derived tree

The chain-carried `MERKLE` records (§4.3) aggregate **windows** — a
second of sensor frames, a batch of digests. Prefix consistency needs
one tree over the **whole chain**, so it is derived rather than carried:

> **The derived root of a chain of `n` records is the §4.3 tree hash
> over the `n` record hashes (§1.2) in seq order: `leaf(d) = SHA-256(0x00 ‖ d)`,
> `node(l, r) = SHA-256(0x01 ‖ l ‖ r)`, an unpaired node promoted, the
> empty chain's root `SHA-256("")`.**

Any verifier holding the headers computes it; it is a pure function of
`record_hash` values the chain check (§7.1) already produces. It is not
written into any record and no record type or TLV is allocated for it.
Where a deployment wants the root committed, it commits it the way it
commits a head: in an anchor store, in a SCITT statement's payload, in a
continuation record's `SEG_PRIOR_ROOT` — all outside the frozen wire.

Because §4.3's bottom-up promote-not-duplicate construction equals
RFC 6962's recursive one (the core says so in §4.3; `test_pala_differential`
checks it against the recursive definition), the RFC's consistency-proof
algorithms apply to the derived tree without modification.

## 2. The proof

Let `first ≤ second` be record **counts** (seq of the last record
covered, plus one). A consistency proof between `root(first)` and
`root(second)` is RFC 6962 `PROOF(first, D[second])`: the list of
subtree hashes that lets a verifier reconstruct both roots from the
shared structure. It verifies with RFC 9162 §2.1.4.2, which corrects
the RFC 6962 text. `first == second` has an empty proof and requires
the roots to be equal; `first == 0` is not defined (there is no prefix
to speak of) and is rejected.

**What it proves.** That every record with `seq < first` in the state
that produced `root(second)` is byte-for-byte (by hash) the record at
the same seq in the state that produced `root(first)` — no change,
reordering, insertion or removal before `first`. It says nothing about
records at or beyond `first`, and nothing about where either root came
from.

**What it does not replace.** The chain check (§7.1) — a consistency
proof between two roots computed by the same party from the same file
proves nothing an attacker could not also compute. The proof has value
exactly when the two roots have **independent provenance**: the first
taken when a prefix was archived or anchored, the second from the live
chain today. Provenance is the caller's evidence; the verifier compares
roots it holds to the document's before it verifies the path
(`pala consistency-verify --first-root … --second-root …`).

## 3. Document format — `pala-consistency-proof/1`

Derived and unsigned, like `pala-bundle/1`: the chain stays
authoritative, and the document re-verifies from this text alone.

```json
{
  "format": "pala-consistency-proof/1",
  "tree": "PALA-1 §4.3 over record hashes, seq order, whole chain",
  "first": 7,
  "second": 17,
  "first_root": "<64 hex>",
  "second_root": "<64 hex>",
  "path": ["<64 hex>", "…"]
}
```

`first` and `second` are counts, not seqs. `path` is the RFC 6962
consistency path, root-ward order, as `SUBPROOF` emits it. A verifier
MUST reject a document whose `format` is not this string, MUST NOT
accept a document on the strength of its own embedded roots alone when
it holds roots from elsewhere, and MUST return a structured result
rather than throw on a malformed path (`verify()` returns `False`).

## 4. Where it is used

| Use | Roots' provenance | Where |
|---|---|---|
| Pruning with a formal check | `root(first)` recorded in the segment manifest when the prefix was archived; `root(second)` from the live chain | `RETENTION.md` §3 |
| A continuation record's commitment to everything before it | `SEG_PRIOR_ROOT = root(seq)` — always from record 0, never a window | `profiles/retention-continuation.md` §2 (open issue 1 is closed by this document) |
| An auditor comparing a bundle taken last quarter to the chain today | the bundle's own derived root vs the chain's | `pala consistency` on the live file; `pala consistency-verify` with `--first-root` from the bundle |

## 5. Companion vectors

`consistency-vectors.json` is generated by `gen_consistency_vectors.py`
from the reference implementation (`palaudit_ref.py`) and the RFC text
alone — not from the package — over the 17-record inference companion
chain: the derived root for every count `0..17`, eleven proofs
(including `first == second`, a power-of-two `first`, and proofs whose
`second` is not the full chain), and three documents that MUST verify
`False`. The package reproduces every root and accepts every proof in
`tests/test_consistency_proofs.py`, which also regenerates the file and
requires it to be byte-identical.

## 6. Not claimed

The proof is a statement about two roots. It is not a receipt, not an
anchor, not a witness. A chain whose roots were both computed today by
the party that holds the file has proven only that it can run SHA-256.
