# Independent verification: SCITT statement construction v3 (bridge run B3)

**Result: verified and reproduced byte-for-byte.** Both statements
reproduce at 369/369 bytes, both derived roots reproduce from the record
hashes, and the prefix-consistency proof verifies from the two
statements' payloads alone. 155/155 checks pass, 0 failures.

**One hard divergence, and it is not in the statements.** A faithful
RFC 9162 §2.1.4.2 implementation cannot verify the `first == second`
proof that `consistency-vectors.json` publishes among its positive
cases — finding **F1**. The B3 statement vector itself is unaffected.

| | |
|---|---|
| Vector under test | `docs/interop/scitt-statement-vector-v3.json` |
| Vector sha256 | `86a474ff33a1a210cfebb7e2b2d0352b0f57246d46b352de8c908891a8a96657` |
| Vector commit | `a39f4fd07b2a64f296ced63c55692fce8f65b25a` |
| Task doc | `docs/interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md` at `7b007c8ad96f7a83df08ce0db63f0b934698da33` |
| Task doc sha256 | `0f3d9e039f38f89e9c9d637511940bcf0ca890343646f13c24b0011cd8147434` |
| Supporting vectors | v2 `2e93995c…4cd5386e` · core `476c05ce…e20a8193` · consistency `7f80808f…578ddadc` |
| Repo HEAD at run time | `45ede168cae7f808075160754e601faedb8ba242` |
| Date | 2026-10-28 |
| Language / runtime | Python 3.12.10, standard library only |
| Wall clock | ~25 min end to end (21:52–22:17); the verifier itself runs in 0.27 s |
| Determinism | three consecutive runs, identical results (canonical digest `7082f13fcbbec8f2…`) |

## Contamination boundary — what was and was not read

**Read.** RFC 9052, RFC 9597, RFC 9679, RFC 8032, RFC 8949, RFC 8392
(CWT claim keys); RFC 6962 §2.1 and §2.1.2 and RFC 9162 §2.1.4.2, both
fetched and quoted verbatim rather than recalled; RFC 9943 §5.1.1.1 and
§6, fetched to re-check conformance under the new content type. The task
file; `scitt-statement-vector-v3.json`; `scitt-statement-vector.json`;
`PALA-1.md` §1.2, §2.1, §4.1, §4.3; `consistency-proof.md`;
`test-vectors.json`; `consistency-vectors.json`;
`draft-sparysh-pala-audit-02` §"Relationship to transparency services".
And, as the boundary permits, my own B1 and B2 code and run records —
`cbor.py` and `ed25519.py` are carried over from B2 **byte-identical**
(`diff` is empty), which is the point of being allowed to reuse them.

**Not read.** `src/palimpsests/**`, `tests/**`, `benchmarks/**`,
`docs/interop/gen_scitt_statement_vector_v3.py`,
`docs/specs/pala-1/palaudit_ref.py`.

Five disclosures, in the interest of the record.

**1 — the generator exclusion was read wider than its list.** The
boundary names two generators; three more sit in directories it
otherwise opens (`gen_vectors.py`, `gen_consistency_vectors.py`,
`profiles/gen_inference_vectors.py`), and `consistency-proof.md` §5 says
the second of those derives from the named-excluded `palaudit_ref.py`.
I read none of the three, taking the stated rationale as controlling
over the enumeration. See ambiguity **U2**.

**2 — `profiles/inference-vectors.json` was read, and is on neither
list.** `consistency-vectors.json` publishes roots and paths but
describes its leaves only in prose, so its `roots_by_count` cannot be
recomputed without the source chain's record hashes. I read that file to
make the stretch goal a real check rather than a restatement of the
file's own assertions. It carries record headers and hashes and no
roots, so it cannot transfer the quantity under test. See **U3**.

**3 — two commit subject lines touching statement v3 were visible.**
The task requires "the commit hash of the vector file you tested" in the
verification record, so `git log -1 -- <vector>` was run. That printed
the subject of commit `a39f4fd0` ("vectors(scitt): construction v3 — two
statements of one chain and the consistency proof between their roots;
roots by the reference implementation") and, for the task file,
`7b007c8a`. A branch listing also exposed the names
`feat/statement-v3` and `docs/b3-statement-v3-task`, and `git ls-tree`
was used on those refs to locate the v3 files — filenames only. No diff,
no patch, no PR and no issue was opened, and the subject lines contain
no construction detail the task does not state outright. The boundary
excludes commit history touching statement v3; obtaining the required
commit hash necessarily touches it, and this is the minimum that does.

**4 — the boundary here was held by restraint, not by construction.**
As in B2: the live repository was checked out and `src/palimpsests/**`
was a `cat` away throughout. That it was not read is an assertion about
conduct, not a property of the setup, and it is why §7 should record
this as a maintainer run rather than an unaffiliated external one.

**5 — `INDEPENDENT-VERIFICATION.md` was read after this report was
final.** That document narrates B1's and B2's findings in detail. It was
opened only *after* this file and `ambiguity-log.md` were written, to
determine where a B3 row belongs and in what format, and the §7 row was
written from this report rather than the other way round. No finding,
measurement or ambiguity entry was added, removed or reworded
afterwards. Same for B2's `README.md`, read at submission time for the
house layout of this file. Same disclosure as B2's, for the same reason.

## Affiliation

**Maintainer run — not an unaffiliated external run.** The implementer
is a maintainer and is additionally the B1 and B2 implementer, which
disqualifies this run from an external label on this surface under §6.1
and §6.3. A run that has seen its own earlier verifier tests that file
as much as the specification.

**AI assistance, as the task asks.** Produced with an AI coding agent
(Claude Opus) under the implementer's direction and review. The agent
wrote `merkle.py` and `scitt_verify_v3.py`, fetched and quoted the RFC
algorithm texts, and ran the suite; the implementer set the boundary,
chose what to test, and reviewed the findings. Two corrections were
made during the run and are worth naming because they cut the other way:
the agent's first recollection of RFC 9162 §2.1.4.2 **omitted step 1**
(the empty-path rejection) — fetching the RFC text is what produced
finding F1 rather than a silent pass — and its first canonical-ordering
check in case A2b was wrong (it re-encoded an order-preserving map and
compared it to itself, which can only succeed). Both were caught by the
run failing, not by inspection.

The repository postdates the agent's training cutoff, so training-data
contamination for this repository is not possible.

What is independent here, and is the claim this run makes: the tree, the
proof construction, the proof verification and the statement
constructor were written from PALA-1 §4.3, `consistency-proof.md` §1–§2,
RFC 6962 and RFC 9162 without reading the bridge implementation or
either excluded generator, and they reproduce the published bytes. That
is an implementation-independence claim, not a personnel-independence
one.

## Toolchain

No COSE library, no CBOR library, no crypto library, no Merkle library.

| File | Lines | What it is |
|---|---|---|
| `verifier/cbor.py` | 211 | RFC 8949 decoder and deterministic encoder. **Byte-identical to B2.** Strict by default: rejects non-minimal length heads, indefinite lengths and trailing data; preserves map order and raw encoded key bytes so §4.2.1 ordering is checked, not assumed |
| `verifier/ed25519.py` | 183 | RFC 8032 Ed25519. **Byte-identical to B2.** Extended-coordinate arithmetic, `0 <= S < L` switchable. Anchored on §7.1 TEST 1 and TEST 2 |
| `verifier/merkle.py` | 207 | **New.** PALA-1 §4.3 tree in both the iterative promote-not-duplicate form and RFC 6962's recursive `MTH`; RFC 6962 §2.1.2 `PROOF`/`SUBPROOF`; RFC 9162 §2.1.4.2 verification, step for step, returning `(ok, reason)` rather than raising |
| `verifier/scitt_verify_v3.py` | 942 | **New.** The run: COSE_Sign1 parse, Sig_structure, RFC 9679 thumbprint, the version rule, the eight task steps, 7 tamper expectations and 13 adversarial checks across nine cases |
| `verifier/run-all.sh` | 30 | Reproduces the whole run from a checkout |
| `output/full-run.log` | — | Full transcript |
| `output/results.json` | — | 155 checks and the divergence, machine-readable |

`merkle.py` has its own self-test, run before anything is trusted: the
two tree constructions PALA-1 §4.3 asserts to be equal are checked equal
for n = 0…24, and a proof is built and verified for **every** pair
0 < m < n ≤ 24 — 276 round trips. PALA-1 §4.3 says an implementer "does
not go looking for a discrepancy" between the two forms; this run checks
that rather than taking it.

## What was done, in order

1. **Toolchain first.** `ed25519.py` against RFC 8032 §7.1 TEST 1 and 2;
   the vector's public key re-derived from its seed; `merkle.py`'s 276
   proof round trips and the two-construction equality; the empty-tree
   root confirmed as `SHA-256("")`.
2. **Step 1 — the roots.** The derived root over records 0–7 and over
   0–11, computed from `subject_chain.record_hashes_hex` with my own
   tree. Both match `statements.*.inputs.root_hex` exactly. Also
   confirmed each statement's head is the last record hash in its range
   (PALA-1 §4.1).
3. **Stretch (a) — the leaves.** All 12 record hashes recomputed as
   `SHA-256(header_bytes)` from `test-vectors.json`'s `header_hex`. All
   12 match both that file's `record_hash` and the v3 vector's
   `record_hashes_hex`; each `header_len` field equals the actual header
   length; the re-derived head equals the published `chain_head`. The v3
   vector's leaves are the published core vectors, not a restatement.
4. **Stretch (b) — the tree against an independent chain.** All 18
   `roots_by_count` entries in `consistency-vectors.json` (counts 0–17)
   reproduced from the inference chain's record hashes. Of its 11
   published proofs, the 10 inside RFC 9162's input domain verify **and**
   their paths rebuild byte-for-byte from the chain via RFC 6962
   `PROOF`. The 11th is finding **F1**. All 3 negative cases verify
   `False`, each for the right reason.
5. **Steps 2 and 3 — both statements, label by label.** Tag 18, strict
   RFC 8949 decode, empty unprotected bucket, attached payload, 64-byte
   signature, Ed25519 over the RFC 9052 §4.4 Sig_structure; protected
   labels exactly `[1, 3, 4, 15]` in §4.2.1 bytewise order; `alg` −8;
   `kid` recomputed as the RFC 9679 thumbprint over `{1:1, −1:6, −2:x}`
   (and confirmed *not* to be the numeric-ordering variant — the B1/B2
   finding, which still holds); CWT `iss`/`sub` with the full untruncated
   64-hex head; content type the v3 string; payload keys exactly
   `[1, 2, 3, 4, 5]` with a 32-byte key 5 equal to the root from step 1.
   RFC 9943 §6 re-checked under the new content type: no `x5t`, no
   `x5chain`, so `kid` is MUST-present and is present, in the protected
   bucket; CWT Claims present with `iss` and `sub`; `iss` a string of 36
   characters. `typ` is not an RFC 9943 parameter and its absence is not
   a defect.
6. **The `first_seq` trap, explicitly.** The `later` statement reports
   8–11 and carries the root over **0–11**. Confirmed, and confirmed
   that the root over 8–11 is a *different* value — see F2.
7. **Step 4 — the case v3 exists for.** Run inside
   `chainless_consistency_check(raw_earlier, raw_later, path, pub)`,
   whose parameter list is the claim: there is no argument through which
   the chain, the record hashes or the vector's `root_hex` and
   `first`/`second` fields could arrive. Both roots are read out of the
   signed payloads; both tree sizes are derived from each statement's own
   signed `last_seq` (8 and 12). RFC 9162 §2.1.4.2 verifies: **the
   12-record state extends the 8-record state.** Reported `root_status`
   for both statements is `carried`, never `verified`. Separately, with
   the chain, `PROOF(8, D[12])` rebuilds the published one-node path, and
   that node is the subtree root over records 8–11.
8. **Step 5 — reproduction.** Both statements rebuilt from the inputs and
   the seed: protected header, payload and signature each byte-identical,
   then the whole 369-byte artifact and its sha256. Stable across three
   runs.
9. **Step 6 — tamper.** All 7 expectations hold (T1–T7). The version rule
   was tested with statements of my own, signed with the vector's key: a
   v2 payload under the v3 content type and a v3 payload under the v2
   content type are both refused, **both with a valid signature** — the
   version rule is a reading rule, not a cryptographic one.
10. **Step 7 — regression.** The v2 statement still verifies, reads as
    construction v2, carries no key 5, and is byte-unchanged at 331
    bytes. A v2-only verifier rejects the v3 statement by content type
    before reading the payload, which is the vector's `relation_to_v2`
    claim, confirmed.
11. **Step 8 — adversarial.** Nine cases of my own (A1–A9, 13 checks):
    key 5 at 31 and 33 bytes; a descending-order payload; a duplicated
    key 5; an inverted `first_seq`/`last_seq`; an incoherent head/root
    pair; `first == second`; a root over a different chain entirely; the
    untagged form; and the empty-tree gap. The four that say something
    are F2, F3, F4 and A6 (the mechanism behind F1).

## Findings

### F1 — `consistency-vectors.json` publishes a positive proof that RFC 9162 §2.1.4.2 rejects

**Severity: specification defect, narrow.** Affects the companion
document and its vector file, not the B3 statement vector, and not any
byte published in it.

Among the 11 proofs in `consistency-vectors.json` is `17 → 17` with an
empty `path`. `consistency-proof.md` §5 presents all 11 as cases "the
package reproduces every root and accepts every proof" for, and §2 says
`first == second` "has an empty proof and requires the roots to be
equal".

RFC 9162 §2.1.4.2 cannot accept it, for two independent reasons:

- its stated input domain is `0 < first < second` — strictly less;
- its **step 1** is "If `consistency_path` is an empty array, stop and
  fail the proof verification."

My implementation returns `False` with the domain guard *removed*, on
step 1 alone. So this is not an artifact of a guard I added.

Meanwhile §2 of the same document asserts the format "verifies with
RFC 9162 §2.1.4.2". Both sentences cannot hold. Per the task's rule the
RFC wins, which makes the equal-size case a **PALA-1 pre-check that must
be settled before §2.1.4.2 is entered** — alongside `first == 0`, which
§2 already handles that way.

**Suggested wording.** In §2: the path algorithm is RFC 9162 §2.1.4.2;
`first == 0` is rejected and `first == second` is accepted iff the roots
are equal, both decided before the algorithm runs. In
`consistency-vectors.json`, move the `17 → 17` entry out of `proofs`
into a separately labelled group, so a conforming verifier is not
required to feed an empty path to an algorithm that must reject it.

### F2 — the wrong root the vector warns about *is* the proof's only path node

**Severity: vector quality.** No byte is wrong; the test is weaker than
it looks.

`tamper_expectations` includes "a root computed over `first_seq..last_seq`
(here 8..11) instead of the prefix: MUST be rejected". That root is

```
b81fb7fb423bd7909330f0294a74962dd662e21b6efe21c3f95945f609217f76
```

which is **byte-identical to `consistency.path[0]`**, the single node of
the published consistency proof. Because `first_seq = 8` is a power of
two and records 8–11 form a complete subtree, the wrong reading does not
produce a random value — it produces a real node of the published tree,
and the one node an implementer is already holding.

This makes the mistake unusually easy to talk yourself into: the value
appears in the proof document, so it looks corroborated. A reader who
computed it would find it where they expected a tree node to be.

**Suggested fix.** Keep the case, and either note the coincidence in the
vector's prose, or add a second pair whose `first_seq` is not a power of
two so the wrong root is not a node of the tree at all.

### F3 — nothing binds the head to the root, and the task's root section does not say so

**Severity: specification precision.**

"What a verifier may claim about the root" is careful and correct: an
unrecomputed root is *carried*, not verified. It says nothing about
payload key 1. Without the chain the head is carried in exactly the same
sense, and nothing relates the two.

Demonstrated (case A5): a statement carrying **record 7's head** with the
**12-record root**, correctly signed, is accepted by a chainless verifier,
and the consistency proof against the `earlier` statement still verifies —
because the proof is a statement about roots and never reads key 1. A
chain-holding verifier catches it only if it checks the head separately:
the root in that statement is the correct root for its own `last_seq`, so
a root-only check passes it.

So the precise claim a holder of two statements and one proof can make is:
*the tree these two signed roots describe grew by extension.* Not that
either head belongs to that tree.

**Suggested wording.** Add to that section: without the chain the head is
carried too, and a chainless consistency check relates the two roots
only — not a head to its root.

### F4 — `first_seq > last_seq` is unconstrained

**Severity: minor, specification completeness.**

No document states `first_seq <= last_seq`. Because the root depends
only on `last_seq`, a statement with `first_seq = 11, last_seq = 8` is
constructible, signable, and carries a root that is *correct* for its
`last_seq`. My reader refuses it; nothing in the task, the vector,
PALA-1 or the draft requires that.

**Suggested wording.** `0 <= first_seq <= last_seq` in the payload table.

## What did not diverge

Worth stating, because the list is longer than the findings:

- both statements reproduce byte-for-byte, 369/369, signature included;
- both derived roots reproduce from the record hashes, and the record
  hashes themselves reproduce from the published headers;
- the consistency path reproduces from the chain via RFC 6962 `PROOF`;
- the proof verifies from the two statements' payloads alone, which is
  the claim v3 exists to support;
- RFC 9943 §6 conformance holds under the new content type;
- the RFC 9679 thumbprint, the §4.2.1 ordering and the untruncated CWT
  subject — B1's findings, as fixed in v2 — all still hold in v3;
- the v2 vector is unaffected and still reads as v2 with no root.

## Verdict

**Construction v3 is verified and reproduced.** An implementation
written from the public standards and the specification text, without
reading the bridge code or either excluded generator, produces the same
369 bytes for both statements, the same two roots, and the same
consistency path — and verifies prefix consistency between two
registered statements using nothing but the statements, the proof and
the public key. That is the property v3 claims and it holds.

On the question the `experimental` marker in
`docs/INTEGRATION-SURFACE.md` is about: this run is an independent
*implementation* of v3, not an independent *party*. It satisfies
implementation independence and does not satisfy personnel
independence, for the reasons in **Affiliation**. F1 should be resolved
before or alongside clearing the marker, since it concerns the
consistency-proof companion that v3's central claim depends on; F2–F4
are precision and vector-quality items that do not block it.
