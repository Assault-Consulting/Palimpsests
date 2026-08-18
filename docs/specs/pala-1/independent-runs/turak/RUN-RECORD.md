# PALA-1 verification run — record

Return this file together with your verifier source. The ambiguity log
is part of this record.

## Run metadata

| Field | Value |
|---|---|
| Date of run | 2026-08-18 |
| Spec version verified | PALA-1 v1.0 (tag `pala1-v1.0`) — **confirmed**: all four input digests matched `fetch-inputs.sh` exactly (transcript in `output/full-run.log` §0) |
| Implementer (name / handle) | Oleksii Turak |
| Contact (email or GitHub) | olexii.turak@gmail.com |
| Association with the project | Not a committer — the implementer's identity does not appear in the repository's commit history. A local copy of the project (which is open source and public) is present on the machine used for the run; it was not used, see "Eligibility" below. |
| Eligibility attestation | **I have not read the reference implementation (`palaudit_ref.py`), the vector generator (`gen_vectors.py`), the production codec under `src/palimpsests/audit/`, the codec tests, `INDEPENDENT-VERIFICATION.md`, or either earlier run's verifier or logs. I worked only from the four allowed inputs of kit README §1, fetched at tag `pala1-v1.0` and digest-checked before use. — Oleksii Turak, 2026-08-18.** |
| Method disclosure | **Perl 5.42.2, core modules only.** `Digest::SHA` and `JSON::PP` for the pass bar; no third-party dependencies. Verifier core `verifier/PALA1.pm` = 337 lines (§2.1 decode, §2.2 TLV, §2.4 container, §7.1 chain, §7.2 completeness, §4.3 Merkle in both constructions). For the optional §4.4 extra the environment had **no crypto library at all**, so `verifier/AESGCM.pm` (245 lines) implements AES-256-GCM from FIPS-197 and NIST SP 800-38D, including the S-box built from its algebraic definition rather than pasted as a table; it is self-tested against FIPS-197 C.3 and SP 800-38D GCM cases 13/14/16 **before** it is allowed to make any claim about a PALA-1 body. Perl was chosen deliberately: the reference implementation is Python, so a different language removes any possibility of structural borrowing. AI-assisted; the agent worked only from the allowed inputs. |
| Time spent (optional) | ≈ 2 hours (single session) |

### Eligibility

The kit (§1) disqualifies a fresh run if the implementer has read the
reference implementation, the production codec, the codec tests, or any
earlier run's verifier or logs. None of them were read. Specifically,
none of `palaudit_ref.py`, `gen_vectors.py`, `INDEPENDENT-VERIFICATION.md`,
`ANCHOR-SOURCES.md`, `REGISTRIES.md`, `profiles/inference-vectors.json`,
`profiles/gen_inference_vectors.py`, anything under
`src/palimpsests/audit/`, anything under `tests/`, or anything under
`docs/specs/pala-1/independent-runs/` was opened at any point.
Pathnames of some of those files were unavoidably observed while
locating the kit itself; no content from any of them was.

What was read: the three verification-kit files (`README.md`,
`RUN-RECORD-TEMPLATE.md`, `fetch-inputs.sh` — the kit directs you to
read these), and the four allowed inputs fetched at `pala1-v1.0` and
digest-checked (`PALA-1.md`, `profiles/robotics.md`,
`profiles/inference.md`, `test-vectors.json`). Every value in this
record was produced by the Perl verifier in `verifier/`, written from
the specification text.

**On the local copy.** The run was carried out on a machine that also
holds a local copy of the project — which is open source and publicly
available, so its presence says nothing a reader could not arrange for
themselves in a minute. It was not used: the four allowed inputs were
fetched fresh from the frozen tag and digest-checked, the verifier was
developed in a separate directory with no path into the copy, and the
off-limits files listed above were not opened. Mentioned only so the
record is complete.

What the run is: a from-scratch second implementation in a different
language from the reference, which reproduces every §8 value and every
published demo diagnosis, and whose ambiguity log and single defect
report below are offered on their own merits.

## §8 Expected results — reproduced values

All eleven reproduced on the verifier's **first execution**, with no
adjustment to the implementation afterwards. Transcript:
`output/full-run.log` §2.

| # | Value | Result | Computed (if diverged) |
|---|---|---|---|
| 1 | `chain_head` | **MATCH** | `3a1a3673f50498eb1d1c6f94b983d6c606cd85ed53627b4e4ffe55153c7af813` |
| 2 | `chain_ok` | **MATCH** | `true` |
| 3 | `record_count` | **MATCH** | `12` |
| 4 | `breaks` (empty) | **MATCH** | `[]` |
| 5 | `gaps` (empty) | **MATCH** | `[]` |
| 6 | `violations` (empty) | **MATCH** | `[]` |
| 7 | `complete_to_anchor` (against published `anchor_head`) | **MATCH** | `true` |
| 8 | `anchor_head` | **MATCH** | `3a1a3673f50498eb1d1c6f94b983d6c606cd85ed53627b4e4ffe55153c7af813` (computed head equals it) |
| 9 | `merkle_tree_hash` (recomputed from `merkle.leaves`, not echoed from the record TLV) | **MATCH** | `518f5be5173250f705e3bda029ec1c11ac5c4459115c07dde5bc1021d9f468db` |
| 10 | `merkle_leaf_count` | **MATCH** | `30` |
| 11 | Leaf-7 inclusion proof (length 5) verifies against the recomputed root | **MATCH** | verifies; `proof_len = 5` |

Extras beyond the pass bar — all run, all passing:

- **Per-record `record_hash`** recomputed as `SHA-256(header_bytes)` for
  all 12 records; matches every published `record_hash`.
- **`body_digest`** recomputed over exactly `body_len` bytes for both
  bodies (seq 3, 75 bytes; seq 5, 44 bytes).
- **§4.4 decryption of the seq-3 body** to the published plaintext
  `clear path ahead, one pedestrian at 12m, static`, using the derived
  nonce `000000000300000000000000` and the 26-byte AAD
  `seq ‖ boot_id ‖ record_type`. Re-encrypting that plaintext reproduces
  the published body **byte-identically**.
- **Both §4.3 constructions** (iterative promotion, RFC 6962 recursive)
  implemented separately; they agree on the published 30 leaves and on
  every leaf count from 0 to 200.
- **The leaf-7 proof was regenerated independently** and is byte-identical
  to the published `merkle.proof`; all 30 leaves verify; a leaf-8 digest
  folded through the leaf-7 path is correctly rejected.
- **The `MERKLE` record's own TLVs** (`0x0011`, `0x0012`) agree with the
  recomputed root and leaf count, and its `body_len` is 0 as §4.3 states.
- **The `ANCHOR` record's `ANCHOR_HEAD` TLV** equals `record_hash` at seq 8
  (`14434088e5f5866cf0276ba5a9055d8ee0d115a750b2cdf9cc4006d9481b29b4`),
  and checking completeness against it yields `anchor_lag = 3`.
- **The §8 narrative table was checked against the bytes** — all 12 record
  types, every TLV the prose attributes to a record (`SHED_CLASS = 1`,
  `SHED_COUNT = 400`, `SHED_WINDOW_NS = 12 s`, `WITNESS_KIND = 1`,
  `WITNESS_RANGE 0–9`, `SHRED_KEY_ID = 7`, the three `ORIGIN_*` triples),
  and eight cross-cutting envelope claims. 50 checks, all passing.
- **The seq-5 `AGGREGATE` body** parses as a §3.2 TLV sequence and decodes
  to the robotics profile's §4 tags: `AGG_WINDOW_NS = 1 000 000 000`
  (1 s), `AGG_SAMPLE_COUNT = 30`, flow min/max/mean = 120 / 4310 / 890
  milli-pixels — consistent with the profile's 30 Hz claim.

## §8 Mutation demos

All seven ran; every published diagnosis reproduced exactly, including
the free-text `anchor_reason` strings. Transcript: `output/full-run.log` §3.

| Demo | Ran? | Diagnosis matched the spec's promise? |
|---|---|---|
| `body_bitflip` | Yes | **Yes** — `body_digest` mismatch detected, `chain_ok` still `true`, and `chain_head` byte-identical to the unmutated chain. Body damage and chain damage are genuinely distinct failures. |
| `unknown_record_type` | Yes | **Yes** — `chain_ok = true`, `count = 13`, `uninterpretable = [12]`, `breaks = []`. |
| `tail_truncation` | Yes | **Yes** — `chain_ok = true` without an anchor; `complete_to_anchor = false` with one; reason string matched verbatim. Also confirmed the truncated file is *not* reported as a truncated tail, because it still ends on a record boundary — which is precisely why §7.1 cannot see it. |
| `stale_anchor` | Yes | **Yes** — `anchor_names_seq = 8`, `anchor_lag = 3`, `chain_ok = true`, reason string matched verbatim; reported as an unanchored tail, not a replacement. |
| `seq_gap` | Yes | **Yes** — `chain_ok = false`, `gaps = [99]`, and `breaks = []`: the hashes do link, only the gap betrays it, exactly as §4.1 argues. |
| `missing_genesis` | Yes | **Yes** — and on the *discriminating* input. See below. |
| `unknown_time_with_clock` | Yes | **Yes** — `chain_ok = false`, single violation `[12, "time_trust=UNKNOWN requires wall_clock_ns=0"]`. Also confirmed `wall_clock_ns = 1784000010000000000` round-trips exactly, which is §1.1's whole argument against JCS. |

**On `missing_genesis`.** The published demo is the one strengthened at
the freeze-candidate run, so it discriminates the two readings of §7.1.
The input used here drops record 0, leaving a chain whose first record is
a `BOOT` with a **non-zero** `prev_hash`. Under the reading §7.1's prose
mandates, that is exactly **one** violation at position 0 and **no**
break; under the superseded literal reading of the older pseudocode it
would have been two violations and a spurious break. This verifier
produced one violation, `breaks = []`, on its first run — the corrected
reading, arrived at from the current text without knowing the history.

### Demo inputs constructed differently from the published ones

Thirteen further cases were built and run (`output/full-run.log` §3,
"Independently constructed cases"). All mutations are applied at the byte
level to the §2.4 container and fed to the same verifier. Highlights:

- **A second `GENESIS` appended at seq 12** — §4.2 requires a violation for
  a `GENESIS` at any position other than the first; no published demo
  exercises this direction. Correctly one violation, `breaks = []`.
- **A first record that *is* a `GENESIS` but carries a non-zero `prev_hash`** —
  the other half of the §4.2 rule. Exactly one violation.
- **A TLV whose declared length overruns `header_len`** — §2.2's framing rule,
  diagnosed as an overrun.
- **The file cut mid-record** (20 bytes removed) — reported as a *truncated
  tail*, with `breaks = []` and the 11 preceding records still parsed;
  §2.4 requires exactly this distinction and no published demo covers it.
- **An unknown TLV type `0x7f00` inside a *known* record** — must be hashed,
  must not cause rejection. Confirmed both: `chain_ok = true`, and the
  record's hash demonstrably covers the unknown bytes.
- **Unknown `format_version = 2` carrying a deliberately illegal
  `time_trust = 9`** — the sharp form of §7.6's "MUST NOT apply §7.4".
  Correctly uninterpretable with **zero** violations: the illegal field
  belongs to a version this verifier does not claim.
- **Records seq 6 and seq 7 transposed** — breaks *and* gaps reported.
- **CVE-2012-2459 directly** — `root([a,b,c])` and `root([a,b,c,c])` are
  distinct under promotion; the run also computes what the *duplicating*
  construction would produce and confirms it collides with
  `root([a,b,c,c])`. The spec's choice is not merely stated but shown to
  matter.
- **Both §4.3 constructions compared for every leaf count 0–200** — the spec
  says they agree and invites the implementer not to go looking for a
  discrepancy; this checks the claim rather than taking it.
- **Inclusion proofs for all 30 leaves**, plus a negative: leaf 8 folded
  through leaf 7's path does not reach the root. Proof lengths are 4 for
  two leaves and 5 for the other 28 — a consequence of promotion, and
  consistent with §4.3's "~log₂(n)" rather than a fixed depth.
- **AAD position binding (§4.4)** — the seq-3 body fails to authenticate
  under seq 5's AAD, and fails when only the `seq` field inside the AAD is
  altered. "Bodies cannot be swapped between records" is demonstrated, not
  assumed.
- **Crypto-shredding (§4.4)** — with the key replaced, the body is
  unreadable while `body_digest` still matches and the chain still
  verifies. "Record exists, body unreadable" is reproducible.

## Ambiguity log

Every point where the specification text made a choice necessary. None of
these blocked reproduction of a §8 value; each is a place where a second
implementer could reasonably have chosen otherwise.

| # | Spec section | What was ambiguous | Your documented choice |
|---|---|---|---|
| 1 | §7.1 pseudocode | `MUST h.header_len == actual header bytes else violation`. In a reader that uses `header_len` itself to slice the header out of the container (§2.4 gives no other way to find the boundary), "actual header bytes" is the same number by construction, so the check can never fire. What independent quantity is it comparing against? | Implemented literally — compare the declared `header_len` against the length of the slice actually taken — and let the real semantic weight sit on the §7.4 check that TLV items *end exactly at* `header_len`, which is falsifiable. A reader that obtained framing from elsewhere (an index, a segmented store) could implement this differently and still conform. |
| 2 | §7.1 pseudocode | The word **break** is overloaded. `MUST h.magic == "PALA" else break, stop` uses it as loop control, while the report structure has a `breaks` array meaning "chain link broken at seq N". A bad-magic record could plausibly be read as requiring an entry in `breaks`. | Read as loop control: stop scanning, add **no** entry to `breaks`. A record whose magic is wrong has no trustworthy `seq` to key a break to. Reported as a separate parse-stop condition instead. |
| 3 | §4.3 | An inclusion proof is "the list of sibling hashes on the path from that leaf to the root". A **promoted** node has no sibling at its level. The text never says what a proof emits there. | Emit nothing for a promoted level. Confirmed correct: the independently generated leaf-7 proof is byte-identical to the published `merkle.proof`, and the resulting proof lengths (4 for two leaves, 5 for 28) are what §4.3's "~log₂(n)" phrasing allows. Worth stating explicitly in the text — an implementer who pads promoted levels gets a proof that still verifies for *some* leaves and silently differs in length for others. |
| 4 | §7.6 vs §7.4 | §7.6 says a verifier **MUST NOT** apply §7.4 to a record of unknown version or type; §7.1's pseudocode puts the "TLV items parse and end exactly at `header_len`" check inside §7.4. But §7.6 also freezes `header_len` *for all future versions*, which implies TLV framing stays parseable and therefore checkable, on any version. So: are the §2.2 structural rules a §7.4 check (skipped) or an envelope invariant (always applied)? | Followed the pseudocode: no §7.4 checks at all on an uninterpretable record, TLV parse included. Demonstrated in case F — an unknown-version record carrying an illegal `time_trust = 9` yields zero violations. The alternative reading is defensible and would produce a different `violations` list on a chain mixing versions. |
| 5 | §2.1 / §5 | `wall_clock_ns` is typed **i64** (signed) at offset 108, but §5 describes only "nanoseconds since Unix epoch, or 0", and §7.4 has no check on it beyond the `UNKNOWN ⟹ 0` rule. Negative values are representable and undefined. | Decode signed, per the §2.1 table; do not flag negatives. Untested by the vectors. A pre-1970 timestamp on a `time_trust = HW_RTC` record — the Jetson-without-an-RTC case §5 opens with — is representable and passes every §7 check. |
| 6 | §3.2 | The `AGGREGATE` body is "a TLV sequence, encoded exactly as §2.2". But §2.2's rules are phrased in terms of the fixed header: items begin after byte 156 and the last must end at `header_len`. A body has neither of those landmarks. | Read "exactly as §2.2" as the *item* encoding only (`type u16 ‖ length u16 ‖ value`), with the sequence running from body offset 0 to `body_len`. The seq-5 body parses cleanly and ends exactly at `body_len` under that reading. |
| 7 | §7.2 | `anchor_lag = N` is "N records past the anchored head" — ambiguous between records strictly after the anchored record and a count that includes it. | Records strictly after. The published `anchor_lag = 3` for an anchor naming seq 8 in a 12-record chain confirms this reading. |
| 8 | §3.1 vs §7 | §3.1 makes an evidentiary promise in normative-sounding terms — "**A crash must leave a visibly unclosed span**, because that is the evidence" — but no check anywhere in §7 makes an unclosed span visible, and §7.4 contains no span rule at all. Visible to whom, by what procedure? | Reported span pairing as an observation *outside* the §7 report, since no §7 check licenses putting it inside. See the Defects table — this is the one item worth the maintainers' attention. |

## Defects

Nothing here contradicts a §8 value; the wire is intact and every
published number reproduces. Item 1 is a specification-completeness
gap, not a wire defect.

| # | Location | Description |
|---|---|---|
| 1 | §3.1 / §7.4 / §8 vectors | **An evidentiary promise with no verification procedure, and vectors that quietly exercise the gap.** §3.1 says a crash "must leave a visibly unclosed span, because that is the evidence", and §3.1 frames the whole design limit as "detectable silence". Yet §7 defines no span check: §7.4's list covers time, body/digest agreement, key/length, and TLV framing, and stops there. `span_id` and `parent_span_id` are *envelope* fields, not profile content, so this is not deferred to a profile either. The asymmetry is what makes it worth raising: §7.4 explicitly justifies its one deliberate omission — "`MERKLE_LEAF_COUNT` is deliberately **not** among these checks", with a paragraph of reasoning — while the span omission is silent, so an implementer cannot tell whether it is a decision or an oversight. Concretely, the committed vectors contain a span that demonstrates the gap: records seq 3 and seq 6 carry `span_id = 2222…` with `parent_span_id = 1111…` (the brain span), but **no `SPAN_START` or `SPAN_END` for `2222…` exists anywhere in the chain**. Note this is not a `SPAN_START` without its `SPAN_END` — that would be §3.1's crash evidence, correctly demonstrated; it is a span referenced by two records with neither endpoint. `chain_ok` is `true` and no §7 check fires, which is correct behaviour under the text as written. **Consequence:** two conformant verifiers will differ on whether a user is ever shown an unclosed or unopened span, and the format's headline guarantee — that absence is visible — is not operationalized anywhere a verifier is told to look. **Suggested resolution:** either add a §7.4 span-pairing check (reported as a violation or as a distinct "unpaired span" class), or add a sentence to §7.4 saying span structure is deliberately out of scope and why, matching the treatment `MERKLE_LEAF_COUNT` already gets. Both are text changes; the vectors need not move a byte. |

## Free-form notes

- **All eleven §8 values reproduced on the verifier's first execution**, with
  no debugging against the expected block. The two failures the run did
  hit were both mine, and neither touched a §8 value: a Perl source-encoding
  bug comparing em-dash strings (fixed with `use utf8`), and an incorrect
  assumption in my own narrative checker that the seq-3 `EVENT` shared the
  brain span's `span_id` — it is in a *child* span, which is the encoding
  that led to defect item 1 above.
- **On the document passing its own test.** The specification is unusually
  implementable from prose. Three things carried disproportionate weight:
  §2.3's explicit warning that the nonce is *inside* `body_len` (named as
  "the one place where an implementer can be confidently wrong" — it would
  have been, without the warning); §4.3's statement that the two tree
  constructions agree, which pre-empts a hunt for a discrepancy that does
  not exist; and §7.1's added paragraph on the non-`GENESIS` first record,
  which is the difference between one violation and three. All three read
  like scar tissue from earlier runs, and all three worked.
- **The freeze holds under adversarial input.** Thirteen self-constructed
  mutations, including every §7.4 branch and both directions of the §4.2
  `GENESIS` rule, produced exactly the diagnoses the text promises.
- **On the AES-256-GCM implementation.** No crypto library was available,
  so it was written from FIPS-197 and SP 800-38D. It is included because
  §4.4 is normative and no header-only verifier touches it: the AAD
  position-binding claim and the crypto-shredding claim are both
  falsifiable, and both were tested rather than trusted. It self-tests
  against published NIST vectors before it is permitted to say anything
  about a PALA-1 body.
- **Reproducing this run:** `sh ../../verification-kit/fetch-inputs.sh && sh verifier/run-all.sh`.
  Requires only Perl 5 with core modules. Full transcript in
  `output/full-run.log`; total 140 checks, 0 failures.
