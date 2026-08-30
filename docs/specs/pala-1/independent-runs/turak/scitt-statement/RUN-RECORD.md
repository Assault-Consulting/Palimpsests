# SCITT-bridge Signed Statement — independent verification run

The run called for by
[`docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md`](../../../../interop/SCITT-STATEMENT-VERIFICATION-TASK.md),
carried out against
[`docs/interop/scitt-statement-vector.json`](../../../../interop/scitt-statement-vector.json).

**Result in one line.** All seven task steps completed. The published
202-byte statement parses, its Ed25519 signature verifies, its payload
commits to the published chain head, and it was **reproduced
byte-for-byte** from the vector's stated inputs by a verifier written
from the RFCs. Every tamper expectation held. **Four findings** are
reported, one of them a violation of a normative MUST in RFC 9943.

## Run metadata

| Field | Value |
|---|---|
| Date of run | 2026-08-30 |
| Vector file tested | `docs/interop/scitt-statement-vector.json` |
| Vector commit | `296f331` (the commit that introduced the file) |
| Vector SHA-256 | `bf81026143d0cb8415667509e1d650b0b7efad7de24eb7907ea4002054bf9491` |
| Repository tree at run | `965e45f` |
| Implementer | Oleksii Turak — olexii.turak@gmail.com |
| Association with the project | **Maintainer.** This is *not* an unaffiliated external run; see "What this run is and is not" below. |
| Verifier | `verifier/` — 1027 lines of Python across three files, standard library only (`hashlib`, `json`, `re`) |
| Environment | CPython 3.12.10, Windows 11 |
| Execution time | 0.33 s for the full 45-check suite |
| Checks run | 45 — 43 pass, 2 report conformance findings (F1, F2); **0 pass-bar failures** |

## The verifier

No COSE library, no CBOR library, and no cryptographic library were used.
The three modules were written from the standards for this run:

| File | Lines | Written from |
|---|---|---|
| `verifier/cbor.py` | 240 | RFC 8949 — a strict definite-length decoder that reports non-shortest heads and out-of-order map keys, plus an encoder that emits only the §4.2.1 deterministic form |
| `verifier/ed25519.py` | 168 | RFC 8032 §5.1 — PureEdDSA over edwards25519, extended coordinates, cofactorless verification, `0 ≤ S < L` enforced |
| `verifier/scitt_verify.py` | 619 | RFC 9052 §4.2/§4.4, RFC 9597 §2, RFC 9943 §6 — the COSE_Sign1 parse, Sig_structure, and the task's seven steps |

`ed25519.py` is self-checked against RFC 8032 §7.1 TEST 1 before it is
trusted with anything: the seed in the vector is that test key, so the
run confirms both that the vector's stated key provenance is real and
that this verifier's signature check agrees with the RFC's own published
signature.

## What was done, in order

1. **Provenance before content.** Derived the public key from
   `private_seed_hex` and matched `public_key_hex`; reproduced the
   RFC 8032 §7.1 TEST 1 signature from the same seed; verified that
   signature with this run's own verifier. Then checked the vector's
   claim about its subject: `chain_head_hex` is the `chain_head`
   published in `docs/specs/pala-1/test-vectors.json`, and
   `first_seq = 0 … last_seq = 11` is that chain's 12 records
   (see ambiguity A6 on reading that file).
2. **Parse** (task step 1) — length, SHA-256, CBOR tag 18, four-element
   array, empty unprotected map, attached payload, 64-byte signature.
3. **Verify** (step 2) — built the Sig_structure as
   `["Signature1", protected, external_aad, payload]` per RFC 9052 §4.4
   and checked the signature over its 146 bytes.
4. **Decode the payload** (step 3) — the four map entries against the
   vector's stated head, sequence range and format id.
5. **Protected header** (step 4) — `alg` and the RFC 9597 label-15 CWT
   claims, then the statement against RFC 9943 §6's requirements for a
   Signed Statement's protected header.
6. **Reproduce** (step 5) — rebuilt the protected header, the payload
   and the signature from the vector's inputs and compared all 202 bytes.
7. **Tamper** (step 6) — the vector's three expectations.
8. **Adversarial** (step 7) — eleven cases of this run's own design.

Full transcript: [`output/full-run.log`](output/full-run.log).
Machine-readable: [`output/results.json`](output/results.json).

## Task steps — what matched

| Step | Requirement | Result |
|---|---|---|
| 1 | Parse `expected.statement_hex` as a COSE_Sign1 | **MATCH** — 202 bytes, SHA-256 `b47ca4f5…6ae997`, tag 18, well-formed |
| 2 | Verify the Ed25519 signature over the Sig_structure | **MATCH** — verifies under `public_key_hex` |
| 3 | Payload commits to `chain_head_hex`, sequence range, format id | **MATCH** — `{1: 3a1a3673…7af813, 2: 0, 3: 11, 4: "pala-1/v1.0"}` |
| 4 | `alg` is EdDSA (−8); CWT claims carry issuer and subject | **MATCH** — and see F1/F2 for what else the header should carry |
| 5 | Rebuild the statement byte-for-byte (stretch) | **MATCH — all 202 bytes.** Protected header (76 B), payload (53 B) and signature (64 B) each reproduced independently |
| 6 | Each `tamper_expectations` entry fails as claimed | **MATCH** — 3 of 3 |
| 7 | Adversarial cases (optional) | **11 constructed**; 2 produced findings (F3, F4) |

The vector is internally consistent: every value in `expected` was
recomputed rather than echoed, and nothing in it had to be taken on
trust. `statement_length_bytes`, `statement_sha256`,
`verifies_with_public_key` and `payload_commits_to_chain_head` are all
correct as published.

### Byte-for-byte reproduction

The strongest evidence the task asked for, and it holds. Working from
`issuer`, `subject`, `chain_head_hex`, `first_seq`, `last_seq`, the
format id and `private_seed_hex`, an independent construction produced
the identical 202 bytes — protected header, payload, and, because
Ed25519 is deterministic, the same 64-byte signature. No divergence to
report, so no encoding question had to be adjudicated by preference.

That reproduction depended on one choice the vector does not state: that
the outer message uses RFC 8949 §4.2.1 deterministic encoding. It does,
but see F3 — nothing requires it to.

## Findings

### F1 — the statement violates a MUST in RFC 9943 §6 *(conformance)*

RFC 9943 §6 requires the `kid` header parameter to be present when
neither `x5t` nor `x5chain` is in the protected header. The published
statement's protected header carries exactly two parameters — `alg` (1)
and CWT Claims (15) — and none of those three. A conforming SCITT
transparency service therefore has no in-band way to resolve the
issuer's verification key; it must be supplied out of band, which the
vector does (`key.public_key_hex`) but the wire format does not.

This is the finding the task said it wanted: the vector's prose and a
standard disagree, and the standard wins. It is a defect in the
statement, not in this run's reading — the run reproduces the bytes
exactly, and those bytes are non-conformant.

Note the RFC is itself softer than it looks: its Figure 3 CDDL (§6.1)
marks `kid` optional with a leading `?`, so an implementer working from
the CDDL alone would not catch this. The conditional MUST is in §6's
prose only. See ambiguity A8.

**Suggested resolution.** Add `kid` (label 4) to the protected header.
It must go in the *protected* bucket — adversarial case A10 shows that a
`kid` added to the unprotected map does not disturb the signature and is
therefore unauthenticated. Adding it changes the statement bytes, the
length and `statement_sha256`, so the vector would be reissued.

### F2 — nothing on the wire says the payload is not a CWT Claims Set *(ambiguity)*

The payload is a CBOR map keyed 1, 2, 3, 4. In a COSE object whose
protected header carries CWT claims under RFC 9597, integer keys 1 and 2
are conventionally `iss` and `sub`. A verifier that reads this payload as
a CWT Claims Set — a reasonable reading for a SCITT Signed Statement —
gets `iss` = 32 raw bytes and `sub` = 0, and RFC 9597 §2 then obliges it
to compare those against the header's claims and reject the statement.

Adversarial case A8 confirms the collision is live: the payload's key 1
is a byte string where the header's `iss` is a text string, so the two
readings are distinguishable but contradictory.

**Suggested resolution.** Declare `content type` (label 3) in the
protected header. RFC 9943's Figure 3 CDDL marks it optional, so this is
a recommendation rather than a second MUST violation — but it is the
parameter that exists to answer exactly this question, and its absence is
what leaves the payload's schema to prose.

### F3 — `statement_sha256` is not a signature-bound identity *(malleability)*

RFC 9052 §9 requires definite lengths and minimum-length arguments, and
states that the restriction applies to the Sig_structure, the
Enc_structure and the MAC_structure — **not** to the COSE message that
carries them. Adversarial case A1 exploits the gap: re-encoding the
protected header's byte-string length in the two-byte form
(`59 004c` for `58 4c`) leaves the protected *content* unchanged, so the
Sig_structure is unchanged and **the signature still verifies** — while
the message becomes 203 bytes with SHA-256 `d5b1d222…`.

The vector publishes `statement_sha256` and `statement_length_bytes` as
expectations, which treats the serialisation as an identity. It is one
only for encoders that choose to be deterministic. Any consumer that
matches a statement by its hash or its length must enforce RFC 8949
§4.2.1 itself; case A1′ confirms this run's decoder does, and rejects the
203-byte variant.

**Suggested resolution.** Text, not bytes: state in the vector that the
statement is encoded in RFC 8949 §4.2.1 deterministic form and that a
verifier MUST reject non-deterministic encodings before treating
`statement_sha256` as an identifier.

### F4 — the CWT subject truncates the chain head to 8 bytes *(design)*

`sub` is `pala-1:chain:` followed by the first 16 hex characters — 8
bytes — of the chain head. Adversarial case A9 signs a second, valid
statement over a head differing in byte 20: the two statements commit to
different chains and carry an **identical** `sub`.

Two different chains therefore collide in the SCITT subject at a 64-bit
birthday bound (~2³² work). A transparency service that indexes,
authorises or de-duplicates by `sub` — which is what `sub` is for —
cannot tell them apart. The payload still commits to the full 32-byte
head, so this is an indexing and authorisation hazard, not a forgery:
anyone who checks the payload gets the right answer.

**Suggested resolution.** Either carry the full head in `sub`, or state
in the vector that `sub` is a non-unique display label and that
authorisation decisions must be made against the payload's full head.

## Tamper expectations

| # | Expectation | Result |
|---|---|---|
| T1 | Flip any bit of the 32-byte head inside the payload → signature verification MUST fail | **Holds** — group equation fails |
| T2 | Flip any bit of the signature → verification MUST fail | **Holds** |
| T3 | Verify against a different expected head → the commitment check MUST fail even though the signature is valid | **Holds** — and this is the distinction F4 turns on |

## Adversarial cases

Eleven cases of this run's own design, with how a careful verifier
should treat each.

| # | Case | This verifier | Should a verifier accept? |
|---|---|---|---|
| A1 | Non-shortest length prefix on the protected bstr | Signature **still verifies**; message hash changes | No — reject non-deterministic CBOR (**F3**) |
| A1′ | The same input through a determinism-enforcing parse | Rejected | Correct behaviour |
| A2 | CBOR tag 98 (COSE_Sign) in place of 18 | Rejected | No — a Sign1 verifier must not accept a multi-signer structure |
| A3 | Untagged COSE_Sign1 | Rejected | Only where the type is established out of band; the task states the message is tagged |
| A4 | 63-byte signature | Rejected on length | No — fail before touching the curve |
| A5 | `S + L` substituted for `S` | Rejected by the range check | No |
| A5′ | The same bytes with the range check disabled | **Accepted** — a second valid signature | Demonstrates why RFC 8032 §5.1.7 requires `0 ≤ S < L` |
| A6 | Duplicate map key in the protected header | Rejected | No — RFC 8949 §5.6 |
| A7 | Payload stripped to `nil`, signature kept | Rejected | No — fail closed; there is no payload to place in the Sig_structure |
| A8 | Payload read as a CWT Claims Set | Contradicts the header's claims | Exposes **F2** |
| A9 | A second head sharing the first 8 bytes | Identical `sub`, valid signature | Exposes **F4** |
| A10 | `kid` injected into the unprotected map | Signature unaffected | Shows an unprotected `kid` is unauthenticated (bears on **F1**) |
| A11 | Trailing bytes appended | Rejected | No — no silent truncation of the input |

## Ambiguity log

Nine entries, in [`ambiguity-log.md`](ambiguity-log.md). None of them
blocked the run; all were resolved by reading a standard, and each is
recorded with the choice made. Three became findings (A5 → F3,
A7 → F2, A8 → F1 context). The rest are places where the vector could
say what it means rather than leaving it to be inferred.

## Eligibility and the contamination boundary

The task's boundary forbids `src/palimpsests/**`, `tests/**`,
`benchmarks/**`, and any pull request, issue or commit history touching
the bridge, until this report is submitted. **None of those were read.**
In particular the branches `feat-scitt-signed-statement` and
`docs-scitt-verification-task` were left untouched.

Read, and disclosed in full:

- **The task's own inputs:** `docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md`
  and `docs/interop/scitt-statement-vector.json`.
- **Public standards:** RFC 9052, RFC 9597, RFC 8949, RFC 8032, and
  RFC 9943 — the last is cited by the task but is not on its
  MAY-read list (ambiguity A1).
- **`docs/specs/pala-1/test-vectors.json`**, to check the vector's own
  statement about where its subject comes from. Not on the MAY-read list
  either (ambiguity A6). It is a published CC0 specification artifact and
  contains no bridge material; the check is optional in the verifier and
  is skipped when the file is absent.
- **Repository conventions only, containing no COSE or bridge material:**
  `docs/specs/pala-1/INDEPENDENT-VERIFICATION.md`, the run records under
  `independent-runs/kurdybaylo/` and `independent-runs/turak/`,
  `pyproject.toml`, `REUSE.toml` and `.gitattributes` — consulted to place
  this run where the project keeps such runs and to match its form.

One incidental exposure, disclosed for completeness. After the run was
complete and this record drafted, running the repository's test suite as
a pre-submission gate produced a collection error naming
`tests/test_scitt_statement.py` and reporting that it imports `cbor2`.
The file itself was not opened, and a module name and an import line
carry nothing about the statement's structure — every value in this
record was fixed before that error appeared. It is logged because a
boundary is only worth what its disclosures are.

## What this run is and is not

Recorded plainly, because the value of a verification record is exactly
its honesty about provenance.

**This is not an unaffiliated external run.** The implementer is a
maintainer of the project. The four external and co-maintainer runs on
the wire format (`INDEPENDENT-VERIFICATION.md` §5) remain the stronger
class of evidence, and §6 of that document explains why. This run does
not claim to be one of those.

**Method disclosure.** The verifier and this record were produced with an
AI coding agent (Claude), working from the task file, the vector and the
RFCs, under the implementer's direction and review. This follows the
precedent of run #4, which was likewise AI-assisted and disclosed as
such. As with that run: the repository was created 2026-07-06, after the
agent's May 2026 training cutoff, so training-data contamination for this
repository is not possible. The agent's session read only the files
listed above.

**What the run does establish.** The published statement is reproducible
byte-for-byte, from the stated inputs, by code written against the
public standards rather than against this repository — and the bytes so
produced are non-conformant with RFC 9943 §6 in a way the repository had
not recorded. A second implementation was enough to find that, which is
the whole argument for having one.

**What it does not establish.** That an outside party would reach the
same conclusions. F1 in particular is worth an unaffiliated confirmation
before it is acted on, since it turns on one sentence of RFC 9943 prose
that the same RFC's CDDL does not enforce.
