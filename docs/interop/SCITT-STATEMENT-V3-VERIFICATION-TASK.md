# External verification task: SCITT statement construction v3

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

**What this is.** Bridge runs B1 and B2 verified and reproduced the
v2 Signed Statement from public standards alone
([SCITT-STATEMENT-VERIFICATION-TASK.md](SCITT-STATEMENT-VERIFICATION-TASK.md)).
Construction v3 adds one thing: the **derived root** over every record
up to the one the statement covers, in the signed payload. Two v3
statements of one chain can then be connected by a prefix-consistency
proof without the chain itself. This task — bridge run **B3** — asks an
independent implementer to verify and reproduce v3 from the text below
and the referenced standards, without reading this repository's code.

**Why it matters.** Until an independent run reproduces it, the
construction is recorded as experimental (`docs/INTEGRATION-SURFACE.md`).
What v3 claims — that a holder of two statements and one proof, with no
chain, can check that the later state extends the earlier one — is
interoperable in fact only once someone else's code says so.

## Contamination boundary

You MAY read:

- RFC 9052 (COSE), RFC 9597 (CWT claims in COSE headers), RFC 8032
  (Ed25519), RFC 8949 (CBOR), RFC 9679 (COSE Key Thumbprint), RFC 6962
  and RFC 9162 (Merkle trees, consistency proofs)
- `docs/interop/scitt-statement-vector-v3.json` — the vector under test
- `docs/interop/scitt-statement-vector.json` — the v2 vector, for the
  shared inputs and as a regression check
- `docs/specs/pala-1/PALA-1.md` (§1.2 and §4.1 record hash, §4.3 Merkle tree),
  `docs/specs/pala-1/consistency-proof.md` (§1 the derived tree, §2 the
  proof), and the published vector data `docs/specs/pala-1/test-vectors.json`
  and `docs/specs/pala-1/consistency-vectors.json`
- `draft-sparysh-pala-audit-02`, section "Relationship to transparency
  services" (on the datatracker or in `standards/`)
- this file, and your own B1/B2 code and run records

You MUST NOT read, until your report is submitted:

- `src/palimpsests/**`, `tests/**`, `benchmarks/**`
- `docs/interop/gen_scitt_statement_vector_v3.py` and
  `docs/specs/pala-1/palaudit_ref.py` — the vector's statements and roots
  were computed with them, so reading them would make your agreement ours
- any pull request, issue, or commit history of this repository
  touching the bridge or statement v3

As in B1 and B2, your reading of the text is what is under test. Where
this file, the vector's prose, the draft and an RFC disagree, the RFC
wins over everything else, and the disagreement is a finding we want.

## Construction v3

Everything is as in v2 except the two items marked **new**.

**The message** is a tagged COSE_Sign1 (CBOR tag 18, first byte `0xd2`):
`[protected, unprotected, payload, signature]`, where `unprotected` is
the empty map, `payload` is attached (a byte string, never nil), and
`signature` is the 64-byte Ed25519 signature (COSE alg -8) over the
Sig_structure `["Signature1", protected, h'', payload]` (RFC 9052 §4.4).

**The protected header** is a CBOR map with exactly these labels,
encoded in ascending order:

| Label | Value |
|---|---|
| 1 (alg) | -8 (EdDSA) |
| 3 (content type) | **new:** the text string `application/vnd.palimpsests.pala1-head-v3+cbor` (v2: `application/vnd.palimpsests.pala1-head+cbor`) |
| 4 (kid) | the RFC 9679 COSE Key Thumbprint of the verification key — SHA-256, all 32 bytes — over the deterministic CBOR encoding of `{1: 1, -1: 6, -2: x}` (OKP, Ed25519, public key `x`) |
| 15 (CWT claims) | `{1: issuer, 2: subject}`; `subject` is `pala-1:chain:` followed by the full chain head in lowercase hex |

A protected header with any other label, without one of these four, or
repeating one, is not this construction and is refused. RFC 9052 permits
further labels in general; this construction does not.

**The payload** is a CBOR map with integer keys in ascending order:

| Key | Value |
|---|---|
| 1 | the chain head — the record hash of record `last_seq`, 32 bytes |
| 2 | `first_seq`, unsigned integer — the first record this publication reports |
| 3 | `last_seq`, unsigned integer |
| 4 | the text string `pala-1/v1.0` |
| 5 | **new:** the derived root, 32 bytes |

A payload map that repeats a key is refused: the same signed bytes would
read two ways. A payload whose keys are distinct but not in this
deterministic encoding is reported as a finding of its own, and the
verdict on the values is reached apart from it; a verifier does not
refuse on the encoding alone.

**The derived root** (key 5) is the PALA-1 §4.3 tree over the record
hashes of records `0 … last_seq`, in seq order — `consistency-proof.md`
§1: leaf(d) = SHA-256(0x00 ‖ d), node(l, r) = SHA-256(0x01 ‖ l ‖ r), an
unpaired node promoted, never duplicated. **It always starts at record 0,
whatever `first_seq` says.** A statement that reports records 8–11
(`first_seq = 8`) carries the root over 0–11. A root over
`first_seq … last_seq` would connect to nothing in a consistency proof.

**Version rule.** The content type, which is signed, says which
construction a statement is. A v2 statement carries exactly payload
keys 1–4; a v3 statement exactly 1–5 with a 32-byte key 5. A key 5 under
the v2 content type, or the v3 content type without key 5, must be
refused — a statement that contradicts its own signed description is not
read either way.

**What a verifier may claim about the root.** Without the chain, the
root is *carried*: the signature covers it, and nothing more is known.
With the chain, it can be *recomputed* and compared. A report must not
call an unrecomputed root verified.

**What it may not claim about the head** (added after bridge run B3, F3).
Without the chain, nothing binds payload key 1 to key 5: a statement
pairing an earlier record's head with a later root is accepted, and a
consistency proof between two roots never reads a head. What two
statements and one proof establish is a relation between the two
**roots** — not that either head belongs to the tree its root describes.

**The range** (B3, F4): `0 <= first_seq <= last_seq`. A statement
outside it is refused, by the builder and by the verifier alike.

**Contamination boundary, as a rule** (B3, U2): for any future run, the
excluded files are every generator (`gen_*.py`) and every reference
implementation that computed a published expected value — not only the
ones a task names.

## The task

1. **Roots.** From `subject_chain.record_hashes_hex` (12 record hashes,
   seq 0–11), compute the derived root over the first 8 and over all 12
   with your own code, and compare with `statements.*.inputs.root_hex`.
   *Stretch:* recompute the 12 record hashes themselves from the headers
   in `test-vectors.json` (PALA-1 §4.1), and check your tree against
   `consistency-vectors.json` too.
2. **Parse and verify** both statements in `statements` (`earlier`,
   `later`) as in the v2 task, steps 1–4: tag, structure, the Ed25519
   signature with `key.public_key_hex`, the protected header label by
   label, the payload against the inputs.
3. **The new parts.** Content type is the v3 string; the payload has
   exactly keys 1–5; key 5 equals the root you computed in step 1 over
   records `0 … last_seq` — for `later` that is 0–11 even though its
   `first_seq` is 8.
4. **The case v3 exists for.** Take the two roots **from the two
   statements' payloads** — not from your step 1 — and verify the proof
   in `consistency` (from size 8 to size 12, `path`) by RFC 9162
   §2.1.4.2. Report that this check used nothing but the two statements,
   the proof and the public key.
5. **Reproduce** both statements byte-for-byte from the inputs and the
   private seed in `key` (Ed25519 is deterministic). If your bytes
   differ, say exactly where; a legitimate encoding divergence is a
   specification finding, not a failure of your run.
6. **Tamper.** Confirm each item in `tamper_expectations` fails the way
   it claims to. The version rule needs statements of your own: sign a
   v2 payload under the v3 content type, and a v3 payload under the v2
   content type, with the vector's key — both must be refused.
7. **Regression.** The v2 vector's statement still verifies, and reads as
   v2 with no root.
8. **Adversarial (optional, valued)** — for example: a root over
   `last_seq` or `last_seq + 2` records; a root over `first_seq … last_seq`;
   payload keys out of order or duplicated; key 5 of 31 or 33 bytes; a
   `first_seq` greater than `last_seq`. Report how a careful verifier
   should treat each. Two are settled above: keys out of order are
   reported, repeated keys refused.

## Deliverables

- Your verifier and constructor code, any language, in whatever state
  it ran — polish is explicitly not requested.
- A run report: what you did, in what order, what matched, what did not,
  wall-clock time spent; whether AI assistance was used, and how.
- An ambiguity log: every place this file, the vector, the draft or a
  standard admitted more than one reading, even if you resolved it
  correctly.

## Acceptance

The run is complete when every expectation in the v3 vector, and every
statement in "Construction v3" above, is either reproduced or
contradicted **with the divergence stated precisely**. A contradiction
is a first-class result. Do not bend your reading to match our bytes.

## Reporting

As for B1 and B2: a pull request adding
`docs/specs/pala-1/independent-runs/turak/scitt-statement-b3/` with the
run report, the code and the ambiguity log, and the association stated
plainly — a maintainer's run, not an unaffiliated external one. Your
name, the date, and the commit hash of the vector file you tested go
into the verification record. Once B3 reproduces v3, the SCITT bridge
stops being marked experimental in `docs/INTEGRATION-SURFACE.md`.
