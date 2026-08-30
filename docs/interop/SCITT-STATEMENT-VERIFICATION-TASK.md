# External verification task: the SCITT-bridge Signed Statement

**What this is.** PALA-1's verification record so far covers the wire
format: five independent implementations reproduced the published
chain from the specification and test vectors alone. This task extends
that record to the SCITT bridge: an independent implementer verifies —
and ideally reproduces — the published Signed Statement from public
standards alone, without reading this repository's code.

**Why it matters.** The statement is what a PALA-1 producer registers
with a SCITT transparency service (RFC 9943). If an outside party can
parse and verify it from the RFCs and the vector file below, the
bridge is interoperable in fact, not by our assertion.

## Contamination boundary

You MAY read:

- RFC 9052 (COSE), RFC 9597 (CWT claims in COSE headers),
  RFC 8032 (Ed25519), RFC 8949 (CBOR)
- `docs/interop/scitt-statement-vector.json` (the vector under test)
- `docs/specs/pala-1/PALA-1.md` — for context on what a chain head is;
  the statement task itself does not require implementing the chain
- this file

You MUST NOT read, until your report is submitted:

- `src/palimpsests/**`, `tests/**`, `benchmarks/**`
- any pull request, issue, or commit history of this repository
  touching the bridge

The point of the boundary is that your reading of the *standards* is
the thing under test. Where the vector file's prose and an RFC seem to
disagree, the RFC wins — and the disagreement is a finding we want.

## The task

1. **Parse** `expected.statement_hex` as a COSE_Sign1 message
   (RFC 9052) with your own code — any language. No COSE library is
   required; the message is small and tagged (CBOR tag 18).
2. **Verify** the Ed25519 signature over the Sig_structure
   (RFC 9052, section 4.4) using `key.public_key_hex`.
3. **Decode** the attached payload (a CBOR map) and check it commits
   to `subject_chain.chain_head_hex` with the stated sequence range
   and format id.
4. **Check the protected header**: alg is EdDSA (-8); `kid` (label 4)
   equals the vector's stated RFC 9679 COSE Key Thumbprint of the
   verification key; `content type` (label 3) names the payload; CWT
   claims (label 15) carry the stated issuer and the full-head subject.
   All four labels sit in the *protected* bucket, in ascending order.
5. **Reproduce** (stretch, but valued): rebuild the statement
   byte-for-byte from the inputs — Ed25519 is deterministic, so an
   independent construction that agrees on every byte of the published
   statement is the strongest possible interop evidence. If your bytes differ, say
   exactly where; a legitimate encoding divergence is a specification
   finding, not a failure of your run.
6. **Tamper**: confirm each expectation in `tamper_expectations`
   fails the way it claims to.
7. **Adversarial (optional, valued)**: construct inputs of your own
   design — malformed CBOR, wrong tag, truncated signature, claim
   confusion — and report how a careful verifier should treat each.

## Byte stability — what "reproduce" may claim

Four ways "the same statement" can honestly differ in bytes; the vector's
`byte_stability` section states each precisely. In one line each:

1. **Signature determinism** — reproduction is claimable only because the
   alg is EdDSA (RFC 8032, deterministic by construction). ES256 bytes are
   library-dependent (RFC 6979 is a choice, not a requirement): such a
   vector could claim *verifies*, never *reproduces*.
2. **The unprotected bucket** is outside the signature — mutations there
   keep verification green while changing the artifact. "The signature
   verifies" and "these are the published bytes" are separate claims.
3. **Tag 18** — this vector's statement is the tagged form (first byte
   `0xd2`); an untagged re-encoding is a different artifact.
4. **The Sig_structure is assembled, not extracted** — what is signed is
   `["Signature1", protected, external_aad, payload]`, built by each
   implementation; byte agreement there is the precondition for signature
   agreement.

## History

- **v1** (commit `296f331`) — verified and reproduced byte-for-byte by
  bridge run **B1** (`docs/specs/pala-1/independent-runs/turak/
  scitt-statement/`), which reported four findings.
- **v2** (this file) — resolves F1 (`kid`, protected, RFC 9943 §6 MUST),
  F2 (content type, protected), F4 (full chain head in the CWT subject),
  and rescopes F3 (`statement_sha256`/`length` are expectations for the
  deterministic encoder emitting the tagged form, not signature-bound
  identities). Verified and reproduced byte-for-byte by bridge run **B2**
  (`docs/specs/pala-1/independent-runs/turak/scitt-statement-b2/`), which
  confirmed F1/F2/F4 fixed and F3's rescoping correct, and reported four
  further findings — the substantive one being that the tamper list does
  not exercise Ed25519 `S + L` signature malleability.

## Deliverables

- Your verifier code, any language, in whatever state it ran —
  polish is explicitly not requested.
- A run report: what you did, in what order, what matched, what did
  not, wall-clock time spent.
- An ambiguity log: every place a standard or this repository's
  published material admitted more than one reading, even if you
  resolved it correctly.

## Acceptance

The run is complete when every expectation in the vector file is
either reproduced or contradicted **with the divergence stated
precisely**. A contradiction is a first-class result: in a previous
run on the wire format, the verifier was right and the published
vectors were inconsistent — that finding is the reason this record
exists. Do not bend your reading to match our bytes.

## Reporting

Open an issue in this repository titled
`independent verification: scitt statement` with the report attached,
or send it to the maintainers' published contact. Your run, your
name (or chosen handle), the date, and the commit hash of the vector
file you tested will be added to the verification record, as with the
five wire-format runs before it.
