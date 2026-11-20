# SCITT interop — what a registered PALA-1 head proves, and what it does not

The SCITT bridge (`src/palimpsests/audit/pala/scitt.py`) exports one
chain head as a Signed Statement (RFC 9052 COSE_Sign1 in RFC 9943's
vocabulary) for registration with a transparency service. This page
states, in claim-sized sentences, what the resulting evidence is —
because "registered with a transparency service" is a phrase that
invites more than it delivers.

## 1. What leaves the device

One COSE_Sign1 per published head: an attached payload
`{head, first_seq, last_seq, "pala-1/v1.0"}` under a protected header
carrying `alg`, the payload's content type, `kid` (RFC 9679 thumbprint
of the verification key) and CWT claims `iss`/`sub` (RFC 9597, label 15)
with the **full** head in `sub`. No record body, no model output, no
timing detail. The construction was independently reproduced
byte-for-byte from the RFCs twice (bridge runs B1 and B2,
`docs/specs/pala-1/independent-runs/turak/`), after B1 found and #192
fixed a missing `kid` (RFC 9943 §6 MUST).

**Construction v3** (since 0.13) adds one member: payload key 5, the
derived root over records `0 … last_seq` (`docs/specs/pala-1/consistency-proof.md`
§1), under its own content type `application/vnd.palimpsests.pala1-head-v3+cbor`.
Everything else is v2's. It is stated byte by byte in
[SCITT-STATEMENT-V3-VERIFICATION-TASK.md](interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md)
and was reproduced independently from that text in bridge run B3
(`independent-runs/turak/scitt-statement-b3/`). What v3 is for is §8.

## 2. What a receipt proves

A receipt is the transparency service's countersigned statement that
**this exact Signed Statement was included in its append-only log at
the time it says** — inclusion under the service's identity and clock.
Combined with the statement's own signature, a verified receipt yields
three facts, each attributable:

1. *Some holder of the issuer key* committed to head `H` for range
   `[first, last]` — the statement's Ed25519 signature.
2. *The service* included that commitment in its log at time `T` — the
   receipt's inclusion proof and countersignature.
3. Therefore `H` **existed by `T`**: a chain later presented with head
   `H` cannot have been fabricated after `T`, and a chain whose head is
   *not* `H` is not the chain that was registered.

That is the whole of it: **existence-in-time of a head**, anchored to a
named service. It is exactly the property a PALA-1 trail cannot supply
from inside itself, and exactly why the bridge exists.

## 3. What a receipt does not prove

- **Nothing about the chain's content or quality.** Registration is not
  review. The service never saw a record; it countersigned a digest.
- **Nothing about internal consistency or completeness.** Those are
  `pala verify`'s questions (§7.1 chain check; completeness against an
  anchor). A receipt makes a *good anchor* — a receipted head supplied
  as `--anchor` turns the completeness question into "does this chain
  end at the head that existed by `T`?" — but it does not answer the
  question by itself.
- **Not endorsement, not certification, not conformity.** "Registered"
  means submitted and included; every other word is an overclaim.
- **Not growth after `T`.** A receipt covers the head it names. That a
  chain which grew past `H` still extends it is shown by a
  prefix-consistency proof (`pala-consistency-proof/1`, since 0.12); with
  v3 statements the proof connects two registered roots (§8).
- **Only as much as the service is trusted.** Receipt verification
  follows the service's protocol and key; the bridge verifies
  *statements*, never receipts — a deliberate boundary, so that trust in
  the service is never silently laundered into trust in the format.

## 4. Verified versus reported

The overclaim rule applies to every sentence a deployment writes:

- A verifier that has run `verify_statement` with a key it
  trusts may say the range is **verified against a signed head**.
- A verifier that has additionally verified the receipt per the
  service's protocol may say the head **existed by `T` per service `S`**.
- Anything short of that — a statement not checked, a receipt not
  verified, a key not trusted — is **reported, not verified**, and is
  worded that way.

## 5. Evidence on record

| Run | Side | Result |
|---|---|---|
| B1 (`independent-runs/turak/scitt-statement/`) | statement, v1 | reproduced byte-for-byte; four findings, one an RFC 9943 MUST — fixed in #192 |
| B2 (`independent-runs/turak/scitt-statement-b2/`) | statement, v2 | 61/61, reproduced byte-for-byte, `kid` thumbprint re-derived; four refinements — folded in #194 |
| B3 (`independent-runs/turak/scitt-statement-b3/`) | statement, v3 | 155/155, both statements reproduced byte-for-byte; the consistency proof verified from the two statements' roots alone; four findings — one in the verifier (an inverted range accepted), fixed in 0.13.1 |
| Registration run 1 (`docs/interop/registration-run-1/`) | registration + receipt | registered with the reference implementation, receipt verified by its verifier and offline from the published artifacts; finding: the reference implementation still expects the draft-era CWT-Claims label 14 (RFC 9597: 15) — patched as infrastructure, diff published |

The statement side is final-RFC. The receipt side, in the reference
implementation, is a draft-era CCF receipt format; a run against a
hosted third-party service with final-RFC receipts is the next class of
evidence and is not yet on record.

## 6. Claim templates

Use these sentences; do not improve them.

- "The chain head `H` (range `a–b`) was registered with `S` on `T`;
  receipt verified per `S`'s protocol."
- "The statement over `H` verifies against issuer key `K` (thumbprint
  `kid`)."
- "This trail's head as of `T` existed by `T`, per `S`."
- (v3) "The chain state of `M` records extends the state of `N` records:
  statements over both, verified against `K`, and a consistency proof
  between their roots."

Not: "audited by", "certified by", "compliant with", "witnessed" (the
format reserves *witnessed* for WITNESS records with receipts that a
verifier has actually checked).

## 7. Operating notes

- Register **the full head** in `sub`; a truncated head collides across
  chains at the truncation's birthday bound and services index by it
  (B1 F4).
- Use Ed25519 (`-8` or `-19`, §9) when byte-for-byte reproduction of the statement matters;
  ES256 signatures are library-dependent bytes (`scitt.py` module
  docstring, byte-stability mode 1).
- Key custody is the deployment's policy. The bridge takes any key the
  `cryptography` package can sign with and never stores one.
- Ecosystem drift is real: the reference emulator lagged RFC 9597 by one
  label. Expect to read the service's protocol, not to assume it.

## 8. Two v3 statements and one consistency proof

**What they establish, without the chain.** A holder of two v3
statements of one chain — sizes `N < M`, both verifying against the same
key — and a `pala-consistency-proof/1` between their roots can check,
with nothing else, that the tree of `M` records extends the tree of `N`:
every record before `N` in the later state is, by hash, the record at
the same position in the earlier one. With both statements registered,
the same holds between two dated entries of a transparency log. That is
the case v3 exists for: a regulator's copy of last quarter's statement,
this quarter's statement, and a proof — no chain transferred.

**What they do not establish** (bridge run B3, finding F3). The relation
is between the two **roots**. Nothing in a statement binds its head
(key 1) to its root (key 5) without the chain: a statement pairing one
record's head with a later tree's root verifies, and so does a
consistency proof that never reads a head. To say that a head belongs to
its root's tree, a verifier needs the chain — or an inclusion proof,
which no statement carries.

**What a verifier may say about a root.** Without the chain: *carried* —
signed, not recomputed. With the chain: *recomputed* and compared.
`verify_statement` reports which (`root_status`), and a report never
calls a carried root verified.

**What a verifier refuses, and what it reports.** The protected header
carries exactly labels 1, 3, 4 and 15; a statement with any other label,
or without one of them, is not this construction and is refused, though
RFC 9052 permits further labels in general. A map that repeats a key —
payload or protected header — is refused: the same signed bytes would
read two ways. A payload or a protected header whose keys are distinct
but not in the deterministic encoding is refused (since 0.15; before, a
payload was reported in `payload_encoding` and accepted): see
[section 11](#11-one-statement-one-encoding-one-name). A message, a protected header or a payload that is one CBOR item
*followed by further bytes* is refused (since 0.15): an artifact that is a
statement plus something else is not the statement, and a strict decoder
— the independent verifier of bridge runs B2 and B3 is one — already
rejects it.

Every refusal is a `StatementRefused` whose `code` names the check that
failed (`docs/INTEGRATION-SURFACE.md`, channel 8). The code is what to
branch on; it names a check, never a cause — a statement for another
chain, a corrupted download and a forgery are refused alike.

## 9. Algorithms

The protected header's `alg` (label 1) is one of three values:

| `alg` | Meaning here | Key | Reproduces byte for byte |
|---|---|---|---|
| `-7` | ES256 | ECDSA on P-256 | no — the signature is library-dependent |
| `-8` | EdDSA, used as Ed25519 | Ed25519 | yes |
| `-19` | Ed25519 (RFC 9864), since 0.15 | Ed25519 | yes |

**`-19` is an addition to the set, not a new construction.** RFC 9864
gives Ed25519 its own identifier and deprecates `-8`, which names a
family and leaves the curve to the key. Content types, payloads and
protected-header labels are those of v2 and v3; the only thing that
differs between a statement under `-8` and the same statement under
`-19` is one signed byte of the protected header, and so the signature.
The payload and the `kid` are identical — a thumbprint is of the key,
not of the algorithm. `docs/interop/scitt-statement-vector-alg19.json`
is the two published statements built again under `-19`, with that
comparison stated in the file.

**Compatibility runs one way.** Every statement issued under `-7` or
`-8` is unchanged and verifies as before. A statement under `-19` is
refused by a verifier from before 0.15 as an unsupported algorithm: it
reads nothing, and does not read something wrong. A statement cannot be
relabelled from one identifier to the other, because the header is
signed.

**The key must be of the type the algorithm means** (since 0.15). Under
`-8` and `-19` the key is Ed25519; under `-7` it is on P-256. Anything
else is refused before a signature is checked (`key_type_mismatch`).
Before this check a statement signed with Ed448 under `-8` verified
against the Ed448 key, while its `kid` was computed as if the key were
Ed25519.

**Which to emit.** The builder's default stays `-7`, and `-8` stays
valid. Emit `-19` when the service that will register the statement
accepts it; a service that has not adopted RFC 9864 refuses it.

**What is on record for `-19`, and what is not.** Bridge runs B1–B3
reproduced the construction under `-8`. No independent party has yet
built or verified a statement under `-19` from this text: until one
does, `-19` rests on this implementation and its vector alone.

## 10. Refusals

A statement `verify_statement` does not accept is refused with one of
21 codes (`STATEMENT_REFUSAL_CODES`). The code names the check that
failed, never a cause; the vocabulary is open, so a release may add a
code but never rename one or give it another meaning.

`docs/interop/scitt-statement-refusal-vectors.json` gives a refused
statement for every code, so that another verifier can compare its
refusals with these: 84 cases. Eighty are a published statement
with one change — signed again with the same test key where the change
touches what is signed, so that it fails on the check it is about; four
are inputs that are not a statement at all. The first 64 are the cases
published before the encoding rule of section 11 and are unchanged, ids
and bytes; the 20 after them are that rule's.
Each of the three algorithms has a case that reaches the signature
check and fails there. The file states the order of the checks, which
decides the code when a change could break more than one, the keys
(as JWK), and the record hashes of the 12-record chain the root cases
are verified against.
It is generated by `gen_scitt_statement_refusal_vectors.py` and
regenerates byte for byte.

Not in the file: inputs that depend on a language's types (a message
that is not bytes, a key that is not a public key) and ES256 statements
that verify, whose signatures do not reproduce. Those stay in this
package's test suite.

## 11. One statement, one encoding, one name

**A valid signature is not an identity.** A COSE_Sign1 signature covers
the protected header and the payload. It does not cover how the envelope
around them is written — the tag, the array head, the length of each
byte string — nor the unprotected header at all. Each of those can be
written several ways, and every combination verifies under the same
signature and has another SHA-256. Measured on the three published
statements before 0.15: 34 375 such writings of each, all accepted, all
with different hashes; the unprotected header could be an integer. None
is a forgery — the signed content is the same — but a reference to a
statement by its digest, a deduplication, or a log leaf computed over
the statement's bytes then depends on who last touched them.

**The rule (since 0.15).** A verifier accepts one encoding:

- the envelope: tag 18 as the one byte `d2`, a definite array of four
  (`84`), each of the three byte strings with its shortest definite
  length;
- the protected header and the payload: the deterministic encoding of
  RFC 8949 §4.2.1 — shortest integers and lengths, no indefinite
  length, keys in bytewise order;
- the unprotected header: a map (RFC 9052 §3), of a definite length,
  with no label twice, and its count of entries written in the shortest
  form — the count is a head of the envelope like the others, so an empty
  header is the one byte `a0` and not `b8 00`. **What it holds, and how
  that is written, is not judged.** A transparency service puts its
  receipts there (RFC 9943, label 394) with its own encoder; nothing in
  it is signed.

Anything else is refused: `non_deterministic_encoding` for the envelope,
the protected header or the payload, `unprotected_header_malformed` for
the header. A check that names what is wrong more exactly — a repeated
key, an indefinite-length map in a signed part, trailing bytes — is
reached first, so no case published earlier changes its code. The
encoding of the envelope and of the protected header is judged before
the signature, so that code depends on the bytes alone; the payload's
after it, with the payload's other checks.

**The name.** `StatementCheck.statement_id` is the SHA-256 of the
statement with its unprotected header emptied:

    SHA-256( d2 84 || bstr(protected) || a0 || bstr(payload) || bstr(signature) )

For a statement with an empty unprotected header — as
`build_signed_statement` writes it, and as every published vector is —
that is the hash of its bytes, and those bytes are the only ones a
verifier accepts for it: of the 34 375 writings measured, one. Attaching a receipt changes the bytes and
their hash and leaves the id as it was. This is the id to use for a
reference, a deduplication or a comparison between two parties' copies.

What the id is not: a name for the *content*. It includes the signature,
so the same payload signed twice with a non-deterministic algorithm
(ES256) is two statements with two ids; under `-8` and `-19` the
signature reproduces and so does the id. Nor does it say the statement
was registered anywhere — a receipt says that, and this package verifies
no receipt.

**Vectors.** `docs/interop/scitt-statement-identity-vectors.json` gives
the id of each published statement and six statements that verify with
something in the unprotected header — a receipt placeholder under 394, a
repeated key id, a private label, and one written the way another
encoder might — each with other bytes and the same id. It is generated
by `gen_scitt_statement_identity_vectors.py` and regenerates byte for
byte. The refused writings are in the refusal vectors of section 10.

**What this does not settle.** Which bytes a transparency service hashes
into its log is that service's rule, not this construction's: one may
hash the statement as registered, another its `Sig_structure`. The id
defined here is this construction's name for a statement and is computed
by its holder; it is not claimed to equal any service's leaf.
