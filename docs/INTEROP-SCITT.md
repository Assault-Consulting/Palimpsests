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
- **Not growth after `T`.** A receipt covers the head it names. A chain
  that grew past `H` verifies against `H` only with a prefix-consistency
  proof (planned; roadmap item WS-PROOF). Until then, register the new
  head.
- **Only as much as the service is trusted.** Receipt verification
  follows the service's protocol and key; the bridge verifies
  *statements*, never receipts — a deliberate boundary, so that trust in
  the service is never silently laundered into trust in the format.

## 4. Verified versus reported

The overclaim rule applies to every sentence a deployment writes:

- A verifier that has run `check_statement_against_head` with a key it
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

Not: "audited by", "certified by", "compliant with", "witnessed" (the
format reserves *witnessed* for WITNESS records with receipts that a
verifier has actually checked).

## 7. Operating notes

- Register **the full head** in `sub`; a truncated head collides across
  chains at the truncation's birthday bound and services index by it
  (B1 F4).
- Use EdDSA when byte-for-byte reproduction of the statement matters;
  ES256 signatures are library-dependent bytes (`scitt.py` module
  docstring, byte-stability mode 1).
- Key custody is the deployment's policy. The bridge takes any key the
  `cryptography` package can sign with and never stores one.
- Ecosystem drift is real: the reference emulator lagged RFC 9597 by one
  label. Expect to read the service's protocol, not to assume it.
