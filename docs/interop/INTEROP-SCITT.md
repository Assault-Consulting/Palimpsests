# SCITT interop: what the bridge proves, and what it does not

The claim discipline for the PALA-1 ↔ SCITT bridge, written after the
loop actually closed: two clean-room verifications of the Signed
Statement (bridge runs B1 and B2), one registration with a
SCRAPI-compatible transparency service, and one receipt verified
(`b2-registration/`). Every sentence below is backed by one of those
records or by the vector's `byte_stability` section.

## The three artifacts, and the claim each one carries

**A chain** is the evidence. It verifies for internal consistency and
— given an anchor — completeness, offline, with no party's
cooperation. Nothing in this document changes that; registration is
never a precondition of a trail's validity.

**A Signed Statement** is one COSE_Sign1 committing to a chain head
and a sequence range. Verifying it (`check_statement_against_head`,
or independently from the RFCs — B1/B2 did) proves: *the holder of
the stated key committed to this head over this range.* It proves
nothing about the chain's contents, and nothing about time.

**A receipt** proves exactly one thing: *a leaf derived from the
statement was included in a particular service's append-only tree, at
a stated tree size, under that service's signing key.* Everything
else commonly read into a receipt is not in it:

- **Not chain validity.** A service registers what it is given; a
  statement over a broken chain registers identically.
- **Not issuer identity.** The service logs a leaf; whether it
  verified the statement's signature, or resolved `kid` to anyone, is
  service policy — in the service we exercised, the statement's
  `iss`/`sub` are not even propagated into the receipt (B4-F3).
- **Not durable existence-in-time.** The receipt is as durable as
  the service and its key. A self-operated instance witnesses only
  itself; a third-party operator adds an independent party; a
  cross-logged or widely-mirrored service adds more. Say which one
  you have.

## The identity question — the one that bites

Bridge run B4 surfaced it concretely (finding B4-F2): the service we
exercised identifies entries — and builds its Merkle leaves — from
**sha256 of the statement's payload**, not of the signed statement.
Two distinct COSE_Sign1 messages over one payload collide into a
single entry; signature and headers are outside the logged identity.

This is the vector's `byte_stability` lesson at the service layer:
"the signature verifies", "these are the published bytes", and "this
is what the log identifies" are **three different claims**. A
consumer of receipts MUST know which identity a given service logs
before treating a receipt as binding a *statement* rather than a
*payload*. When reporting, name the leaf definition — this
repository's records do (`artifacts.json → receipt.verified`).

## Verified vs reported — the overclaim rule, applied

A party that has:

- run `check_statement_against_head` with a key it trusts → may say
  the statement is **verified**;
- reconstructed the Merkle root from the receipt's inclusion data and
  checked the service's signature over it, with the service's
  published key → may say the receipt is **verified** *for that
  service's leaf definition*;
- done neither → reports the range as **reported, not verified** —
  never as witnessed.

The receipt exercised here makes the root the *detached payload*, so
a verifier is forced to reconstruct it before any signature check —
the proof is authenticated despite living in the unprotected header.
That is the right shape; not every service will have it.

## Dependency reality (finding B4-F1)

The first registration attempt failed before any SCITT semantics were
reached: `cbor2` ≥ 6 decodes a tag's array as a tuple, `pycose` 1.1.0
requires a list, and the pair — admitted by the service's own open
pin — cannot decode *any* tagged COSE message. Interop failures at
this layer look identical to protocol failures from the outside.
When a registration fails, capture the raw error body first and
bisect the decode path before touching the statement.

## How to re-verify everything offline

From `b2-registration/artifacts.json` alone: (1) the chain hex →
`pala verify` (expect PARTIAL without an anchor, chain_ok true);
(2) the statement hex against the head with the public key from its
`kid` derivation; (3) the receipt hex: rebuild the root from
`tree_size`/`leaf_index`/`proof` with leaf = the recorded leaf
definition, then check the ES256 signature with the embedded jwks.
No network, no service, no this-repository code required for (2) and
(3) — B1/B2 proved both from the RFCs alone.

## Record

- Statement construction: independently verified and reproduced
  byte-for-byte, twice (B1 against v1 with four findings; B2 against
  v2, 61/61, findings folded back — see
  `docs/specs/pala-1/INDEPENDENT-VERIFICATION.md` §7).
- Registration + receipt: `b2-registration/` — self-operated
  conforming implementation, claim scoped accordingly.
- Open, deliberately: a third-party-operated registration (stronger
  witnessing claim) and an unaffiliated run of the statement task
  against vector v2 (the task file is already shaped for it).
