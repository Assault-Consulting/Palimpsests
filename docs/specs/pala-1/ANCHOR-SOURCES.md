# Anchor sources — a design note

Where the completeness anchor can live, what each choice defends
against, and — the subject that prompted this note — what binding the
anchor to a hardware attestation quote would add. **Non-normative**: the
core specification (`PALA-1.md` §7.2) defines what an anchor *is*; this
note catalogues where one can come from. Nothing here changes a wire
byte, and §"Freeze compatibility" below states that precisely.

| | |
|---|---|
| **Status** | Design note, non-normative |
| **Licence** | CC0-1.0, like the core specification. |

## What the anchor is, restated in one paragraph

Chain verification (§7.1) cannot see a truncated tail: drop the last N
records and what remains is a perfectly linked chain with a different
head. The anchor is the head the chain is *supposed* to have, held
**outside the log** — and completeness (§7.2) is the comparison of the
computed head against it. The anchor store is therefore a deployment
component by design: the format requires that an anchor exist outside
the log and says nothing about what holds it (core §10, open issue 5).
The writer's anchor boundary is pluggable for the same reason.

## The catalogue

| Source | Defends against | Trust rests on | Cost |
|---|---|---|---|
| Local file | Accidental truncation | Filesystem permissions | Zero |
| OS keychain (current default) | Truncation by an actor without keychain access | OS account isolation | Zero |
| PKCS#11 token (shipped, ADR-0004) | Truncation by an actor who owns the host account but not the token's PIN and presence | The token's isolation from the host | A token (SoftHSM covers CI) |
| Peer device | Loss/compromise of one machine | The peer's independence | A second device |
| RFC 3161 TSA (witness path, `WITNESS_KIND = 2`) | Fresh genesis — proves existence at time T | The TSA | Network, per-witness |
| Transparency log (witness path, `WITNESS_KIND = 1`) | Fresh genesis, with public auditability | The log's append-only property | Network, per-witness |
| **TEE-quote-bound store (this note)** | Anchor forgery without hardware compromise | The vendor attestation chain | TEE-class hardware |

The first three hold the *current* head (the §7.2 store); the witness
pair proves *existence at a time* (§7.3, tier C). The TEE option below
strengthens the store leg, not the witness leg — the distinction the
core draws between §7.2 and §7.3 carries through unchanged.

## PKCS#11 token store — shipped (ADR-0004)

The first store outside the host trust boundary is in the code:
`Pkcs11Anchor` / `Pkcs11AnchorStore` behind the existing pluggable
seams, the `[pkcs11]` extra, and `pkcs11` as one more **named source**
in a chain's attempts — a report renders it exactly like `keychain` and
`file`, no schema change. This strengthens the *store* leg (§7.2), not
the witness leg (§7.3): *when* still comes from a witness.

Claim honesty, verbatim from the ADR: **the tier-B mechanism is shipped
and tested; a tier-B claim for a concrete deployment requires a real
token or HSM holding the anchor — SoftHSM in CI proves the code path,
not the tier.**

## TEE-quote-bound anchoring

The design, in one sentence: at anchor time, bind the current chain
head into hardware attestation evidence by placing `SHA-256(head)` in
the quote's user-data field (report data in SGX/TDX-class quotes), and
store the quote alongside — or as — the anchor.

Verification then reads: the quote verifies through the vendor's
attestation chain → the platform with that identity and TCB state,
at quote time, held *this* head. Comparing the computed head against
the quoted one is §7.2 exactly; what changed is what forging the
anchor now costs.

**What it strengthens.** At tier A the anchor's integrity rests on OS
account isolation — the honest statement in the core is that tier A
does not defend against the owner (core §9.2). A quote-bound anchor
moves that boundary: producing a false anchor now requires defeating
the hardware attestation, not editing a keychain entry. It also carries
platform identity as a side effect — a tier-B-flavoured property on the
anchor leg, without TPM NV counters.

**What it does not do — stated with the same discipline as core §9:**

1. It does not attest execution. The quote grounds the *log's head*,
   not the inference that produced the records. Confidential-compute
   execution attestation is a different mechanism at a different layer,
   and this note claims nothing about it.
2. It does not prove freshness by itself. A quote binds a head to a
   platform; *when* still comes from the witness path. The strong
   combination is quote-bound store + periodic witness — each leg
   answering the question the other cannot.
3. It does not help where the hardware is absent. Commodity and edge
   deployments — the systems this format is local-first *for* — keep
   the existing stores. This is an additional rung, not a new floor.

## Freeze compatibility

Everything above fits inside the v1.0 freeze, because the anchor store
is outside the log by design:

- The `ANCHOR` record and its `ANCHOR_HEAD` TLV are unchanged — they
  record a store write, as they always did (§7.2).
- The quote itself lives in the store, a deployment component the
  format deliberately does not describe.
- What v1 **cannot** express is a first-class in-chain witness claim of
  kind "TEE quote": `WITNESS_KIND` is a closed vocabulary (1, 2) in
  version 1, and extending it is a format-version decision — recorded
  in `REGISTRIES.md` as such, not smuggled in as an edit. Until then, a
  deployment can hold quotes store-side without any in-chain claim,
  losing nothing but the chained self-description of the witness.

## Status of this note

A composition of existing mechanisms, documented so the option is
visible; not a commitment to implement. If a deployment driver appears,
the implementation path is an anchor-store backend behind the existing
pluggable boundary — code, tests and a verification-kit note, with the
wire untouched.
