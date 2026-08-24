# Cryptographic scope and agility — a design note

What version 1 fixes cryptographically, where a future suite would enter,
and what is deliberately absent. **Non-normative**: the core specification
(`PALA-1.md`) defines the format; this note exists so that a reviewer
reading §4.4 finds a decision rather than an omission. Nothing here changes
a wire byte, and the closing section names the test that holds each
behavioral claim below to the code.

| | |
|---|---|
| **Status** | Design note, non-normative |
| **Licence** | CC0-1.0, like the core specification. |

## What is fixed

One suite, everywhere:

| Purpose | Algorithm | Where |
|---|---|---|
| Record hash — the chain link | SHA-256 over the header bytes | §1.2, §7.1 |
| Body digest | SHA-256 over exactly `body_len` bytes | §2.1, §4.4 |
| Merkle leaf and node hash | SHA-256, RFC 6962 domain-separated | §4.3 |
| Body encryption | AES-256-GCM, `seq`-derived nonce | §4.4 |

There is no algorithm identifier anywhere in the header. `key_id` names a
key, not a cipher; there is no suite field, no digest-length field, and no
profile identifier either (§3.4). The suite is a property of
`format_version` and of nothing smaller.

## Why one suite is the security argument

**No downgrade surface.** An in-band algorithm identifier is an input, and
an input an attacker can set is a negotiation an attacker can steer. A
verifier that can be told which algorithm to use can be told to use the
weaker one. This format has no field to carry such an instruction, so that
class of attack has nowhere to land — not because it is defended against,
but because it was never made expressible.

**A verifier that fits in one person's head.** An auditor implementing
§7 from the text has exactly one construction to get right per purpose.
That is not a convenience: five implementations now reproduce the §8
values from the specification and the vectors alone, three of them
external and unaffiliated (`INDEPENDENT-VERIFICATION.md`,
`CLARIFICATIONS.md`), and the first four found and closed four defects
between them — the last a common-mode defect the differential test
structurally could not see (§11). Every additional suite would have
multiplied the surface each of those runs had to cover, and a defect
sitting in the under-exercised branch of a two-suite verifier is a defect
that ships.

**Header-only verification stays key-free and stdlib-only.** SHA-256 is in
every language's standard library; AES-GCM is not, and the format confines
it to bodies for exactly that reason (§1.2). A second digest algorithm
would put that property at risk for no gain a deployment has asked for.

## Where the seams are

### (a) `format_version` — how a suite would change

§11 is unambiguous: frozen means the wire no longer changes, and a change
to the wire is a new format version, never an edit to this one. A future
suite therefore arrives as a new version with its own vector set — not as
a field, a flag, or a profile revision. Profiles may add *additively*
within their own body namespaces; a hash is not in a profile's namespace.

The cost of that mechanism is worth stating plainly: it is a new
specification, a new reference implementation, and a new set of
independent runs. It is not cheap, and it is not meant to be. What makes
it affordable in a deployment is (b).

### (b) §7.6 — how two versions coexist

A verifier meeting an unknown `format_version` **MUST** still chain-verify
it, **MUST** report it as uninterpretable, **MUST NOT** reject the chain,
and **MUST NOT** apply §7.4 to it. That is the whole coexistence story,
and it is what makes a mixed deployment degrade gracefully rather than
fail: writers upgraded ahead of readers produce records an old auditor
cannot interpret and can still account for, in order, without gaps, with
the head unchanged by its own ignorance.

> *"Chain intact, 1.2M records, no gaps, 400 records I cannot interpret."*

Nine fields are frozen at their offsets for every future version so that
sentence stays sayable: `magic`, `format_version`, `header_len`,
`record_type`, `seq`, `boot_id`, `prev_hash`, `body_len`, `body_digest`.
`body_len` is in that set for a mechanical reason — without it a reader
cannot find the record *after* an unknown one that carries a body, and
forward compatibility dies at the first such record.

One implication of that freeze is worth flagging rather than assuming.
`prev_hash` and `body_digest` are frozen *at their stated offsets*, and
§2.1 states both as 32 bytes; a future version that honours §7.6 therefore
cannot widen them in place, since doing so would move every field after
them. A wider digest would have to be framed alongside — (d) — rather than
substituted for the chain link. Whether that is the intended reading is a
question for the maintainers, not one this note settles.

### (c) The witness path is already algorithm-agile

`WITNESS_RECEIPT` (TLV `0x0033`) is opaque bytes, and §7.3 puts receipt
verification out of scope: a receipt follows the witness's own protocol.
A transparency log that migrates to post-quantum signatures, or a new
RFC 3161 TSA profile, changes what those bytes contain and nothing about
this format. Two bounds, stated rather than discovered:

- `WITNESS_KIND` is a **closed vocabulary** in version 1 — 1 (transparency
  log), 2 (RFC 3161 TSA). A new receipt *format* under an existing kind
  needs no wire change; a new *kind* is a format-version decision recorded
  in `REGISTRIES.md` as such — the same conclusion `ANCHOR-SOURCES.md`
  reaches for TEE quotes.
- `header_len` is a u16, so one TLV value stops at 65 375 bytes. Receipts
  at post-quantum signature sizes fit; something larger is not a longer
  value but a different design.

### (d) TLV framing carries explicit lengths

Every TLV item states its own length, and unknown TLV types **MUST** be
hashed and **MUST NOT** cause rejection (§2.2). Width is therefore a
property of a value, not of the envelope: a 48-byte digest frames under
the existing rules, in a chain that verifies, with the item reported
rather than refused. No envelope change is needed to carry it — which is
the narrow, real sense in which this format is already agile.

## What is deliberately not provided

1. **In-band suite negotiation.** It would create the downgrade surface
   the whole design avoids: the moment a record can say which algorithm
   verifies it, an attacker can say it too.
2. **Per-record algorithm selection.** Every reader would then need every
   suite to read any chain, and the chain's real strength would be set by
   its weakest record rather than by its specification.
3. **Any second suite today.** No driver has appeared: SHA-256 and
   AES-256-GCM are not near a break, and adding a second suite now would
   spend the argument above to buy nothing.

The third refusal is enforced rather than merely stated: version-1 fields
validate their width and refuse before a byte is written, so a wider
digest cannot be smuggled into a v1 record while the version still claims
to be 1.

## The tests are the contract

`tests/test_crypto_invariants.py` pins each behavior asserted above:

| Claim | Pinned by |
|---|---|
| SHA-256 is the record hash, byte for byte | `test_record_hash_reproduces_the_published_value` |
| SHA-256 is the body digest, over exactly `body_len` bytes | `test_body_digest_reproduces_the_embedded_header_field` |
| AES-256-GCM under §4.4's nonce and AAD derivations | `test_the_encrypted_body_derivations_round_trip_to_the_published_plaintext` |
| An unknown `format_version` verifies, is reported, is not rejected | `test_an_unknown_format_version_is_reported_never_rejected` |
| …and is hashed into the head, not skipped | `test_the_unknown_record_is_hashed_into_the_head_not_skipped` |
| …and the container walk crosses it, `body_len` being frozen | `test_the_container_walk_crosses_an_unknown_record_with_a_body` |
| §7.4 is not applied across the version seam | `test_semantic_checks_do_not_cross_the_version_seam` |
| A 48-byte value frames under the existing TLV rules | `test_tlv_framing_round_trips_a_48_byte_value` |
| …and a chain carrying one verifies, with the TLV reported | `test_a_chain_carrying_a_48_byte_tlv_verifies_with_the_tlv_reported` |
| A witness receipt is opaque bytes, up to the u16 ceiling | `test_a_witness_receipt_is_opaque_bytes_up_to_the_u16_ceiling` |
| The record hash covers header bytes; the body binds through `body_digest` | `test_a_mutated_body_moves_its_digest_but_not_the_record_hash`, `test_mutating_the_embedded_body_digest_moves_the_record_hash` |
| A version-1 field refuses a wider digest before writing a byte | `test_a_wrong_width_digest_is_refused_before_any_byte_is_written` |

Every known-answer constant in that module comes from the published
companion vectors (`profiles/inference-vectors.json`), never from a value
computed by the code under test and pasted back.

What the table cannot cover is the reasoning. That one suite is the better
trade is an argument, and arguments are not pinnable; if it is wrong, it
is wrong in a way no test will report. Everything stated above as a
*behavior* is in the table, and nothing above claims a behavior that is
not.

## Status of this note

Documentation of a decision already taken, written down so it is legible
as a decision. If a driver appears — a real weakness, a regulatory
requirement, a deployment that cannot use AES — the path is the one above:
a new `format_version`, a new vector set, and the §7.6 posture carrying
existing verifiers through the transition. Never an edit to this one.
