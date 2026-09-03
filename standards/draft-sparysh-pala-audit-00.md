---
title: "PALA-1: A Tamper-Evident Audit Record Format for Constrained and Disconnected Deployments"
abbrev: "PALA-1 Audit Records"
docname: draft-sparysh-pala-audit-00
category: info
submissiontype: independent
ipr: trust200902
keyword:
  - audit trail
  - tamper-evident logging
  - AI inference
  - hash chain
  - crypto-shredding
  - local-first
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - ins: A. Sparysh
    name: Andrii Sparysh
    organization: Assault Consulting
    city: Kyiv
    country: Ukraine
    email: as@assault.consulting
  - ins: O. Verteletskyi
    name: Oleksandr Verteletskyi
    organization: Assault Consulting
    city: Kyiv
    country: Ukraine
    email: ov@assault.consulting

contributor:
  - ins: O. Turak
    name: Oleksii Turak
    email: olexii.turak@gmail.com
    contribution: >
      Produced the fifth implementation of the frozen wire format, in
      Perl 5, working from the specification text and published vectors
      alone under the project's stated contamination boundary, and
      surfaced a specification-completeness gap in span pairing that was
      resolved on the public record before this document existed. Later,
      as a maintainer, reproduced the SCITT-bridge Signed Statement
      byte-for-byte from the referenced standards in two further runs,
      the first of which identified a conformance defect against
      RFC 9943 that was corrected on the record.

normative:
  RFC2119:
  RFC8174:
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    author:
      org: National Institute of Standards and Technology
    date: 2015-08
    seriesinfo:
      FIPS: PUB 180-4
  SP800-38D:
    title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    author:
      org: National Institute of Standards and Technology
    date: 2007-11
    seriesinfo:
      NIST: SP 800-38D

informative:
  RFC3161:
  RFC6962:
  RFC7942:
  RFC8032:
  RFC8785:
  RFC8949:
  RFC9052:
  RFC9597:
  RFC9679:
  RFC9942:
  RFC9943:
  RFC9995:
  I-D.daniel-ai-agent-internet-architecture:
  I-D.mih-scitt-agent-action-capsule:
  I-D.munoz-scitt-permit-profile:
  I-D.emirdag-scitt-ai-agent-execution:
  I-D.kamimura-vap-framework:
  I-D.dawkins-scitt-ai-article50:
  I-D.sato-soos-gar:
  I-D.mih-sokolov-scitt-payload-binding:
  I-D.nobuo-scitt-protected-object-binding:
  PALA-SPEC:
    title: "PALA-1 wire format specification, v1.0 (frozen)"
    target: https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/PALA-1.md
    date: 2026-08
  PALA-VECTORS:
    title: "PALA-1 test vectors and independent verification record"
    target: https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/specs/pala-1
    date: 2026-08
  PALA-INTEROP:
    title: "PALA-1 SCITT bridge: statement vector, bridge runs and registration run"
    target: https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/interop
    date: 2026-08
  PALA-COST:
    title: "Serialization cost, independently measured: chain hashing versus per-record signing"
    target: https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/oleksandr/serialization-cost/REPORT.md
    date: 2026-08

--- abstract

This document describes PALA-1, a compact binary record format for
tamper-evident audit trails produced by AI inference runtimes and
robotic control systems. It is designed for a class of deployment
defined by three constraints that hold together: the hardware is
computationally modest and its cycles are reserved for the workload and
the power budget rather than for the audit trail; no external witness is
reachable, whether because policy forbids outbound contact or because
the platform operates beyond connectivity, so a witness is unavailable
by rule or by physics rather than by circumstance; and the right to
verify the trail is separated from the right to read what it records.

Records form an append-only hash chain. Integrity verification requires
no key material of any kind, inspects no record bodies, and costs one
hash per record rather than one signature. The format distinguishes
three separately answerable questions -- internal consistency,
completeness against an external anchor, and existence at a point in
time against an external witness -- and states which of the three a
given trail actually supports rather than implying all three.

The format is frozen at version 1.0 and is described here as it is.
This document presents an existing wire format; it does not revise one.
Where a deployment does permit an external witness, a chain head may be
published to a transparency service such as that of the Supply Chain
Integrity, Transparency, and Trust architecture (SCITT, RFC 9943);
that path is described but is not part of the hashing contract.


--- middle

# Introduction

An AI inference runtime executing on a workstation, an edge device, or a
robot produces a sequence of events that someone may later need to
reconstruct: what was asked, what was answered, which tools were
dispatched, what came back, and what the operator did about it.

A growing body of work addresses this by making a record transparent:
the producer signs a statement, registers it with an external service
maintaining an append-only log, and receives a receipt proving
registration {{RFC9943}}. Where that construction is available it
answers questions this format cannot answer alone, and this document
describes how to reach it ({{transparency}}).

It presupposes two things: that cycles are available to sign each
record, and that a witness is reachable. This document addresses the
deployments where neither holds.

## The constraints {#constraints}

Three constraints defined this format. They are stated first because
every subsequent decision follows from them, and a reader who rejects
them will reject the format.

**C1 -- the hardware is modest, and its cycles are reserved for the
workload and the power budget.** The target is a control system or an
inference runtime on commodity or embedded hardware, frequently one
that carries its own power. A trail that writes thousands of records in
a session cannot spend an asymmetric signature on each one: that cost
is taken directly from the workload the device exists to run, and on a
self-powered platform it is taken from endurance as well. The usual
answer to a compute constraint -- provision a faster processor -- does
not resolve the second of those, since a faster processor draws more.
Integrity therefore has to come from hashing a chain, not from signing
a record.

**C2 -- no external witness is reachable.** This is not a network that
happens to be down. It is either a regime under which reaching an
external service is not permitted, or a platform operating beyond
connectivity by the nature of its task; in both cases the witness is
unavailable **by rule or by physics**, and no engineering effort
changes it. The distinction from C1 matters: C1 is a constraint that
better hardware partly relaxes over time, while C2 does not relax at
all. Any design that requires a service to be reachable before a record
is trustworthy is inapplicable here, not merely inconvenient.

**C3 -- the right to verify is separated from the right to read.** An
auditor may be entitled to establish that a trail is intact and
complete while holding no clearance for what the trail records. This
is an access regime, not a privacy preference, and it makes
"verification requires reading the records" an unsatisfiable
requirement rather than an acceptable cost.

## What the constraints force

Each of the following is a consequence, not a preference.

From C1: the chain hash covers a fixed-length record header, one hash
per record, no asymmetric operation on the write path.

From C1 and C3 together: because there is no per-record signature,
there is no per-record signature to check, and integrity verification
consequently needs no key material at all. A verifier reads headers,
reports that a million records contain no break, and has read none of
the bodies. The header is fixed-length so that it can be scanned and
sought without parsing a variable structure.

From C3: bodies are bound into the chain by a digest carried inside the
header, so a body may be encrypted, or its key destroyed, while the
chain continues to verify. Key destruction is an ordinary lifecycle
operation in such a deployment rather than an exceptional one.

From C2: existence in time is never asserted by the format on its own
authority. Where a deployment does permit publication, the claim is
made after the fact by a record naming an explicit range and a witness,
and a verifier reports the witnessed range and the unwitnessed
remainder separately ({{transparency}}). A trail that has never been
witnessed says so.

And from all three: the format is binary and has no canonicalisation
step, because a canonicalisation step is a place where two conforming
implementations can disagree about the bytes being hashed. A JSON
canonicalisation such as {{RFC8785}} serialises numbers through double
semantics, and a nanosecond wall-clock value exceeds the largest
integer a double represents exactly, so its canonical form is lossy.
The available workarounds -- the value as a string, truncation to
milliseconds -- each trade the property JSON was chosen for against the
one property this format cannot trade: byte-exact agreement between
independent implementations. Inspectability is recovered by a
converter, which is a tool and not part of the hashing contract.

## On COSE {#on-cose}

The question this section exists to answer is why the records are not
COSE_Sign1 {{RFC9052}} structures, given that CBOR encodes a
nanosecond integer exactly and is not subject to the objection above.

The objection above is to JSON canonicalisation, and it does not apply
to CBOR. A CBOR encoding could carry the same chain semantics this
document defines, and an implementer who values ecosystem alignment
over the constraints of {{constraints}} should consider that a
reasonable design.

What C1 and C3 exclude is not the encoding but the envelope. COSE_Sign1
places a signature on each record and a verification key in the hands
of anyone checking one. Both are intrinsic to what a single-signer
signature envelope is, not parameters of it, and both are the two
properties C1 and C3 rule out. A signature per record is the cost C1
forbids; a key required to verify is the dependency C3 forbids.

The trade-off applies in both directions and is stated here rather than
left for a reader to find. A COSE_Sign1 record is self-sufficient: it
carries its own evidence, and one such record proves something on its
own. A PALA-1 record proves nothing on its own -- the sequence is what
carries the evidence, and a single record removed from its chain is
inert. For deployments that write few records, are not
compute-constrained, and need per-record self-sufficiency, the envelope
is the better choice and this format is the wrong tool.

Where the two meet is {{transparency}}: a chain head expressed as a
Signed Statement is a COSE_Sign1 structure, so the envelope is used
exactly where its cost is paid once rather than per record.

## Scope

In scope: the byte layout of a record, the rules linking records into a
chain, the aggregation of record digests, the encoding of assurance
claims, and a normative verification procedure any party can implement
from this document alone.

Out of scope: agent-to-agent protocols, authorization decisions, policy
evaluation, transport, and the internal protocol of any witness. This
document records what a runtime did. It does not decide what a runtime
may do, and it makes no claim about the honesty of the runtime at the
moment of recording ({{security}}).

## A note on regulation

The constraints of {{constraints}} arose in deployments that are also
subject to record-keeping, data-minimisation and erasure obligations,
and those obligations shaped what the format was required to support:
that a trail can be verified without disclosing its contents, and that
a record's content can be destroyed without falsifying the trail it
sits in.

No claim is made that this format satisfies any legal obligation.
Regulations of this kind do not prescribe formats, and a format cannot
discharge a duty that falls on an operator. The relationship is only
that a set of obligations produced a set of technical requirements,
and this document specifies a format meeting them.

## Terminology

{::boilerplate bcp14-tagged}

# Record layout {#layout}

A record is `header || body`. The body may be empty.

## Fixed header -- 156 bytes {#fixed-header}

| Offset | Size | Field | Type | Notes |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | bytes | `PALA` (0x50 0x41 0x4C 0x41) |
| 4 | 2 | `format_version` | u16 | 1 |
| 6 | 2 | `header_len` | u16 | 156 + TLV bytes. Total header length. |
| 8 | 2 | `record_type` | u16 | {{types}} |
| 10 | 1 | `assurance_tier` | u8 | {{tiers}} |
| 11 | 1 | `time_trust` | u8 | {{time}} |
| 12 | 8 | `seq` | u64 | Monotonic within a chain. Never reused. |
| 20 | 16 | `boot_id` | bytes | Opaque, unique per boot |
| 36 | 32 | `prev_hash` | bytes | `record_hash` of the previous record |
| 68 | 16 | `span_id` | bytes | Zero if not span-scoped |
| 84 | 16 | `parent_span_id` | bytes | Zero = root |
| 100 | 8 | `monotonic_ns` | u64 | Since boot. Never wall-clock. |
| 108 | 8 | `wall_clock_ns` | i64 | Nanoseconds since Unix epoch, or 0 |
| 116 | 4 | `key_id` | u32 | 0 = no body, or a cleartext body. {{bodies}} |
| 120 | 4 | `body_len` | u32 | {{body-len}} |
| 124 | 32 | `body_digest` | bytes | SHA-256 {{FIPS180-4}} of the body bytes, or 32 zero bytes if `body_len = 0` |

All multi-byte integers little-endian. No padding. `header_len` MUST be >= 156
and MUST equal the actual number of header bytes.

## TLV extensions {#tlv}

Immediately after the fixed header, until `header_len` is reached:

```
type: u16 | length: u16 | value: <length> bytes
```

A TLV item MUST NOT overrun `header_len`. The last item MUST end exactly at
`header_len`.

**Unknown TLV types MUST be hashed and MUST NOT cause rejection.** They are
opaque bytes to a verifier that does not know them. This is what makes {{verify-body}}
possible.

| Type | Name | Value |
|---|---|---|
| 0x0001 | `ORIGIN_ROLE` | UTF-8 role of the emitting component, e.g. `planner.main`; vocabularies are profile-defined ({{profiles}}) |
| 0x0002 | `ORIGIN_MODEL_DIGEST` | 32 bytes |
| 0x0003 | `ORIGIN_CONFIG_DIGEST` | 32 bytes |
| 0x0011 | `MERKLE_TREE_HASH` | 32 bytes |
| 0x0012 | `MERKLE_LEAF_COUNT` | u32 |
| 0x0020 | `SHED_CLASS` | u16 |
| 0x0021 | `SHED_COUNT` | u32 |
| 0x0022 | `SHED_WINDOW_NS` | u64 |
| 0x0030 | `WITNESS_KIND` | u16 -- 1 = transparency log, 2 = {{RFC3161}} TSA |
| 0x0031 | `WITNESS_RANGE_LO` | u64 |
| 0x0032 | `WITNESS_RANGE_HI` | u64 |
| 0x0033 | `WITNESS_RECEIPT` | opaque |
| 0x0040 | `SHRED_KEY_ID` | u32 |
| 0x0050 | `ANCHOR_HEAD` | 32 bytes -- the head written to the anchor store. {{verify-anchor}} |

**TLV type numbers and record type numbers are separate namespaces.** TLV
`0x0011 MERKLE_TREE_HASH` and record type `0x0020 MERKLE` both concern Merkle
aggregation and are different numbers in different spaces. The names are kept
distinct for that reason; do not read one table with the other's numbers.

**`origin` is three TLVs, not a name.** `(ORIGIN_ROLE, ORIGIN_MODEL_DIGEST,
ORIGIN_CONFIG_DIGEST)` -- because the first question after an incident is
which weights produced an output, and a component name alone does not
answer it. A model update is a different origin and the chain shows it.

## body_len -- exactly what it counts {#body-len}

> **`body_len` is the total number of bytes following the header, up to the
> start of the next record.** A reader that consumes `body_len` bytes after
> `header_len` has consumed the whole body and nothing else.

For an encrypted body ({{bodies}}) that total covers `nonce || ciphertext || tag` --
the nonce is **inside** the count, not additional to it. `body_digest` is taken
over exactly those `body_len` bytes.

This is stated explicitly because it is the most likely implementer error:
a reader that treats the 12-byte nonce as a prefix outside `body_len`
truncates the GCM tag, fails to decrypt, and attributes the failure to the
cipher.

## File container {#container}

A log file is records **concatenated back-to-back, with no file header, no
framing, and no trailing metadata**. The first record starts at byte 0.

A reader finds record boundaries from the records themselves: read the fixed
header at the current offset, confirm `magic`, take `header_len` and
`body_len`, and the next record begins at
`offset + header_len + body_len`. A file whose final record ends exactly at
end-of-file is well-formed; anything else is a truncated tail and MUST be
reported as such (it is not a chain break at any earlier record).

There is deliberately nothing else at file level. A file header would be one
more thing to version, and the records are already self-delimiting;
rotation, segmentation and naming are storage concerns outside this format --
a segment boundary is invisible to the chain, which continues across files
exactly as it continues across boots.

# Record types {#types}

| Value | Name | Class | Meaning |
|---|---|---|---|
| 0x0001 | `GENESIS` | never-shed | Chain origin. {{genesis}} |
| 0x0002 | `BOOT` | never-shed | New boot. Its `prev_hash` **is** the cross-boot link. |
| 0x0010 | `SPAN_START` | normal | Opens a span |
| 0x0011 | `SPAN_END` | normal | Closes it. {{spans}} |
| 0x0012 | `EVENT` | normal | Point event. Payload semantics are profile-defined ({{profiles}}). |
| 0x0020 | `MERKLE` | sheddable | Digest aggregation over a window. {{merkle}} |
| 0x0021 | `AGGREGATE` | sheddable | Tier 0 statistics over a window. {{aggregate}} |
| 0x0030 | `SHED` | **never-shed** | Records that records were dropped. {{shed}} |
| 0x0040 | `SAFETY` | **never-shed** | Written by the safety path; the audit only observes |
| 0x0050 | `ANCHOR` | never-shed | Local anchor written. {{verify-anchor}} |
| 0x0051 | `WITNESS` | never-shed | External witness receipt. {{tiers}} |
| 0x0060 | `KEY_SHRED` | never-shed | A key was destroyed. {{bodies}} |

## Spans are two records {#spans}

`SPAN_START` and `SPAN_END` are separate chained records. Duration is derived at
read time.

The alternative -- one record written on close -- loses exactly the case that
crashed. **A crash must leave a visibly unclosed span**, because that is the
evidence.

This also fixes the limit of the whole design: the audit **cannot** guarantee a
record precedes the action it describes -- that would require blocking, which the
architecture forbids. It guarantees only that **absence is visible**: the
property provided is detectable absence, not write-ahead semantics.

## AGGREGATE body schema {#aggregate}

Tier 0 statistics are not personal data, so an `AGGREGATE` body SHOULD be
cleartext (`key_id = 0`). Encrypting it would only make the post-market
monitoring export useless to the party entitled to read it.

The body is a TLV sequence, encoded exactly as {{tlv}}, in its **own type
namespace**. The core defines the window framing; the measured quantities are
profile-defined:

| Type | Name | Value |
|---|---|---|
| 0x0001 | `AGG_WINDOW_NS` | u64 -- length of the aggregation window. **Core.** |
| 0x0002 | `AGG_SAMPLE_COUNT` | u32 -- samples folded into this record. **Core.** |
| 0x0003+ | *profile-defined* | Allocated upward from 0x0003 by the chain's profile ({{profiles}}) |

A reader treats body tags it does not know as opaque -- reported, never
rejected -- the same posture {{forward-compat}} takes for the header. Because one chain
follows exactly one profile ({{profiles}}), profile allocations cannot collide
within a chain.

**Milli-units, not floats -- a constraint on profiles.** A float in a body
reintroduces exactly the cross-implementation disagreement {{constraints}} rejects JSON
for -- and it would do so in the one record type whose whole purpose is being
comparable across versions and vendors. A profile MUST express fractional
quantities as fixed-point integers (milli-, micro-). Fixed-point integers
carry no cross-implementation ambiguity.

The framing is defined here rather than left to implementations because
`AGGREGATE` is the PMM instrument: a wholly undefined body means two
conformant implementations produce incomparable exports, which defeats the
record type. The core fixes the window; each profile fixes the quantities --
so two implementations of the *same profile* are comparable. The robotics
profile published with the specification {{PALA-SPEC}} defines
optical-flow statistics at 0x0003-0x0005.

## SHED is in the never-shed class {#shed}

The audit never blocks the execution path. Therefore records are dropped
under saturation, and **which** records is a design decision, not an accident.

A dropped record is survivable. A **silently** dropped record is a log that
misrepresents by omission, which is worse than no log. `SHED` carries class, count and window,
and it is never itself shed.

## Profiles {#profiles}

The envelope must outlive any one domain, so the split is structural: this
document defines everything a verifier needs -- layout, chain, tiers, time,
cryptography, the three questions -- and **profiles** define what the records are
*about*. A profile is a companion document that fixes, for one domain:

- **`EVENT` payload semantics** -- what lives in the bodies;
- **`AGGREGATE` quantities** -- body tags from 0x0003 upward ({{aggregate}});
- **`MERKLE` leaf source** -- what the aggregated digests are digests *of*,
  and at what rate ({{merkle}});
- **`ORIGIN_ROLE` vocabulary** -- the component names that appear in headers.

**One chain follows exactly one profile.** Which profile is a property of
the deployment, stated by the emitting system's documentation; the format
does not carry a profile identifier in version 1 (a chain's `ORIGIN_ROLE`
vocabulary makes it evident in practice, and adding a field is a v1.0
freeze decision, not a retrofit). Mixing profiles within one chain is out
of scope.

**Verification is profile-independent.** Every check in {{verification}} reads the
envelope only; a verifier needs no profile knowledge to answer the three
questions, and profile content it does not understand is opaque bytes --
reported, never rejected ({{aggregate}}, {{forward-compat}}).

Two profiles are published with the specification {{PALA-SPEC}}: a
robotics profile -- the first, and the one the committed test vectors
follow -- and an inference profile, under which the reference
implementation audits its own serving loop.

# Recording at the dispatch boundary {#dispatch}

This section is informative and describes an emitter obligation that the
record types of this document are shaped to support.

A hash chain constrains the relationship between records. On its own it
does not constrain *when* a record was written relative to the event it
describes. A producer could execute an entire session and afterwards
emit a chain that is internally consistent, verifies correctly, and
records only what the producer chose to say about itself. Such a trail
is conformant and evidentially weak, and the distinction matters
wherever the question is whether a control actually operated.

The record types here are designed so that a conforming emitter does not
have that freedom in the one place it matters most: the tool-dispatch
boundary, where an inference runtime causes an effect outside itself.

A tool call is recorded when the call is handed to its executor, before
any result is known. The result is recorded as a separate record bound
by digest to the call it answers, so an attempt cannot be presented as a
completion. On shutdown, a call with no recorded outcome is explicitly
cancelled in the chain, so a reader never encounters a dispatch whose
fate is unstated. Span-structured events are two records -- one at open,
one at close -- for the same reason.

The consequence a verifier can rely on: for every dispatch in a
conforming trail there is a record written before the outcome existed,
and every such record has a stated fate. What no format can supply is an
assurance that the emitter obeyed this. That is a property of the
implementation, which is why the verification procedure treats an
unpaired dispatch as an advisory finding to be surfaced rather than
silently tolerated, and why independent implementations of this document
are the evidence that matters ({{impl}}).

A second limit is stated for the same reason. An emitter can record only
the dispatches it mediates as structured data. A client that negotiates
tool use with the model in free text and executes the result locally
produces no dispatch at the emitter's boundary, and therefore no record;
the reference implementation measured this with a widely used agent
client and documents it as a visibility limit rather than concealing it
({{impl}}). A trail's silence about tool use is evidence of what the
emitter observed, not of what the client did.

# Chain rules {#chain}

## Linking {#linking}

```
record_hash(r)  = SHA-256(header_bytes(r))
r.prev_hash     = record_hash(previous record)
```

`seq` MUST increase by exactly 1 within a chain. **A gap in `seq` is a break,
whether or not the hashes link**, and a verifier MUST report it as one ({{verify-chain}}).

The rule is not redundant with the hash link. An actor holding the key can
rebuild a shorter, perfectly linked chain that omits a range of `seq`; the
hashes will chain and only the gap reveals it.

## Genesis and boots {#genesis}

- `GENESIS` has `prev_hash` = 32 zero bytes **and** `record_type = GENESIS`.
  A distinguished type is required so that *"no predecessor"* and *"predecessor
  removed"* are distinguishable. `prev_hash = 0` alone is not sufficient.
- A verifier MUST report as a **violation** any chain whose first record is
  not a `GENESIS` (the record is the wrong kind; the links around it may be
  perfectly sound), and MUST report a `GENESIS` at any position other than
  the first as a violation. Defining the type and then not checking it adds
  nothing.
- **A `BOOT` record's `prev_hash` is the previous boot's head.** The chain is
  continuous across power cycles; a deleted segment leaves a head nothing
  references.

**What this does not fix -- stated in the format, not hidden in prose:** an owner
with the key can start a *new* `GENESIS` and present the device as new. Chain
continuity cannot prove device continuity. Only {{tiers}} addresses that, and only
partly.

## Merkle aggregation {#merkle}

High-rate digests are aggregated per window into one `MERKLE` record -- the
digest **source** and rate are profile-defined ({{profiles}}): the robotics profile
folds a second of sensor-frame digests into one record; an inference
profile might fold a batch of token or KV-operation digests. The tree is
the same either way.

{{RFC6962}} tree hash, domain-separated:

```
leaf(d)        = SHA-256(0x00 || d)
node(l, r)     = SHA-256(0x01 || l || r)
empty          = SHA-256("")
```

**An unpaired node is PROMOTED, never duplicated.** Duplicating the last node is
the CVE-2012-2459 mistake: two distinct leaf sets collapse to the same root.

An **inclusion proof** for a leaf is the list of sibling hashes on the path
from that leaf to the root, each tagged with the side the sibling occupies:
an entry `["L", s]` means the sibling is the **left** operand of `node()` --
the step computes `node(s, h)` -- and `["R", s]` computes `node(h, s)`.
Folding the leaf's `leaf()` hash through the entries in order MUST
reproduce the tree hash. This is the encoding the published vectors use for the
inclusion proof {{PALA-VECTORS}}.

Two constructions are in circulation and they agree, which is worth stating so
an implementer does not go looking for a discrepancy: RFC 6962 defines the tree
recursively, splitting at the largest power of two below `n`; the iterative
bottom-up form that promotes an unpaired node yields the same root. Either may
be implemented.

This provides **selective disclosure**: one leaf can be proven with about
log2(n) hashes without revealing the other n-1 -- one moment, without the
rest of the window.

**The count is a commitment, verified against the leaves -- never in the
header.** `MERKLE_LEAF_COUNT` states how many leaves the root covers. Because the
`MERKLE` record does not carry the leaves, only a party that has them -- checking
a disclosure, or holding the full set -- can confirm it, and such a verifier
SHOULD check that the number of leaves equals `MERKLE_LEAF_COUNT` and reject a
disclosure whose count disagrees. A mismatch is a defect of that disclosure, not
a chain violation: the header and its chain are intact; what was revealed is
inconsistent with what was committed. A header-only verifier ({{verify-chain}}) neither has
the leaves nor checks the count.

## Bodies, encryption and crypto-shredding {#bodies}

A body is one of two shapes, and `key_id` says which:

| `key_id` | Body |
|---|---|
| `0` | Absent (`body_len = 0`), or **cleartext**: `body` is the raw bytes |
| `!= 0` | **Encrypted**: `body = nonce (12) \|\| ciphertext \|\| tag (16)` |

In both cases `body_digest = SHA-256(body_bytes)` over exactly `body_len` bytes.
The digest does not know which shape it covered -- which is why crypto-shredding
does not disturb it.

Body encryption is **AES-256-GCM** {{SP800-38D}}.

```
nonce      = 4 zero bytes || seq (u64 LE)
aad        = seq (u64 LE) || boot_id (16) || record_type (u16 LE)
ciphertext = AES-256-GCM(K[key_id], nonce, plaintext, aad)
body       = nonce || ciphertext || tag
body_digest= SHA-256(body)
```

The AAD binds the ciphertext to its position in the chain: bodies cannot be
swapped between records.

**The nonce is derived from `seq`, not random.** A random 96-bit nonce is not
safe past ~2^32 records under one key -- a horizon a sustained high-rate writer
actually reaches within the ten-year lifetime this format must survive (a
30 Hz emitter crosses it in under five years; higher rates get there
sooner). A `seq`-derived nonce is unique per record by construction -- `seq` never
repeats within a chain ({{linking}}) -- and its only leak is the record's position,
which the cleartext header states anyway. A key MUST NOT be reused across chains
with independent `seq` spaces.

**Order of operations is normative** (it is otherwise circular):
1. encrypt -> 2. compute `body_digest` -> 3. fill the header -> 4. `record_hash`.

**Crypto-shredding.** Keys live outside the log, addressed by `key_id`. Erasure =
destroying `K[key_id]`; a `KEY_SHRED` record notes it. The body becomes noise,
`body_digest` stays, the chain still verifies. A verifier reports *"record
exists, body unreadable"* -- a reported condition, not a gap in the chain.

**Shred granularity equals key granularity, and that is a deployment decision,
not a format one.** Per subject, per session, per day -- the format only requires
that `key_id` exists and that destroying a key breaks nothing structural.

**`key_id` scope is one device.** 2^32 keys is ample per device and ambiguous
across a fleet: two devices may both use `key_id = 7` for unrelated keys. A fleet
key-management layer MUST qualify `key_id` with a device identity of its own;
the format does not carry one.

# Time {#time}

A device without a battery-backed real-time clock boots with its wall clock
at the Unix epoch, and network time synchronisation is unavailable under C2.
Therefore:

- **`monotonic_ns` and `seq` are authoritative for ordering.** Always present.
- **`wall_clock_ns` is advisory** and always accompanied by `time_trust`:

| `time_trust` | Meaning |
|---|---|
| 0 | `UNKNOWN` -- `wall_clock_ns` MUST be 0 |
| 1 | `UNSYNCED` -- free-running, no external reference |
| 2 | `HW_RTC` -- battery-backed clock, unverified |
| 3 | `NTP_SYNCED` -- externally synchronised |

Values above 3 are undefined in version 1. A verifier MUST report a record whose
`time_trust` is `UNKNOWN` with a non-zero `wall_clock_ns` as a violation ({{verify-chain}}):
an unenforced requirement is not a requirement, and this one separates an
explicit statement that the time is unknown from a timestamp that cannot be
justified. The first can be defended; the second cannot.

# Assurance tiers {#tiers}

The format states how much it can be trusted. It does not overstate.

| Tier | Mechanism | Proves | Does not prove |
|---|---|---|---|
| **A** = 0 | Chain + local anchor | A record was modified; with the anchor, that nothing was truncated | Everything else |
| **B** = 1 | + hardware root of trust | Device identity | **Fresh genesis** -- a TPM signs any chain |
| **B+** = 2 | + monotonic NV counter bound to `seq` | Counter never returns to zero -> fresh genesis visible | Platform-bound |

**Tier C is deliberately not a header value.**

Tier C -- periodic publication of the chain head to a transparency log or an {{RFC3161}} TSA -- proves **existence at time T**, which is the guarantee that actually
defeats a fresh genesis. But a header cannot honestly claim to have been
witnessed *before the witness exists*.

So tier C is asserted **after the fact**, by a `WITNESS` record covering a `seq`
range. A verifier reads:

> *records 0-9: externally witnessed at 2026-07-16T10:00Z
> records 10-...: tier A, no existence claim*

**C is strictly stronger than B here**, because fresh genesis is a question of
existence, not identity. Its cost is one published hash, not data: the model
of Certificate Transparency applied to an audit trail.

# Relationship to transparency services {#transparency}

This section is informative. It adds no requirement and changes no byte.

The strongest question this format cannot answer from its own bytes is
existence at a point in time. A chain proves that its records have not
been altered relative to one another. It does not prove that the chain
was not created wholesale after the fact, because a producer in
possession of its own keys can construct a consistent history at any
time. Defeating that requires a party other than the producer to have
observed a commitment, and the observation has to have happened.

PALA-1 handles this by deferring the claim rather than asserting it. A
witness record covers an explicit range of sequence numbers and states
that the head of that range was published externally. The record is
itself chained, so the claim cannot be inserted retroactively without
breaking the chain, and a verifier reports the witnessed range and the
unwitnessed remainder separately. The protocol by which the external
publication is verified is the witness's own and is out of scope here.

A SCITT transparency service {{RFC9943}} is one such witness, and a
natural one where a deployment permits it. A producer takes the chain
head, expresses it as a Signed Statement -- a COSE_Sign1 {{RFC9052}}
whose payload commits to the head by digest -- registers it with a
transparency service, and attaches the returned Receipt -- a COSE
Receipt {{RFC9942}} -- to the statement's unprotected header, producing
what {{RFC9943}} calls a Transparent Statement, which is then carried in
the evidence the producer exports.
What the producer publishes is one digest, not the trail:
no record body, no personal data, no model output leaves the device.
The envelope's cost is paid once per published head rather than once
per record ({{on-cose}}), which is what makes it affordable under C1.

The construction published with the specification {{PALA-INTEROP}} is
stated here so that it can be checked rather than assumed. The
statement's protected header carries the algorithm, the payload's
content type, a key identifier, and CWT claims for issuer and subject
under the header label registered by {{RFC9597}}.

Two of those values are digests, and they are treated differently on
purpose. The subject names the **full** chain head: a transparency
service indexes by the subject, distinct chains must not collide under
it, and a truncated digest collides at the birthday bound of whatever
length is kept. The key identifier is the COSE Key Thumbprint of the
verification key {{RFC9679}} **truncated to its first 20 bytes**, which
is not a thumbprint and is not claimed to be one. The asymmetry is
deliberate: `kid` is a hint for locating a key and {{RFC9052}} places no
collision-resistance duty on it, since presenting the wrong key simply
fails the signature check, whereas the subject is the identifier by
which a relying party decides that two statements concern the same
thing, and nothing downstream catches a collision there. Truncation is
acceptable exactly where a collision is self-correcting and
unacceptable where it is not. The payload is attached -- a CBOR map of the head, the sequence
range and the format identifier, encoded as CBOR {{RFC8949}} -- so
that the statement is readable
offline, without the service. Section 6 of {{RFC9943}} requires the
`kid` header parameter when neither `x5t` nor `x5chain` is present in
the protected header; its initial omission was found by a reproduction
of the statement performed under a stated contamination boundary and
was corrected before any registration took place ({{impl}}).

Two properties of the envelope bear on what such a statement can be
said to be. First, byte-for-byte reproduction of a statement by an
independent implementation is achievable only when the signature is
deterministic: EdDSA {{RFC8032}} provides that by construction, whereas
an ECDSA signature is deterministic only as a per-library choice, so two
conforming implementations may emit different signature bytes over
identical input. The published vector therefore uses EdDSA, and a vector
over ECDSA could claim that a statement verifies, not that it
reproduces. Second, a valid signature and the published bytes are two
different facts: content in the unprotected header, the presence or
absence of the outer CBOR tag, a detached payload, or a non-canonical
Ed25519 scalar each yield an artifact with different bytes over which
the signature still verifies. An auditor comparing an artifact to a
published one compares bytes; an auditor accepting a statement checks
the signature; the two checks are not substitutes for each other.
{{PALA-INTEROP}} enumerates these cases with executable expectations.

Under C2 this path is closed -- by policy or by the absence of any
reachable service -- and the format is designed so
that its closure costs nothing structural: a trail that is never
witnessed is still verifiable for internal consistency and, against a
local anchor, for completeness. It simply does not claim the third
question, and says so.

Two properties of this arrangement are worth stating plainly, because
the difference between them is the difference between a claim and a
proof.

A verifier that has checked a Receipt against a log key it trusts may
report the covered range as externally witnessed. A verifier that has
not checked one MUST NOT, whatever the trail says about itself. The
overclaim rule that governs every assurance field in this document
governs this one.

And the guarantee itself is bounded. A Receipt establishes that a
commitment was registered, and therefore bounds when the trail can have
been constructed and makes later substitution or omission detectable. It does
not establish that the recorded content is true. That boundary is not
peculiar to this format; it applies to every construction of this kind,
including the transparency service's own.

# Verification {#verification}

Verification answers three questions, and they MUST NOT be collapsed into one
boolean. Each needs different inputs and each fails differently.

| Question | Needs | Answers |
|---|---|---|
| **{{verify-chain}} Is what I hold internally consistent?** | Nothing | Modification, reordering, `seq` gaps |
| **{{verify-anchor}} Is what I hold all of it?** | An anchor, from outside the log | Truncation, replacement, rollback |
| **{{verify-witness}} Did this history exist at time T?** | A witness receipt | Fresh genesis |

A verifier that reports only {{verify-chain}} as "ok" is misleading, because {{verify-chain}} cannot see
a truncated tail: dropping the last N records leaves a perfectly linked chain
with a different head and no other trace.

## Header-only chain verification {#verify-chain}

Requires no key. Touches no bodies.

```
prev     := unset                          # no link expectation yet
expected := unset
for index, header h in file order:
    MUST h.magic == "PALA"                         else break, stop
    MUST h.header_len == actual header bytes       else violation
    if index == 0:
        MUST h.record_type == GENESIS              else violation
        if h.record_type == GENESIS:
            MUST h.prev_hash == 32 zero bytes      else violation
    else:
        MUST h.record_type != GENESIS              else violation
    if prev is set and h.prev_hash != prev:  report break at h.seq
    if expected is set and h.seq != expected:  report gap at h.seq
    expected := h.seq + 1
    if h.format_version unknown or h.record_type unknown:
        report uninterpretable at h.seq    # not a break; see below
    else:
        run semantic checks                # violations, not breaks
    prev := SHA-256(h.header_bytes)
report: count, breaks, gaps, violations, uninterpretable, head = prev
```

`chain_ok` is true iff `breaks`, `gaps` and `violations` are all empty. It means
**internally consistent**, nothing more.

A chain whose first record is not a `GENESIS` yields exactly **one**
violation -- the wrong *kind* of first record. Per {{genesis}}, the links around it
may be perfectly sound: the zero-`prev_hash` requirement applies only when
the first record *is* a `GENESIS`, and the break check compares only records
that have a predecessor in the file. (Aligned at the final pre-freeze verification run:
read literally, the earlier pseudocode produced two violations and a
spurious break on this case, contradicting this section's own prose above
and {{genesis}}. The published missing-GENESIS demonstration had not discriminated the
two readings -- its input satisfied both -- until that run
constructed the discriminating case; the demo input was strengthened
accordingly, with its published outputs unchanged.)

`breaks` and `gaps` are reported at the record's `seq`. Violations from
per-record checks are likewise keyed by `seq`; the
chain-does-not-start-with-`GENESIS` violation is reported at position `0`,
because it is a property of the chain, not of any record's `seq`.

## Completeness against an anchor {#verify-anchor}

The anchor is the head this chain is supposed to have, obtained from **outside
the log**: the *current* head held in the local anchor store (an OS keychain
entry), or the head covered by the newest `WITNESS` receipt. An in-chain
`ANCHOR` record with its `ANCHOR_HEAD` TLV **records a store write at the time
it occurred** -- a historical note, not the anchor itself. Because a writer may
append records after a store write, the newest `ANCHOR` record's head can lag
the store's current head; a completeness check therefore uses the **store's
current head**, not any in-chain `ANCHOR` record's TLV.

Given an anchor `A` and a computed head `H`:

| Condition | Report |
|---|---|
| `A == H` | Complete to the anchor |
| `A` is the `record_hash` of some record in the chain | **Unanchored tail**: `anchor_lag = N` records past the anchored head. A crash between write and anchoring, or an anchor-store outage -- or records appended by a writer without anchor access. |
| `A` names no record in the chain | **Replaced, rolled back, or truncated.** This is not the history that was anchored. |

Both non-matching cases are failures; the diagnosis differs, and the diagnosis is
what an auditor acts on. Without an anchor a verifier MUST report completeness as
*not checked* -- never as passing.

## Existence against a witness {#verify-witness}

A `WITNESS` record asserts that the head of records `[RANGE_LO, RANGE_HI]` was
published to an external log at some time. Verification is out of scope for this
document -- it follows the witness's own protocol (a COSE Receipt
{{RFC9942}}, a Rekor inclusion proof, an {{RFC3161}} token). What this format
guarantees is only that the claim is *in* the chain, is itself chained,
and names its range explicitly.

A verifier SHOULD report the witnessed range and the unwitnessed remainder
separately ({{tiers}}).

## Semantic checks {#verify-semantic}

On records whose version and type are known -- **`GENESIS` and `BOOT` included**.
The position checks {{verify-chain}} makes at index 0 (the record is a `GENESIS`, its
`prev_hash` is zero) are *in addition to* these, not in place of them: a
`GENESIS` with `time_trust = UNKNOWN` and a non-zero `wall_clock_ns` is as much
a violation as any other record.

The checks:

- `time_trust == UNKNOWN` => `wall_clock_ns == 0` ({{time}})
- `time_trust <= 3` ({{time}})
- `body_len == 0` if and only if `body_digest == 32 zero bytes` ({{fixed-header}})
- `key_id != 0` and `body_len > 0` => `body_len >= 28` (nonce + tag, {{bodies}})
- TLV items parse and end exactly at `header_len` ({{tlv}})

These are violations, not breaks: the record is defective, the chain around it
may be sound. They MUST be reported distinctly.

`MERKLE_LEAF_COUNT` is deliberately **not** among these checks. A `MERKLE`
record carries the root and the count but never the leaves (`body_len = 0`,
{{merkle}}), so a header-only verifier does not have the leaves to count and does not
treat the field as verifiable here -- it is a commitment, checked only when the
leaves are disclosed. {{merkle}} says how.

## Body verification (needs the key) {#verify-body}

`SHA-256(body) == header.body_digest`, then -- if `key_id != 0` -- AES-256-GCM
decrypt with the nonce and AAD of {{bodies}}. Failure to decrypt with a **matching**
digest means the key is wrong or destroyed -- not that the log is corrupt. These
MUST be reported distinctly.

## Forward compatibility {#forward-compat}

A verifier meeting an unknown `format_version`, `record_type` or TLV type:

- **MUST** still chain-verify it -- the hash is over raw bytes
- **MUST** report it as uninterpretable
- **MUST NOT** reject the chain
- **MUST NOT** apply {{verify-semantic}} to it -- those checks belong to a version it claims

**These fields are frozen for all future versions:** `magic`, `format_version`,
`header_len`, `record_type`, `seq`, `boot_id`, `prev_hash`, `body_len`,
`body_digest`, at their stated offsets.

`body_len` is in the frozen set for a mechanical reason: without it a verifier
cannot find the next record, and forward compatibility ends at the first
unknown record with a body.

That freeze is what allows a tool written today to report, on a trail written
ten years later:

> *"Chain intact, 1.2M records, no gaps, 400 records I cannot interpret."*

# Test vectors {#vectors}

The full set -- every record byte, the Merkle leaves and the inclusion
proof -- is published as {{PALA-VECTORS}}. The vectors are
deterministic: a fixed key, derived nonces and fixed identifiers -- real
cryptography over deterministic inputs. Such inputs MUST NOT be used
outside a test vector.

The vector chain's record bodies and narrative follow the robotics
profile ({{profiles}}). Every property demonstrated below is an
**envelope** property and holds under any profile.

The chain is a representative ten seconds: genesis, boot with no clock, a
`brain` span, a `c'` write with an encrypted body, a second of frames, a
second of Tier 0 statistics, a divergence event, a shed notice, span close,
a local anchor, an external witness, and an erasure.

```
key    = 000...02a (32 bytes)          key_id = 7
nonce = 4 zero bytes || seq (u64 LE)
  seq 3 -> 000000000300000000000000
body plaintext (seq 3) =
  "clear path ahead, one pedestrian at 12m, static"
```

| seq | type | note |
|---:|---|---|
| 0 | `GENESIS` | tier A, time UNKNOWN |
| 1 | `BOOT` | `wall_clock_ns = 0`, `time_trust = UNSYNCED` |
| 2 | `SPAN_START` | brain |
| 3 | `EVENT` | AES-GCM body, `key_id = 7`, origin = eyes.tier1 + digests |
| 4 | `MERKLE` | 30 frame digests |
| 5 | `AGGREGATE` | cleartext TLV body, `key_id = 0` |
| 6 | `SAFETY` | divergence, origin = perception_health |
| 7 | `SHED` | class 1, 400 records, 12 s window |
| 8 | `SPAN_END` | |
| 9 | `ANCHOR` | carries the head anchored at seq 8 |
| 10 | `WITNESS` | transparency log, covers seq 0-9 |
| 11 | `KEY_SHRED` | key 7 destroyed -> seq 3 body unreadable |

**Expected results -- an implementation that disagrees with any of these is
wrong, or this specification is:**

```
chain_head =
  3a1a3673f50498eb1d1c6f94b983d6c606cd85ed53627b4e4ffe55153c7af813
chain_ok           = true    record_count = 12
breaks = []   gaps = []   violations = []
complete_to_anchor = true
  (the anchor is the store's current head = the tip)
anchor_head =
  3a1a3673f50498eb1d1c6f94b983d6c606cd85ed53627b4e4ffe55153c7af813
  (== chain_head)

merkle_tree_hash =
  518f5be5173250f705e3bda029ec1c11ac5c4459115c07dde5bc1021d9f468db
merkle_leaf_count   = 30         proof(index 7) verifies   proof_len = 5
```

The `ANCHOR` record at seq 9 carries, in its `ANCHOR_HEAD` TLV, the head as of
seq 8 (`14434088e5f5866cf0276ba5a9055d8ee0d115a750b2cdf9cc4006d9481b29b4`) -- a
historical store write that lags the tip by 3. It is **not** the completeness
anchor (which is the store's current head, `anchor_head` above); the
`stale_anchor` demonstration below checks against it deliberately.

Seven properties the vectors demonstrate rather than assert:

| Demo | Result |
|---|---|
| Flip one bit in the seq-3 body | `body_digest` mismatch detected **and the chain still verifies** -- body damage and chain damage are distinct failures |
| Append a record of unknown type `0x7fff` | `chain_ok = true`, `count = 13`, `uninterpretable = [12]` -- {{forward-compat}} works |
| Destroy key 7 | seq 3 body unreadable forever, chain unchanged -- {{bodies}} works |
| **Drop the last record** | `chain_ok = true` **without** an anchor; `complete_to_anchor = false` **with** one -- {{verify-chain}} cannot see truncation, {{verify-anchor}} can. This is why the two questions are separate. |
| **Stale anchor** (anchor names seq 8, chain has 12) | `anchor_lag = 3`, reported as an unanchored tail, **not** a replacement |
| **`seq` gap** 11 -> 99 with valid hashes | `chain_ok = false`, `gaps = [99]` -- {{linking}} |
| **Chain with no `GENESIS`** | `chain_ok = false`, violation *"chain does not start with a GENESIS record"* -- {{genesis}} |
| **`time_trust = UNKNOWN` with a non-zero clock** | `chain_ok = false`, violation -- {{time}} |

A companion vector {{PALA-INTEROP}} publishes a Signed Statement over this
chain head in the construction of {{transparency}}: 331 bytes, EdDSA under
the published test key of {{RFC8032}} Section 7.1, with the expected
bytes, digest, key identifier and a set of tamper expectations that
includes the byte-stability cases stated there. The vector was reissued
once, after a reproduction performed under a stated contamination
boundary found the conformance defect described in {{impl}}; both
versions and their digests are on the record.

# Related work

Evidence for the conduct of AI systems is an active area, and most of
the current work sits in a different place in the stack than this
document. The distinctions below are stated to locate this format, not
to rank the documents.

**Transparency substrate.** {{RFC9943}} defines an architecture in which
an issuer registers a signed statement with a transparency service and
receives a receipt, generalising the approach of certificate
transparency to arbitrary content. It is the substrate a number of the
documents below profile, and, as described in {{transparency}}, the
natural witness for a PALA-1 chain head. This document does not compete
with it; the two operate at different points and compose.

**Statement profiles for agent conduct.** A cluster of individual
submissions profiles that substrate for AI agents.
{{I-D.mih-scitt-agent-action-capsule}} records verdict-level disposition
for a single agent action, with a binding that distinguishes a
dispatched effect from an observed result and a flag that prevents a
policy approval from being presented as human oversight.
{{I-D.munoz-scitt-permit-profile}} records pre-execution authorization --
whether an action was permitted, rather than what occurred.
{{I-D.emirdag-scitt-ai-agent-execution}} defines operator-signed
interaction records with redaction receipts.
{{I-D.kamimura-vap-framework}} frames hash chaining, signatures and
anchoring as a conformance-tiered provenance architecture.
{{I-D.dawkins-scitt-ai-article50}} profiles receipts for a specific
regulatory transparency obligation. {{I-D.sato-soos-gar}} records
session-level governance audit records produced by an enforcing
component.

These are per-action or per-session statement profiles, expressed in
JSON or CBOR, made transparent by registration with a service. This
document specifies a wire format for a continuously appended local
trail, verifiable without a service and without a key, under the
constraints of {{constraints}}. The difference is not a disagreement
about design: none of the documents above targets a deployment in which
signing each record is unaffordable, an external service is forbidden
by policy, and the verifier may not read what it verifies. A single
agent action in one of those profiles may correspond to many PALA-1
records; conversely a PALA-1 chain head may be carried into that
ecosystem as a signed statement. The layers are complementary, and the
practical relation is the anchoring path of {{transparency}}.

**Statement construction and binding.**
{{I-D.mih-sokolov-scitt-payload-binding}} extracts, as a reusable
profile, the construction that systems anchoring structured records to a
transparency service repeatedly re-derive: a canonical payload form, a
content-derived identifier, receipt binding in the unprotected header,
and typed digest references between records. Its envelope conventions
-- `alg`, `kid` or `x5chain`, and a content type in the protected
header -- are the ones the statement of {{transparency}} follows.
{{I-D.nobuo-scitt-protected-object-binding}} defines a common model for
relating Signed Statements to the objects they describe, including
device instances. {{RFC9995}} defines a COSE structure carrying a digest
of a payload that the verifier obtains elsewhere. The statement of
{{transparency}} is a narrow instance of these concerns: its payload is
a fixed-shape commitment to a chain head -- which is not a digest of a
file but the result of the chain rules -- together with the range and
format identifier a verifier needs to recompute it. It could be
expressed under either binding document, or as a hash envelope over the
head, without loss, and this document does not preclude that.

**Architectural requirements.**
{{I-D.daniel-ai-agent-internet-architecture}} states requirements for
supporting AI agents on the Internet, among them that audit evidence be
tamper-evident and support selective disclosure, and that protocols not
require the collection of private reasoning traces as a condition of
accountability. This format was designed before those requirements were
written and satisfies the second by construction: chain verification
inspects headers only and never requires a body to be disclosed.

**Time and existence.** {{RFC3161}} timestamp tokens and
{{RFC6962}}-style logs are alternative witnesses for the existence claim
of {{transparency}}. This document is deliberately indifferent to which
is used; the witness record names a range and a witness, not a
mechanism.

**What is not addressed here.** Selective disclosure at field
granularity, agent identity, authorization, and cross-party attestation
are all outside this document. Where a deployment needs them, the
profiles above address them directly and this format is not a substitute.

# Implementation status {#impl}

This section records implementation experience per {{RFC7942}} and is to
be removed before publication as an RFC, should that occur.

The wire format described here is frozen at version 1.0. Five
implementations of it exist: the reference implementation; one written
by a co-maintainer under a stated contamination boundary; and three by
implementers who were external to the project at the time of their
runs -- one has since become a maintainer -- and who worked from the
specification text and the published test vectors alone
{{PALA-VECTORS}}. Each of the
latter four reproduces the published expected values of the
specification's test-vector section without access to any prior
implementation.

| # | Implementer | Language | Date | Spec tested | Result |
|---|---|---|---|---|---|
| 1 | reference (authors) | Python | -- | -- | the format's origin, not a verification run |
| 2 | O. Verteletskyi (co-maintainer, stated boundary) | Python, stdlib | 2026-08 | `776aa15a`, `ce877e4` | chain + completeness reproduced; Merkle first blocked (leaves unpublished); 2 spec defects filed, closed; Merkle then reproduced |
| 3 | R. Bakaiev (external, unaffiliated) | Python, stdlib | 2026-08 | `c8e8247` | 8/9 blind; 1 divergence -- the verifier was right, the vectors were inconsistent; confirmed at `1294bd0`, verifier unchanged |
| 4 | V. Kurdybailo (external, unaffiliated) | Python, stdlib | 2026-08 | `ff2720a` | 11/11 blind first run + 7/7 demos; own adversarial construction exposed a common-mode pseudocode/prose defect; fixed, vectors byte-identical |
| 5 | O. Turak (external and unaffiliated at the time of the run; a maintainer since) | Perl 5, core only | 2026-08 | tag `pala1-v1.0` | 11/11 + 7/7 first run; 13 own adversarial cases, 140 checks, 0 failures; 8 ambiguities logged; span-pairing gap reported; AES-GCM built from the primitive standards, NIST-tested first |

Run kind, stated in the vocabulary in current use for interoperability
reporting: rows 2 through 5 are each an *independent implementation from
the text*, checked against author-supplied vectors. None is an
*independent implementation with independent vectors*, since the vectors
are this project's; rows 4 and 5 additionally constructed their own
adversarial inputs beyond the published set, and in row 4 that
construction is what exposed the defect. The distinction is recorded
here rather than left to be inferred.

The fifth run is described in more detail because it is the one that
changed the specification after the freeze. The gap concerned span
pairing: the specification states that a crash must leave a visibly
unclosed span, because that is the evidence, yet defines no pairing
check anywhere -- so two conformant verifiers would differ on whether a
user ever sees an unpaired span. The resolution deliberately did not
make span pairing a verification verdict, since a trail truncated by a
crash is incomplete without being falsified; it is surfaced as an
advisory finding instead. The finding, the reasoning and the resolution
are on the public record, as are the verifiers, run records and
ambiguity logs of every run above.

The reference implementation ships the published vectors inside its
distribution package, so an installed build can be checked against them
without network access.

The cost claim of C1 has been measured rather than argued. An in-repository
harness compares chain hashing with per-record COSE signing, and a
second run of the same comparison, performed by a co-maintainer under a
stated contamination boundary, agrees with it: with native primitives on
a workstation, which is the case least favourable to the format,
per-record signing costs between 45 and 61 times the header hash on the
write path and between 116 and 168 times on the verify path
{{PALA-COST}}. On the embedded
targets of {{constraints}} the ratio is larger. These are measurements
of two implementations, not properties of the format, and are reported
as such.

**The transparency path.** The Signed Statement construction of
{{transparency}} has its own record, kept separately from the wire-format
runs above because neither is evidence for the other {{PALA-INTEROP}}.
Two runs by a maintainer, each performed under a stated contamination
boundary from the referenced standards and the published vector alone,
and each with its own implementation of the CBOR and Ed25519
primitives, reproduced the statement byte-for-byte. The
first run found that the protected header omitted the `kid` header
parameter that Section 6 of {{RFC9943}} requires when neither `x5t` nor
`x5chain` is present, and that the subject truncated the chain head; the construction was
corrected, the vector reissued, and the second run reproduced the
corrected statement and independently re-derived the key thumbprint. The
second run additionally established that the published tamper
expectations had not exercised Ed25519 signature non-uniqueness (a
scalar increased by the group order verifies unless the verifier
enforces the range check of {{RFC8032}} Section 5.1.7); the reference
implementation's verifier was measured to enforce it, and the case is
now an executable expectation.

Registration was then exercised end to end: a statement over the head of
a chain written during a co-maintainer's session with the serving
interface described below was registered with the SCITT API emulator
published by the scitt-community project (`scitt-api-emulator` -- an
emulator, not a production service), and the receipt was verified both
by that emulator's own verifier and offline from the published
artifacts alone. The run is reported with its scope: the emulator was
operated by the authors on a local host for the duration of the run,
under a single-use key, and its receipt structure is the emulator's own,
predating {{RFC9942}}. One finding resulted: the emulator expected the
CWT-claims header under a draft-era label, whereas {{RFC9597}}
registered a different one; the statement was not altered to match, the
emulator received a one-line correction whose diff is published with the
run, and the matter is reported upstream. A registration with a transparency
service operated by an unrelated party is the next class of evidence and
is not claimed here.

The reference implementation also serves an interface compatible with a
widely deployed inference API, recording the tool-dispatch boundary of
{{dispatch}} for any client of that interface. A measured limit of that
recording is stated in the same record: when a client negotiates tool
use with the model in free text and executes locally, no structured
dispatch crosses the interface and nothing is recorded; the reference
implementation reports this as a visibility limit and does not
reconstruct dispatches from prose.

# Security considerations {#security}

Tamper-evidence applies to record bytes, not to the honesty of the
recorder. This format makes alteration of a written trail detectable. It
cannot establish that the runtime which wrote the trail reported
truthfully at the moment of writing, and no format can: a dishonest
producer with no external observer can construct an internally valid
record of a fiction. Publication of a chain head to an external witness
({{transparency}}) bounds when such a trail can have been constructed
and makes its later substitution or omission detectable; it does not
make its content true. Every claim elsewhere in this document is bounded
by this paragraph.

The boundaries below are stated here rather than discovered later.

1. **It does not make the log true.** The chain proves *this is what the system
   recorded, unmodified*. Not *this is what happened*. A hallucinated model
   output is preserved faithfully.
2. **It does not defend against the owner at tier A.** Key and anchor are both
   theirs. Tier A is self-diagnostics. {{tiers}} is the only mitigation, and it is partial.
3. **It does not bind to hardware.** *"This is the same device"* needs tier B+.
4. **A digest without its frame proves nothing about content.** Commitment
   defeats fabrication; it does not reconstruct.
5. **Cleartext headers are metadata, and metadata discloses.** The span graph,
   origins and timing are readable without a key. That is the cost of {{constraints}}, and
   it is not zero.
6. **It does not guarantee an action was logged before it happened.** {{spans}}.
7. **The chain alone does not detect truncation.** {{verify-anchor}} is not optional;
   without an anchor the last N records can be removed silently.

# IANA considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The specification was hardened by its independent verifiers, whose
findings were resolved on the public record before this document
existed, and the transparency path was hardened in the same way by the
runs recorded in {{impl}}. The authors thank every external contributor
to that effort, the maintainers of the scitt-community reference
implementation, and the SCITT and COSE working groups, whose published
work this document refers to and builds no claim upon.
