# PALA-1 — audit log wire format

An append-only, hash-chained, selectively-disclosable audit log format for
local AI systems: encrypted bodies, cleartext headers, out-of-band anchoring,
and header-only verification that needs no key. This document is normative
for the format and self-contained: the rationale for each decision is in §1,
and an independent verifier is implementable from this text plus the test
vectors alongside it. This document is the profile-independent **core**:
record-**body** semantics beyond it are defined by companion **profiles**
(§3.4), and the envelope, chain and verification rules below hold under
every profile.

| | |
|---|---|
| **Format identifier** | `PALA`, version 1 |
| **Status** | **Draft.** The field set is *not yet frozen* — do not implement against this before the specification reaches v1.0. |
| **Date** | 2026-08-03 |
| **Licence** | This specification and its test vectors: CC0-1.0. Reference code alongside them: Apache-2.0. |

## The test this document must pass

> **An independent party must be able to write a verifier from this document
> alone, without our code.**

If that is possible, trusting us becomes unnecessary: a regulator, a deployer or
an opposing expert verifies the log with their own tool. If it is not, the audit
is self-attestation wearing a specification's clothes.

Everything below is subordinate to that sentence. Where the prose is ambiguous,
the specification is defective — not the implementer.

**Corollary that outranks convenience:** the format must remain readable when our
binary no longer builds. PLD liability runs ten years; hardware, toolchains and
this codebase will not. The format is the deliverable.

**Normative language.** MUST, MUST NOT, SHOULD and MAY carry their RFC 2119
meanings. `palaudit_ref.py` is a reference implementation, not a source of
normative meaning: where it disagrees with this prose, the implementation is
wrong.

---

## 1. Design decisions and why

| Decision | Rationale |
|---|---|
| **Binary, not JSON** | §1.1 |
| **Chain hash covers the header only** | §1.2 |
| **Body bound via `body_digest` inside the header** | §1.2 |
| **Little-endian, packed, no alignment padding** | Native on every target; one less thing to get wrong. Stated, therefore not a guess. |
| **Hash over raw bytes, never over parsed structure** | A verifier that cannot interpret a record can still verify it. §7.5 |
| **Assurance tier is data, not a promise** | §6 |
| **Integers only, never floats** | §1.1 applies inside bodies too. §3.2 |
| **Envelope in the core, body semantics in profiles** | The chain must outlive any one domain. §3.4 |

### 1.1 Why not RFC 8785 (JCS)

JCS was the obvious candidate — JSON is inspectable and every language has a
parser. It is rejected for one concrete reason:

**JCS serialises numbers through ECMAScript double semantics.** `wall_clock_ns`
is nanoseconds since epoch: `1784000010000000000`. That exceeds 2⁵³
(`9007199254740992`), the largest integer a double represents exactly. A
JCS-canonical form of this record is **lossy**, and two implementations can
legitimately disagree on the bytes being hashed.

Workarounds exist (numbers as strings, millisecond truncation). All of them
trade the one property JCS was chosen for — obviousness — against the property we
cannot trade: **byte-exact agreement between independent implementations**.

A binary format has no canonicalisation step at all. Serialisation *is*
canonicalisation. There is nothing to disagree about.

Inspectability is recovered with a converter (`pala2json`), which is a tool, not
part of the hashing contract.

### 1.2 Why the chain hash covers the header only

```
record_hash = SHA-256(header_bytes)
header.body_digest = SHA-256(body_bytes)
```

The body is bound into the chain through `body_digest`, which sits inside the
header. Three consequences, all load-bearing:

1. **Chain verification needs no key and touches no bodies.** A verifier reads
   headers and reports *"1.2M records, no breaks"* — having seen none of the
   bodies' content: no personal data, no model output, nothing a profile puts
   there. This is what lets one artefact serve both a regulator and GDPR
   minimisation.
2. **Crypto-shredding leaves the chain intact.** Destroy the key, the body
   becomes noise, `body_digest` remains, the chain still verifies. Erasure and
   immutability stop being in conflict.
3. **Header-only export is a post-market-monitoring bundle** with zero content.

---

## 2. Record layout

A record is `header || body`. The body may be empty.

### 2.1 Fixed header — 156 bytes

| Offset | Size | Field | Type | Notes |
|---:|---:|---|---|---|
| 0 | 4 | `magic` | bytes | `PALA` (0x50 0x41 0x4C 0x41) |
| 4 | 2 | `format_version` | u16 | 1 |
| 6 | 2 | `header_len` | u16 | 156 + TLV bytes. Total header length. |
| 8 | 2 | `record_type` | u16 | §3 |
| 10 | 1 | `assurance_tier` | u8 | §6 |
| 11 | 1 | `time_trust` | u8 | §5 |
| 12 | 8 | `seq` | u64 | Monotonic within a chain. Never reused. |
| 20 | 16 | `boot_id` | bytes | Opaque, unique per boot |
| 36 | 32 | `prev_hash` | bytes | `record_hash` of the previous record |
| 68 | 16 | `span_id` | bytes | Zero if not span-scoped |
| 84 | 16 | `parent_span_id` | bytes | Zero = root |
| 100 | 8 | `monotonic_ns` | u64 | Since boot. Never wall-clock. |
| 108 | 8 | `wall_clock_ns` | i64 | Nanoseconds since Unix epoch, or 0 |
| 116 | 4 | `key_id` | u32 | 0 = no body, or a cleartext body. §4.4 |
| 120 | 4 | `body_len` | u32 | §2.3 |
| 124 | 32 | `body_digest` | bytes | `SHA-256(body_bytes)`, or 32 zero bytes if `body_len = 0` |

All multi-byte integers little-endian. No padding. `header_len` MUST be ≥ 156
and MUST equal the actual number of header bytes.

### 2.2 TLV extensions

Immediately after the fixed header, until `header_len` is reached:

```
type: u16 | length: u16 | value: <length> bytes
```

A TLV item MUST NOT overrun `header_len`. The last item MUST end exactly at
`header_len`.

**Unknown TLV types MUST be hashed and MUST NOT cause rejection.** They are
opaque bytes to a verifier that does not know them. This is what makes §7.5
possible.

| Type | Name | Value |
|---|---|---|
| 0x0001 | `ORIGIN_ROLE` | UTF-8 role of the emitting component, e.g. `planner.main`; vocabularies are profile-defined (§3.4) |
| 0x0002 | `ORIGIN_MODEL_DIGEST` | 32 bytes |
| 0x0003 | `ORIGIN_CONFIG_DIGEST` | 32 bytes |
| 0x0011 | `MERKLE_TREE_HASH` | 32 bytes |
| 0x0012 | `MERKLE_LEAF_COUNT` | u32 |
| 0x0020 | `SHED_CLASS` | u16 |
| 0x0021 | `SHED_COUNT` | u32 |
| 0x0022 | `SHED_WINDOW_NS` | u64 |
| 0x0030 | `WITNESS_KIND` | u16 — 1 = transparency log, 2 = RFC 3161 TSA |
| 0x0031 | `WITNESS_RANGE_LO` | u64 |
| 0x0032 | `WITNESS_RANGE_HI` | u64 |
| 0x0033 | `WITNESS_RECEIPT` | opaque |
| 0x0040 | `SHRED_KEY_ID` | u32 |
| 0x0050 | `ANCHOR_HEAD` | 32 bytes — the head written to the anchor store. §7.2 |

**TLV type numbers and record type numbers are separate namespaces.** TLV
`0x0011 MERKLE_TREE_HASH` and record type `0x0020 MERKLE` both concern Merkle
aggregation and are different numbers in different spaces. The names are kept
distinct for that reason; do not read one table with the other's numbers.

**`origin` is three TLVs, not a name.** `(ORIGIN_ROLE, ORIGIN_MODEL_DIGEST,
ORIGIN_CONFIG_DIGEST)` — because *"which weights said that?"* is the first
question after an incident, and `"Tier1"` does not answer it. A model update is a
different origin and the chain shows it.

### 2.3 `body_len` — exactly what it counts

> **`body_len` is the total number of bytes following the header, up to the
> start of the next record.** A reader that consumes `body_len` bytes after
> `header_len` has consumed the whole body and nothing else.

For an encrypted body (§4.4) that total covers `nonce || ciphertext || tag` —
the nonce is **inside** the count, not additional to it. `body_digest` is taken
over exactly those `body_len` bytes.

This is spelled out because it is the one place where an implementer can be
confidently wrong: a reader that treats the 12-byte nonce as a prefix outside
`body_len` truncates the GCM tag, fails to decrypt, and blames the crypto.

### 2.4 File container

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
rotation, segmentation and naming are storage concerns outside this format —
a segment boundary is invisible to the chain, which continues across files
exactly as it continues across boots.

---

## 3. Record types

| Value | Name | Class | Meaning |
|---|---|---|---|
| 0x0001 | `GENESIS` | never-shed | Chain origin. §4.2 |
| 0x0002 | `BOOT` | never-shed | New boot. Its `prev_hash` **is** the cross-boot link. |
| 0x0010 | `SPAN_START` | normal | Opens a span |
| 0x0011 | `SPAN_END` | normal | Closes it. §3.1 |
| 0x0012 | `EVENT` | normal | Point event. Payload semantics are profile-defined (§3.4). |
| 0x0020 | `MERKLE` | sheddable | Digest aggregation over a window. §4.3 |
| 0x0021 | `AGGREGATE` | sheddable | Tier 0 statistics over a window. §3.2 |
| 0x0030 | `SHED` | **never-shed** | Records that records were dropped. §3.3 |
| 0x0040 | `SAFETY` | **never-shed** | Written by the safety path; the audit only observes |
| 0x0050 | `ANCHOR` | never-shed | Local anchor written. §7.2 |
| 0x0051 | `WITNESS` | never-shed | External witness receipt. §6 |
| 0x0060 | `KEY_SHRED` | never-shed | A key was destroyed. §4.4 |

### 3.1 Spans are two records

`SPAN_START` and `SPAN_END` are separate chained records. Duration is derived at
read time.

The alternative — one record written on close — loses exactly the case that
crashed. **A crash must leave a visibly unclosed span**, because that is the
evidence.

This also fixes the limit of the whole design: the audit **cannot** guarantee a
record precedes the action it describes — that would require blocking, which the
architecture forbids. It guarantees only that **absence is visible**. Not
write-ahead semantics. Detectable silence.

### 3.2 `AGGREGATE` body schema

Tier 0 statistics are not personal data, so an `AGGREGATE` body SHOULD be
cleartext (`key_id = 0`). Encrypting it would only make the post-market
monitoring export useless to the party entitled to read it.

The body is a TLV sequence, encoded exactly as §2.2, in its **own type
namespace**. The core defines the window framing; the measured quantities are
profile-defined:

| Type | Name | Value |
|---|---|---|
| 0x0001 | `AGG_WINDOW_NS` | u64 — length of the aggregation window. **Core.** |
| 0x0002 | `AGG_SAMPLE_COUNT` | u32 — samples folded into this record. **Core.** |
| 0x0003+ | *profile-defined* | Allocated upward from 0x0003 by the chain's profile (§3.4) |

A reader treats body tags it does not know as opaque — reported, never
rejected — the same posture §7.6 takes for the header. Because one chain
follows exactly one profile (§3.4), profile allocations cannot collide
within a chain.

**Milli-units, not floats — a constraint on profiles.** A float in a body
reintroduces exactly the cross-implementation disagreement §1.1 rejects JSON
for — and it would do so in the one record type whose whole purpose is being
comparable across versions and vendors. A profile MUST express fractional
quantities as fixed-point integers (milli-, micro-). Fixed-point integers
cost nothing and disagree with nobody.

The framing is defined here rather than left to implementations because
`AGGREGATE` is the PMM instrument: a wholly undefined body means two
conformant implementations produce incomparable exports, which defeats the
record type. The core fixes the window; each profile fixes the quantities —
so two implementations of the *same profile* are comparable. The robotics
profile (`profiles/robotics.md`) defines optical-flow statistics at
0x0003–0x0005.

### 3.3 `SHED` is in the never-shed class

The audit fails open: it never blocks the hot path. Therefore records are dropped
under saturation, and **which** records is a design decision, not an accident.

A dropped record is survivable. A **silently** dropped record is a log that lies
by omission, which is worse than no log. `SHED` carries class, count and window,
and it is never itself shed.

### 3.4 Profiles

The envelope must outlive any one domain, so the split is structural: this
document defines everything a verifier needs — layout, chain, tiers, time,
crypto, the three questions — and **profiles** define what the records are
*about*. A profile is a companion document that fixes, for one domain:

- **`EVENT` payload semantics** — what lives in the bodies;
- **`AGGREGATE` quantities** — body tags from 0x0003 upward (§3.2);
- **`MERKLE` leaf source** — what the aggregated digests are digests *of*,
  and at what rate (§4.3);
- **`ORIGIN_ROLE` vocabulary** — the component names that appear in headers.

**One chain follows exactly one profile.** Which profile is a property of
the deployment, stated by the emitting system's documentation; the format
does not carry a profile identifier in version 1 (a chain's `ORIGIN_ROLE`
vocabulary makes it evident in practice, and adding a field is a v1.0
freeze decision, not a retrofit). Mixing profiles within one chain is out
of scope.

**Verification is profile-independent.** Every check in §7 reads the
envelope only; a verifier needs no profile knowledge to answer the three
questions, and profile content it does not understand is opaque bytes —
reported, never rejected (§3.2, §7.6).

Profiles so far: **robotics** (`profiles/robotics.md`) — the first profile,
and the one the committed test vectors follow; and **inference**
(`profiles/inference.md`) — the dogfooding profile: the emitting library
audits its own serving loop, with `MERKLE` deferred until that profile
defines a leaf source.

---

## 4. Chain rules

### 4.1 Linking

```
record_hash(r)  = SHA-256(header_bytes(r))
r.prev_hash     = record_hash(previous record)
```

`seq` MUST increase by exactly 1 within a chain. **A gap in `seq` is a break,
whether or not the hashes link**, and a verifier MUST report it as one (§7.1).

The rule is not redundant with the hash link. An actor holding the key can
rebuild a shorter, perfectly linked chain that omits a range of `seq`; the
hashes will chain and only the gap betrays it.

### 4.2 Genesis and boots

- `GENESIS` has `prev_hash` = 32 zero bytes **and** `record_type = GENESIS`.
  A distinguished type is required so that *"no predecessor"* and *"predecessor
  removed"* are distinguishable. `prev_hash = 0` alone is not sufficient.
- A verifier MUST reject as a break any chain whose first record is not a
  `GENESIS`, and MUST report a `GENESIS` at any position other than the first
  as a violation. Defining the type and then not checking it buys nothing.
- **A `BOOT` record's `prev_hash` is the previous boot's head.** The chain is
  continuous across power cycles; a deleted segment leaves a head nothing
  references.

**What this does not fix — stated in the format, not hidden in prose:** an owner
with the key can start a *new* `GENESIS` and present the device as new. Chain
continuity cannot prove device continuity. Only §6 addresses that, and only
partly.

### 4.3 Merkle aggregation

High-rate digests are aggregated per window into one `MERKLE` record — the
digest **source** and rate are profile-defined (§3.4): the robotics profile
folds a second of sensor-frame digests into one record; an inference
profile might fold a batch of token or KV-operation digests. The tree is
the same either way.

RFC 6962 tree hash, domain-separated:

```
leaf(d)        = SHA-256(0x00 || d)
node(l, r)     = SHA-256(0x01 || l || r)
empty          = SHA-256("")
```

**An unpaired node is PROMOTED, never duplicated.** Duplicating the last node is
the CVE-2012-2459 mistake: two distinct leaf sets collapse to the same root.

Two constructions are in circulation and they agree, which is worth stating so
an implementer does not go looking for a discrepancy: RFC 6962 defines the tree
recursively, splitting at the largest power of two below `n`; the iterative
bottom-up form that promotes an unpaired node yields the same root. Either may
be implemented.

This buys **selective disclosure**: prove one leaf with ~log₂(n) hashes without
revealing the other n−1. *"Show me this moment"* without *"show me
everything"*.

### 4.4 Bodies, encryption and crypto-shredding

A body is one of two shapes, and `key_id` says which:

| `key_id` | Body |
|---|---|
| `0` | Absent (`body_len = 0`), or **cleartext**: `body` is the raw bytes |
| `≠ 0` | **Encrypted**: `body = nonce (12) ‖ ciphertext ‖ tag (16)` |

In both cases `body_digest = SHA-256(body_bytes)` over exactly `body_len` bytes.
The digest does not know which shape it covered — which is why crypto-shredding
does not disturb it.

Body encryption is **AES-256-GCM**.

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
safe past ~2³² records under one key — a horizon a sustained high-rate writer
actually reaches within the ten-year lifetime this format must survive (a
30 Hz emitter crosses it in under five years; higher rates get there
sooner). A `seq`-derived nonce is unique per record by construction — `seq` never
repeats within a chain (§4.1) — and its only leak is the record's position,
which the cleartext header states anyway. A key MUST NOT be reused across chains
with independent `seq` spaces.

**Order of operations is normative** (it is otherwise circular):
1. encrypt → 2. compute `body_digest` → 3. fill the header → 4. `record_hash`.

**Crypto-shredding.** Keys live outside the log, addressed by `key_id`. Erasure =
destroying `K[key_id]`; a `KEY_SHRED` record notes it. The body becomes noise,
`body_digest` stays, the chain still verifies. A verifier reports *"record
exists, body unreadable"* — honest, not a hole.

**Shred granularity equals key granularity, and that is a deployment decision,
not a format one.** Per subject, per session, per day — the format only requires
that `key_id` exists and that destroying a key breaks nothing structural.

**`key_id` scope is one device.** 2³² keys is ample per device and ambiguous
across a fleet: two devices may both use `key_id = 7` for unrelated keys. A fleet
key-management layer MUST qualify `key_id` with a device identity of its own;
the format does not carry one.

---

## 5. Time

A Jetson without an RTC battery boots into 1970. NTP is a network, and this is a
local-first system. So:

- **`monotonic_ns` and `seq` are authoritative for ordering.** Always present.
- **`wall_clock_ns` is advisory** and always accompanied by `time_trust`:

| `time_trust` | Meaning |
|---|---|
| 0 | `UNKNOWN` — `wall_clock_ns` MUST be 0 |
| 1 | `UNSYNCED` — free-running, no external reference |
| 2 | `HW_RTC` — battery-backed clock, unverified |
| 3 | `NTP_SYNCED` — externally synchronised |

Values above 3 are undefined in version 1. A verifier MUST report a record whose
`time_trust` is `UNKNOWN` with a non-zero `wall_clock_ns` as a violation (§7.1):
an unenforced MUST is not a MUST, and this one is the difference between an
honest *"I do not know the time"* and a confident timestamp that cannot be
justified. The first survives cross-examination. The second does not.

---

## 6. Assurance tiers

The format states how much it can be trusted. It does not overstate.

| Tier | Mechanism | Proves | Does not prove |
|---|---|---|---|
| **A** = 0 | Chain + local anchor | A record was modified; with the anchor, that nothing was truncated | Everything else |
| **B** = 1 | + hardware root of trust | Device identity | **Fresh genesis** — a TPM signs any chain |
| **B+** = 2 | + monotonic NV counter bound to `seq` | Counter never returns to zero → fresh genesis visible | Platform-bound |

**Tier C is deliberately not a header value.**

Tier C — periodic publication of the chain head to a transparency log or an RFC
3161 TSA — proves **existence at time T**, which is the guarantee that actually
defeats a fresh genesis. But a header cannot honestly claim to have been
witnessed *before the witness exists*.

So tier C is asserted **after the fact**, by a `WITNESS` record covering a `seq`
range. A verifier reads:

> *records 0–9: externally witnessed at 2026-07-16T10:00Z
> records 10–…: tier A, trust at your own risk*

**C is strictly stronger than B here**, because fresh genesis is a question of
existence, not identity. And it costs the thesis nothing: **one hash is
published, not data.** Certificate Transparency, applied to an audit log.

---

## 7. Verification (normative)

Verification answers three questions, and they MUST NOT be collapsed into one
boolean. Each needs different inputs and each fails differently.

| Question | Needs | Answers |
|---|---|---|
| **§7.1 Is what I hold internally consistent?** | Nothing | Modification, reordering, `seq` gaps |
| **§7.2 Is what I hold all of it?** | An anchor, from outside the log | Truncation, replacement, rollback |
| **§7.3 Did this history exist at time T?** | A witness receipt | Fresh genesis |

A verifier that reports only §7.1 as "ok" is misleading, because §7.1 cannot see
a truncated tail: dropping the last N records leaves a perfectly linked chain
with a different head and no other trace.

### 7.1 Header-only chain verification

Requires no key. Touches no bodies.

```
prev     := 32 zero bytes
expected := unset
for index, header h in file order:
    MUST h.magic == "PALA"                         else break, stop
    MUST h.header_len == actual header bytes       else violation
    if index == 0:
        MUST h.record_type == GENESIS              else break
        MUST h.prev_hash == 32 zero bytes          else violation
    else:
        MUST h.record_type != GENESIS              else violation
    if h.prev_hash != prev:  report break at h.seq
    if expected is set and h.seq != expected:  report gap at h.seq
    expected := h.seq + 1
    if h.format_version unknown or h.record_type unknown:
        report uninterpretable at h.seq            # NOT a break — §7.5
    else:
        run §7.4 semantic checks                   # violations, not breaks
    prev := SHA-256(h.header_bytes)
report: count, breaks, gaps, violations, uninterpretable, head = prev
```

`chain_ok` is true iff `breaks`, `gaps` and `violations` are all empty. It means
**internally consistent**, nothing more.

### 7.2 Completeness against an anchor

The anchor is the head this chain is supposed to have, obtained from **outside
the log**: the local anchor store (an OS keychain entry, noted in-chain by an
`ANCHOR` record and its `ANCHOR_HEAD` TLV), or the head covered by the newest
`WITNESS` receipt.

Given an anchor `A` and a computed head `H`:

| Condition | Report |
|---|---|
| `A == H` | Complete to the anchor |
| `A` is the `record_hash` of some record in the chain | **Unanchored tail**: `anchor_lag = N` records past the anchored head. A crash between write and anchoring, or an anchor-store outage — or records appended by a writer without anchor access. |
| `A` names no record in the chain | **Replaced, rolled back, or truncated.** This is not the history that was anchored. |

Both non-matching cases are failures; the diagnosis differs, and the diagnosis is
what an auditor acts on. Without an anchor a verifier MUST report completeness as
*not checked* — never as passing.

### 7.3 Existence against a witness

A `WITNESS` record asserts that the head of records `[RANGE_LO, RANGE_HI]` was
published to an external log at some time. Verification is out of scope for this
document — it follows the witness's own protocol (Rekor inclusion proof, RFC 3161
token). What this format guarantees is only that the claim is *in* the chain, is
itself chained, and names its range explicitly.

A verifier SHOULD report the witnessed range and the unwitnessed remainder
separately (§6).

### 7.4 Semantic checks

On records whose version and type are known:

- `time_trust == UNKNOWN` ⟹ `wall_clock_ns == 0` (§5)
- `time_trust <= 3` (§5)
- `body_len == 0` ⟺ `body_digest == 32 zero bytes` (§2.1)
- `key_id != 0` and `body_len > 0` ⟹ `body_len >= 28` (nonce + tag, §4.4)
- TLV items parse and end exactly at `header_len` (§2.2)

These are violations, not breaks: the record is defective, the chain around it
may be sound. They MUST be reported distinctly.

### 7.5 Body verification (needs the key)

`SHA-256(body) == header.body_digest`, then — if `key_id != 0` — AES-256-GCM
decrypt with the nonce and AAD of §4.4. Failure to decrypt with a **matching**
digest means the key is wrong or destroyed — not that the log is corrupt. These
MUST be reported distinctly.

### 7.6 Forward compatibility

A verifier meeting an unknown `format_version`, `record_type` or TLV type:

- **MUST** still chain-verify it — the hash is over raw bytes
- **MUST** report it as uninterpretable
- **MUST NOT** reject the chain
- **MUST NOT** apply §7.4 to it — those checks belong to a version it claims

**These fields are frozen for all future versions:** `magic`, `format_version`,
`header_len`, `record_type`, `seq`, `boot_id`, `prev_hash`, `body_len`,
`body_digest`, at their stated offsets.

`body_len` is in the frozen set for a mechanical reason: without it a verifier
cannot find the next record, and forward compatibility dies at the first
unknown record with a body.

That freeze is what keeps this sentence sayable in ten years by a tool written
today:

> *"Chain intact, 1.2M records, no gaps, 400 records I cannot interpret."*

---

## 8. Test vectors

Generated by `palaudit_ref.py`; full set in `test-vectors.json`. Deterministic:
fixed key, derived nonces, fixed IDs — real crypto, fake entropy. **Never do this
outside a test vector.**

The vector chain's record bodies and narrative follow the **robotics
profile** (`profiles/robotics.md`), the first profile and the one the
reference implementation emits. Every property demonstrated below is an
**envelope** property and holds under any profile.

The chain is a plausible ten seconds: genesis, boot with no clock, a brain span,
a `c'` write with an encrypted body, a second of frames, a second of Tier 0
statistics, a divergence event, a shed notice, span close, a local anchor, an
external witness, and a GDPR erasure.

```
key    = 000...02a (32 bytes)          key_id = 7
nonce  = 4 zero bytes || seq (u64 LE)  -> seq 3: 000000000300000000000000
body plaintext (seq 3) = "clear path ahead, one pedestrian at 12m, static"
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
| 10 | `WITNESS` | transparency log, covers seq 0–9 |
| 11 | `KEY_SHRED` | key 7 destroyed → seq 3 body unreadable |

**Expected results — an implementation that disagrees with any of these is
wrong, or this specification is:**

```
chain_head       = 3a1a3673f50498eb1d1c6f94b983d6c606cd85ed53627b4e4ffe55153c7af813
chain_ok         = true      record_count = 12   breaks = []   gaps = []   violations = []
complete_to_anchor = true    (anchor = chain_head)

anchor_head (seq 8) = 14434088e5f5866cf0276ba5a9055d8ee0d115a750b2cdf9cc4006d9481b29b4
merkle_tree_hash    = 518f5be5173250f705e3bda029ec1c11ac5c4459115c07dde5bc1021d9f468db
merkle_leaf_count   = 30     proof(index 7) verifies   proof_len = 5
```

Seven properties the vectors demonstrate rather than assert:

| Demo | Result |
|---|---|
| Flip one bit in the seq-3 body | `body_digest` mismatch detected **and the chain still verifies** — body damage and chain damage are distinct failures |
| Append a record of unknown type `0x7fff` | `chain_ok = true`, `count = 13`, `uninterpretable = [12]` — §7.6 works |
| Destroy key 7 | seq 3 body unreadable forever, chain unchanged — §4.4 works |
| **Drop the last record** | `chain_ok = true` **without** an anchor; `complete_to_anchor = false` **with** one — §7.1 cannot see truncation, §7.2 can. This is why the two questions are separate. |
| **Stale anchor** (anchor names seq 8, chain has 12) | `anchor_lag = 3`, reported as an unanchored tail, **not** a replacement |
| **`seq` gap** 11 → 99 with valid hashes | `chain_ok = false`, `gaps = [99]` — §4.1 |
| **Chain with no `GENESIS`** | `chain_ok = false`, violation *"chain does not start with a GENESIS record"* — §4.2 |
| **`time_trust = UNKNOWN` with a non-zero clock** | `chain_ok = false`, violation — §5 |

---

## 9. What this format does not do

Stated here rather than discovered later.

1. **It does not make the log true.** The chain proves *this is what the system
   recorded, unmodified*. Not *this is what happened*. A hallucinated model
   output is preserved faithfully.
2. **It does not defend against the owner at tier A.** Key and anchor are both
   theirs. Tier A is self-diagnostics. §6 is the only path out and it is partial.
3. **It does not bind to hardware.** *"This is the same device"* needs tier B+.
4. **A digest without its frame proves nothing about content.** Commitment
   defeats fabrication; it does not reconstruct.
5. **Cleartext headers are metadata, and metadata discloses.** The span graph,
   origins and timing are readable without a key. That is the price of §1.2, and
   it is not zero.
6. **It does not guarantee an action was logged before it happened.** §3.1.
7. **The chain alone does not detect truncation.** §7.2 is not optional garnish;
   without an anchor the last N records can be removed silently.

---

## 10. Open issues

Still open:

| # | Issue |
|---|---|
| 1 | **Endianness of the wire vs network convention.** Little-endian chosen for native cost. Reconsider only with a reason better than tradition. |
| 2 | **`seq` per chain — but is there one chain or several?** Currently one global chain with Merkle aggregation removing the high-rate pressure. If parallel writers still serialise badly under measurement, per-origin chains with cross-links return, and `seq` semantics change. **Unmeasured.** |
| 3 | **Witness durability.** A tier-C claim lives exactly as long as its witness. Rekor, a TSA, or self-hosted — each has a ten-year question, and self-hosted reintroduces *"trust us"*. |
| 4 | **TPM clear semantics.** Does a TPM clear reset NV counters? If yes, tier B+ is weaker than stated in §6 and that table is wrong. **Unverified.** |
| 5 | **Anchor store binding.** §7.2 requires an anchor from outside the log but does not say what holds it, or how a reader on a different machine obtains it. This is the same question as `AuditReader`: class or protocol. |

---

## 11. Status

The prose is normative; `palaudit_ref.py` alongside this document is a
reference implementation, subordinate to it — where they disagree, the
implementation is wrong.

This format remains a **draft**, not a specification, until the test at the
top of this document has actually been run: a second implementation, written
by someone who has not read the reference code, reproduces the §8 hashes
from this text and the vectors alone. Until then the field set may change,
and nothing should be built against it that cannot afford to re-encode.
