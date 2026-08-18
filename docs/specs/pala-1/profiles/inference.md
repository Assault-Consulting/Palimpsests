# PALA-1 inference profile

The second PALA-1 profile, and the dogfooding one: record-body semantics
and vocabularies for a local LLM inference library emitting PALA-1 about
its own serving loop — model loads, sessions, KV operations, serving
statistics. This document is a companion to the core specification
(`../PALA-1.md`, §3.4) and defines nothing about the envelope, the chain,
or verification: those are the core's, and they hold here unchanged. A
verifier needs nothing from this document to answer the core's three
questions.

| | |
|---|---|
| **Profile of** | PALA-1, version 1 |
| **Status** | **Frozen — v1.0** (2026-08-09, with the core). Existing tag and kind allocations are permanent; the `EVT_KIND` and `AGG_*` spaces grow **additively** in profile revisions (§6.3) — additions never renumber and never touch the envelope. The profile is emitted by the Palimpsests writer (Phase 3, wired). |
| **Date** | 2026-08-09 (frozen; first draft 2026-08-03) |
| **Revision** | **r3** (2026-08-18) — additive only; see §9 for the revision history. r1 is the freeze. |
| **Licence** | CC0-1.0, like the core specification and its test vectors. |

**Metadata-only discipline.** The emitting library's existing audit log
records model and KV *operations*, never request content, and this
profile keeps that line: no tag below carries prompt or completion text.
A deployment that chooses to log content anyway MUST encrypt those bodies
(`key_id ≠ 0`) so crypto-shredding remains the erasure path; the profile
neither requires nor encourages it.

---

## 1. `ORIGIN_ROLE` vocabulary

UTF-8 values for the core's `ORIGIN_ROLE` TLV (core §2.2), naming the
emitting component. Names map to the library's actual modules rather than
an invented taxonomy:

| Role | Component |
|---|---|
| `engine.ollama` | Level 1 adapter — external daemon |
| `engine.llamacpp` | Level 2 adapter — managed `llama-server` subprocess |
| `engine.native` | Level 3 — the in-process serving engine |
| `scheduler` | The native decode loop and its slot management |
| `kv_store` | The content-addressed KV state store |
| `context_memory` | The window manager / block-memory layer |

The core's origin triple answers *"which weights said that?"*:
`ORIGIN_MODEL_DIGEST` is the digest of the loaded model artefact (the
GGUF file for levels 2–3), and `ORIGIN_CONFIG_DIGEST` is the digest of
the canonical encoding of the engine's memory configuration — a config
change is a different origin and the chain shows it. How the canonical
config encoding is produced is fixed by the writer, not this profile,
and is an open issue until it is (§6).

## 2. Spans — sessions and requests

A **session is a span**: `SPAN_START` when a stateful session opens,
`SPAN_END` when it closes, `span_id` carried by every record the session
produces. The core's crash guarantee then reads directly on serving: a
process that dies mid-session leaves a visibly unclosed span, which is
the evidence (core §3.1). One-shot requests MAY be spans of their own;
nested request-within-session spans use `parent_span_id`. This profile
adds no span body — the envelope's span fields are sufficient — so a
span record's `body_len` SHOULD be 0.

## 3. `EVENT` bodies — model and KV operations

An `EVENT` body is a TLV sequence, encoded exactly as core §2.2, in its
own type namespace:

| Type | Name | Value |
|---|---|---|
| 0x0001 | `EVT_KIND` | u16 — see the kind table below. MUST be present, first. |
| 0x0002 | `EVT_BLOB_DIGEST` | 32 bytes — digest of the KV state blob saved or restored |
| 0x0003 | `EVT_TOKEN_COUNT` | u32 — tokens involved in the operation (e.g. prefix length copied) |
| 0x0004 | `EVT_DETAIL` | UTF-8, ≤ 200 bytes — clipped, metadata only, never request content |
| 0x0005 | `EVT_CATEGORY` | u16 — incident category (§4, kind 102). *(r2)* |
| 0x0006 | `EVT_SEVERITY` | u16 — 1 low, 2 medium, 3 high. *(r2)* |
| 0x0007 | `EVT_RECOVERABLE` | u8 — 0 no, 1 yes. *(r2)* |
| 0x0008 | `EVT_REF_SEQ` | u64 — `seq` of the record this one refers to. *(r2)* |
| 0x0009 | `EVT_REF_HASH` | 32 bytes — `record_hash` of the referenced record; binds the reference past any `seq` ambiguity. *(r2)* |
| 0x000A | `EVT_OPERATOR_ID` | 16 bytes — pseudonymous operator identifier (§4, kind 103). *(r2)* |
| 0x000B | `EVT_DISPOSITION` | u16 — 0 acknowledged, 1 dismissed, 2 escalated. *(r2)* |
| 0x000C | `EVT_TOOL_NAME` | UTF-8, ≤ 64 bytes — the registered tool identifier (§3.1). An identifier, never arguments. *(r3)* |
| 0x000D | `EVT_PAYLOAD_DIGEST` | 32 bytes — SHA-256 of the canonical tool arguments (kind 8) or tool result payload (kind 9); the payload itself never enters the log. *(r3)* |
| 0x000E | `EVT_OUTCOME` | u16 — 0 ok, 1 error, 2 timeout, 3 cancelled (§3.1, kind 9). *(r3)* |

| `EVT_KIND` | Meaning |
|---|---|
| 1 | `MODEL_LOAD` — a model became the active origin |
| 2 | `MODEL_UNLOAD` |
| 3 | `KV_SAVE` — session state serialized (`EVT_BLOB_DIGEST` present) |
| 4 | `KV_RESTORE` — session state restored (`EVT_BLOB_DIGEST` present) |
| 5 | `PREFIX_COPY` — a shared prefix copied into a session slot (`EVT_TOKEN_COUNT` = prefix length) |
| 6 | `PREFIX_WARM` — a prefix holder decoded a prefix for sharing |
| 7 | `RECOVERY_TRUNCATED_TAIL` — on resume, the writer removed a torn (never-complete) trailing record left by a crash; `EVT_DETAIL` carries the byte count and offset |
| 8 | `TOOL_CALL` — the serving loop dispatched a tool invocation requested by the model (§3.1). *(r3)* |
| 9 | `TOOL_RESULT` — a dispatched invocation returned and its result re-entered generation (§3.1). *(r3)* |

A `RECOVERY_TRUNCATED_TAIL` event is written by a resumed writer as the
first record after `BOOT`, when opening the chain truncated a torn
trailing record — bytes a crashed process wrote only partially. A torn
record never entered the chain (its header never hashed into a link), so
removing it does not contradict append-only; what append-only demands is
that the removal be **on the record**, and this kind is that record. A
writer MUST NOT truncate anything beyond the torn region, and MUST
refuse auto-recovery when the bytes after the damage contain further
record magic — that is mid-stream damage for the verifier to diagnose,
not a torn tail.

### 3.1 Tool-loop events *(r3)*

When the serving engine runs a tool loop — the model requests a tool,
the runtime executes it, the result re-enters generation — the runtime
is the one component that observes every dispatch directly, below any
agent framework. These two kinds record that observation. What they
record is dispatches, not "decisions": whether a dispatch was wise is a
judgment the log must not fake, in exactly the sense §4 refuses to fake
incident determinations. What they give a reader is the decision
*evidence* at the layer where it is generated: which tool, when, with
what argument digest, and what came back.

**`TOOL_CALL` (8).** Written when the loop dispatches an invocation.
The body MUST carry `EVT_TOOL_NAME`, SHOULD carry `EVT_PAYLOAD_DIGEST`
over the canonical argument encoding (the writer fixes the
canonicalization, as it does for the config digest), and MAY carry
`EVT_DETAIL`. Arguments and results never appear in the body in any
form other than a digest — the metadata-only line above is unchanged by
this revision.

**`TOOL_RESULT` (9).** Written when the invocation returns (or fails,
or is abandoned). The body MUST carry `EVT_REF_SEQ` **and**
`EVT_REF_HASH` of its `TOOL_CALL` — the same hash-bound reference rule
as `OVERSIGHT_ACK`, checked by readers as an advisory — MUST carry
`EVT_OUTCOME`, and SHOULD carry `EVT_PAYLOAD_DIGEST` over the result
payload when the outcome is `ok`. `cancelled` (3) covers abandonment:
session closed, loop preempted, or a guard refusing further dispatches
(§4, kind 104).

Two properties fall out of existing structure rather than new
mechanics, and are worth stating so nobody builds them twice. Duration:
both records carry `monotonic_ns`, so invocation latency is the delta
between a result and its referenced call — no duration tag exists
because none is needed. Composition with oversight: the r2 reference
tags are generic, so an `INCIDENT_CANDIDATE` MAY name a `TOOL_CALL` or
`TOOL_RESULT` as its source record today, with zero new machinery —
tool activity that trips a documented trigger becomes a referenced,
never-shed observation through the loop that already exists.

**Unknown kinds — the reader rule** *(r2)*. A reader encountering an
`EVT_KIND` it does not know MUST treat the body as opaque, MUST report
the kind as unknown, and MUST NOT reject the record or the chain — core
§7.6, mirrored one layer up. This binds *readers*; the envelope verifier
never reads kinds at all (core §7 is body-blind by construction), so an
addition to this enum cannot affect chain verification in any
implementation. Additions never renumber.

Operation metadata is not personal data, so an inference `EVENT` body
SHOULD be cleartext (`key_id = 0`) — the same reasoning the core applies
to `AGGREGATE`. The `EVT_DETAIL` clip at 200 bytes carries over the
emitting library's existing rule for error text in audit rows: exception
strings can embed URLs with tokens, and they do not belong in a
metadata-only log. Tool *names* are identifiers and sit on the metadata
side of that line; tool *arguments* do not, which is why kind 8 carries
a digest and nothing else.

## 4. `SAFETY` — guard refusals

The library's serving path contains guards that refuse operations rather
than corrupt state — the prefix-holder release-ordering guard is the
canonical case: releasing a holder with live consumers would silently
perturb their logits, and the guard refuses. A `SAFETY` record is written
when a guard fires: the audit *observes* the refusal, it does not
implement it (core §3). The body is the §3 TLV encoding with `EVT_KIND`
values from 100 upward:

| `EVT_KIND` | Meaning |
|---|---|
| 100 | `GUARD_PREFIX_RELEASE` — a prefix-holder release was refused while consumers were live |
| 101 | `GUARD_STATE_REJECT` — a persisted KV blob failed validation before reaching the C parser |
| 102 | `INCIDENT_CANDIDATE` — the library observed a pattern worth a human look (Art. 12(2)(a) support). *(r2)* |
| 103 | `OVERSIGHT_ACK` — a human (or delegated service) recorded a disposition for a candidate (Art. 14 support). *(r2)* |
| 104 | `GUARD_TOOL_LOOP_LIMIT` — the tool loop hit its configured iteration or depth cap and further dispatches were refused. *(r3)* |

**`INCIDENT_CANDIDATE` (102)** *(r2)*. Not an incident determination —
that is a legal judgment the log must not fake — but a recorded,
never-shed observation that a documented trigger fired. The body MUST
carry `EVT_CATEGORY` and `EVT_SEVERITY`, SHOULD carry
`EVT_RECOVERABLE`, and MAY carry `EVT_REF_SEQ` + `EVT_REF_HASH` naming
the source record, plus `EVT_DETAIL`. Categories in r2:

| `EVT_CATEGORY` | Trigger (pre-registered; thresholds are deployment-tunable) |
|---|---|
| 1 | `GUARD_ESCALATION` — guard refusals exceeded a threshold within a window |
| 2 | `SELF_CHECK_FAILED` — the library's own chain self-verification reported a failure |
| 3 | `ANCHOR_ANOMALY` — anchor-store writes failed repeatedly |

The category enum grows additively like every enum in this profile.
`SAFETY` records are never shed (core §3): dropping incident evidence
under load is the one shed no deployment may configure.

**`GUARD_TOOL_LOOP_LIMIT` (104)** *(r3)*. The §4 pattern applied to the
tool loop: the cap refuses further dispatches rather than let a runaway
loop exhaust the engine, and the record observes the refusal. The body
SHOULD carry `EVT_TOKEN_COUNT` as the iteration count reached and MAY
carry `EVT_REF_SEQ` + `EVT_REF_HASH` of the last `TOOL_CALL` before the
cap. Loop-limit refusals feed the same escalation counter as every
guard — a burst of them becomes an `INCIDENT_CANDIDATE` with category 1
through the existing r2 trigger, not through anything new.

**`OVERSIGHT_ACK` (103)** *(r2)*. The oversight loop's closing record.
The body MUST carry `EVT_REF_SEQ` **and** `EVT_REF_HASH` of the
candidate being answered (the hash binds the reference), MUST carry
`EVT_DISPOSITION`, and MUST carry `EVT_OPERATOR_ID`. The operator id is
**pseudonymous by construction**: 16 opaque bytes whose mapping to a
person lives with the deployer, outside the log — no name, no account,
no PII ever enters a record. A writer validates the *format* of these
fields only; whether the reference names a real candidate is the
reader's referential-integrity check, reported as an advisory, never a
chain violation (the chain is sound either way — the semantics may not
be).

## 5. `AGGREGATE` body — serving statistics

The core fixes the window framing (`AGG_WINDOW_NS`, `AGG_SAMPLE_COUNT`,
tags 0x0001–0x0002) and hands quantities to profiles from 0x0003 upward
(core §3.2). This profile allocates:

| Type | Name | Value |
|---|---|---|
| 0x0003 | `AGG_REQUESTS` | u32 — requests completed in the window |
| 0x0004 | `AGG_TOKENS_PREFILL` | u64 — prefill tokens computed |
| 0x0005 | `AGG_TOKENS_DECODE` | u64 — decode tokens produced |
| 0x0006 | `AGG_PREFILL_SAVED` | u64 — prefill tokens *not* recomputed thanks to shared prefixes, the tool loop, or KV restore |
| 0x0007 | `AGG_SESSIONS_OPEN` | u32 — open sessions at window end |
| 0x0008 | `AGG_TOOL_CALLS` | u32 — tool invocations dispatched in the window. *(r3)* |

All quantities are natural integers; the core's fixed-point constraint is
satisfied without milli-units. `AGG_PREFILL_SAVED` is deliberate: the
library's measured value proposition is avoided re-prefill, and this tag
makes that claim an auditable time series rather than a benchmark
artefact. Statistics are not personal data: cleartext (`key_id = 0`),
per core §3.2.

The window length is the writer's choice (deployment-tunable); the
per-second convention of the robotics profile does not carry over.

## 6. Open issues (profile)

| # | Issue |
|---|---|
| 1 | **`MERKLE` leaf source — deferred.** Version 1 of this profile defines no leaf source, and an inference chain SHOULD NOT emit `MERKLE` records until a revision defines one. Candidates: per-request metadata digests (selective disclosure of one request's existence) vs per-token-batch digests (finer, heavier). The choice changes what a disclosed leaf proves and is not needed for the first writer. |
| 2 | **Canonical config encoding for `ORIGIN_CONFIG_DIGEST`.** Must be byte-deterministic across versions of the emitting library, or the same config produces different origins. Fixed by the writer; recorded here when it is. |
| 3 | **`EVT_KIND` completeness.** The enum will grow under Phase 3–4 instrumentation (shed classes, engine switches, context-memory events). Additions before freeze are expected; renumbering is not. *r2 exercised exactly this path: kinds 102–103 and tags 0x0005–0x000B arrived additively with the envelope untouched. r3 repeated it: kinds 8–9 and 104, tags 0x000C–0x000E, one `AGG_*` tag.* |
| 4 | **Canonical tool-argument encoding for `EVT_PAYLOAD_DIGEST`.** Same shape as issue 2: byte-deterministic across library versions, or the same call produces different digests. Fixed by the writer; recorded here when it is. *(r3)* |

---

## 7. Relationship to the writer

This profile is the contract Phase 3 implements: the writer emits
`GENESIS`/`BOOT`, session spans, §3 events, §4 guard refusals, §5
aggregates, `SHED` under saturation, `ANCHOR`/`WITNESS` per the core —
and the definition of done is the library verifying its own log:
`palimpsests pala verify` green on a stream this profile describes. The
first non-robotics chain in existence is the point: the format proves its
width by having two emitted profiles, not one dressed in generality.

## 8. `KEY_SHRED` bodies — documented erasure *(r2)*

The core already makes erasure and immutability compatible: destroy
`K[key_id]`, note it with a `KEY_SHRED` record, the chain stays intact
(core §4.4). What the core record does not carry is *why* — and an
erasure a deployer cannot document is half an answer to GDPR Art. 17.
This profile therefore defines a TLV body for `KEY_SHRED` records, in
its **own** type namespace (it is not an `EVENT` body):

| Type | Name | Value |
|---|---|---|
| 0x0001 | `SHRED_REASON` | u16 — 0 unspecified, 1 legal_erasure, 2 retention_expiry, 3 policy |
| 0x0002 | `SHRED_TARGET_SEQS` | concatenated u64 LE array (`length / 8` = count) — the record seqs whose bodies this key protected; optional |
| 0x0003 | `SHRED_DETAIL` | UTF-8, ≤ 200 bytes — ticket/request reference, metadata only; optional |

One record, one operation: the note rides the same `KEY_SHRED` record
that documents the destruction — never a second record type, never a
second event. The body MUST be cleartext (`key_id = 0`): an erasure
note encrypted under some other key would need its own erasure story,
and the note must outlive every key by design. Whether
`SHRED_TARGET_SEQS` names records that exist and carried that
`key_id` is a reader advisory, like every referential check in r2.

## 9. Revision history

| Rev | Date | Changes |
|---|---|---|
| r1 | 2026-08-09 | The freeze (with core v1.0). Tags 0x0001–0x0004; kinds 1–7, 100–101; `AGG_*` 0x0003–0x0007. |
| r2 | 2026-08-10 | Additive only: `EVT` tags 0x0005–0x000B; `SAFETY` kinds 102 (`INCIDENT_CANDIDATE`, category enum 1–3) and 103 (`OVERSIGHT_ACK`); the `KEY_SHRED` body schema (§8); the unknown-kind reader rule (§3). No envelope byte, no core text, and no byte of `test-vectors.json` changed; the new semantics ship with their own companion vectors (`inference-vectors.json`, generated by `gen_inference_vectors.py` beside it). |
| r3 | 2026-08-18 | Additive only: `EVENT` kinds 8 (`TOOL_CALL`) and 9 (`TOOL_RESULT`) with §3.1; `SAFETY` kind 104 (`GUARD_TOOL_LOOP_LIMIT`); `EVT` tags 0x000C–0x000E (`EVT_TOOL_NAME`, `EVT_PAYLOAD_DIGEST`, `EVT_OUTCOME`); `AGG_TOOL_CALLS` (0x0008); open issue 4 (canonical tool-argument encoding). No envelope byte, no core text, no byte of `test-vectors.json` changed; companion vectors for the new kinds extend `inference-vectors.json` in the implementing PR chain. |
