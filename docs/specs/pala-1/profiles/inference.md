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
| **Revision** | **r9** (2026-11-19) — additive only; see §9 for the revision history. r1 is the freeze. |
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
and is recorded in §6, issue 2.

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
| 0x000E | `EVT_OUTCOME` | u16 — 0 ok, 1 error, 2 timeout, 3 cancelled (§3.1, kind 9). *(r3)* 4 unobserved: a result returned, and the recording vantage could not observe whether the tool failed. *(r6)* |
| 0x000F | `EVT_TOOLS_OFFERED` | u16 — number of structured tools offered in the request (kind 10). *(r4)* |
| 0x0010 | `EVT_TOOLS_DIGEST` | 32 bytes — SHA-256 over the canonical offered-name list: the *sorted* names as a JSON array, compact separators, non-ASCII preserved, UTF-8 (the §6.2 discipline applied to names; kind 10). Order-independent: the offer is a set. *(r4)* |
| 0x0011 | `EVT_SOURCE` | u16 — how the serving layer learned of the event: 0 parsed from the wire it mediated, 1 reported by the client through the ingestion surface, 2 derived from a telemetry span the client exported *(r7)*. Absent means 0, so every prior record's meaning and bytes are unchanged. Kinds 8/9. An evidence-quality mark, never a trust upgrade. *(r5)* |
| 0x0012 | `SEG_PREDECESSOR_HEAD` | 32 bytes — `record_hash` of the last record of the previous segment; MUST equal the record's own `prev_hash` (§3.2, kind 11). *(r6)* |
| 0x0013 | `SEG_INDEX` | u32 — ordinal of the segment the record opens, counting from 0 for the segment that holds `GENESIS` (kind 11). *(r6)* |
| 0x0014 | `SEG_RETENTION_S` | u64 — the retention floor in force at the cut, in seconds; 0 means none declared (kind 11). Policy, not something the chain enforces. *(r6)* |
| 0x0015 | `SEG_PRIOR_ROOT` | 32 bytes — the derived root of `[0, seq)`: the §4.3 tree over the record hashes of every record before this one, always from record 0 (`consistency-proof.md` §1; kind 11). *(r6)* |
| 0x0016 | `EVT_ROUTE` | UTF-8, ≤ 64 bytes — the reporting route a count is about (kind 14, §3.4). A route, never a request. *(r9)* |
| 0x0017 | `EVT_REFUSED_EMPTY` | u32 — reports on the route refused for an absent or empty credential, so far in this run (kind 14). *(r9)* |
| 0x0018 | `EVT_REFUSED_WRONG` | u32 — reports on the route refused for a credential that is not the serving layer's, so far in this run (kind 14). *(r9)* |
| 0x0019 | `EVT_ACCEPTED` | u32 — reports accepted on the same route, so far in this run (kind 14). *(r9)* |
| 0x001A | `EVT_REJECTED` | u32 — reports to the route that were read and rejected, so far in this run (kind 14). *(r9)* |

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
| 10 | `TOOLS_OFFERED_NO_CALL` — the request offered structured tools, the completion produced no structured tool call, and the request itself carried no structured tool traffic; the serving layer records the visibility boundary it sits behind (§3.1). An observation of offer and absence, never an inference about what the reply text did. *(r4)* |
| 11 | `SEGMENT_CONTINUATION` — the first record of a segment the writer opened after a cut, declaring what precedes it (§3.2). *(r6)* |
| 12 | `WRITER_CLOSE` — the writer was closed; the last record it writes (§3.3). *(r8)* |
| 13 | `WRITER_OPEN` — a writer that marks its close with kind 12 began writing here (§3.3). *(r8)* |
| 14 | `REPORTS_REFUSED` — reports to a reporting route were refused before they were read (§3.4). *(r9)* |

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

### 3.1 Tool-loop events *(r3, r4, r5)*

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

**Outcome 4, `unobserved` *(r6)*.** Some vantages see a result come
back but cannot see whether the tool failed: a serving layer that reads
only the `role: tool` message the client sends, a gateway callback, an
agent hook that delivers a shell command's output as a string. For
those, `ok` claims too much — a reader counting failures from the chain
would count none — and `error` claims what was not observed. A writer
whose vantage cannot observe failure SHOULD record 4: the result
returned and re-entered generation, its digest is recorded as for `ok`
(`EVT_PAYLOAD_DIGEST` SHOULD be present), and whether it was a success
is not stated. A vantage that *can* observe failure — a hook that fires
separately on failure, a protocol result that carries an error flag —
records 0 or 1 as before.

`ok` (0) keeps its meaning (note 5): a return was observed; it never
stated success, and records written before r6 used it at blind vantages
too. Outcome 4 adds information, it does not narrow 0 — so a reader
cannot treat an `ok` as "the tool did not fail", before or after r6.

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

**Kind 10 *(r4)* — the boundary, made visible.** A completion can offer
tools and receive prose: a client that runs its tool loop in text keeps
every dispatch beyond this runtime's sight (the visibility limit above;
ADR-0005). Kind 10 records exactly the completions where that blindness
is total — structured tools offered, no structured call produced, and no
structured tool traffic in the request either. It asserts the offer and
the absence, never what the reply text did. `EVT_TOOLS_OFFERED` carries
the count and `EVT_TOOLS_DIGEST` the order-independent digest of the
offered names, so the offer is verifiable without content entering the
log. Completions inside a visible structured loop (tool-role messages or
prior structured calls in the request) do not emit kind 10 — that loop
is already on the record as kinds 8/9.

**Source marking *(r5)*.** Kinds 8 and 9 MAY carry `EVT_SOURCE`, and a
record written from a client report through the ingestion surface MUST
carry it with value 1. The absent tag means *parsed from the wire* — the
serving layer's own observation of a loop it mediated — which keeps
every r3/r4 record's meaning and bytes unchanged. The reference rule is
untouched: a reported result binds to its reported call by seq and hash
exactly as wire-parsed ones do. What the mark changes is what a reader
may *claim*: a wire-parsed pair is the runtime's own observation; a
reported pair is the client's assertion, faithfully recorded — the
chain proves the report happened, what it digested, and when, never
that the tool actually ran.

**Telemetry *(r7)*.** A pair written from a telemetry span — an
OpenTelemetry `execute_tool` span exported to the serving layer — MUST
carry `EVT_SOURCE` with value 2. It is a client's assertion like value 1,
and one step further from the event: a span is exported after the tool
returned and carries the call and its outcome together, so both records
of the pair are written at one moment, and their place in the chain is
when the export arrived — not when the call was made, and not in order
with the calls around it. A reader MUST NOT read the position or the
time claims of a value-2 pair as the time of the call. Value 1 keeps its
meaning: a report made for the audit, as the event happened. A reader
that does not know value 2 sees a source it cannot name, which is the
right answer for it. Records written before r7 from telemetry carry
value 1; they are not re-marked, and nothing in them was false — value 2
says more, not something else.

### 3.2 Segment continuation *(r6)*

A writer that rotates its container under a policy (cutting a new
segment file at a record boundary) MAY delete whole segments from the
front once a retention period has passed. The surviving chain then
starts mid-stream, and the core reports exactly that — its first record
is not a `GENESIS` (core §4.2). Kind 11 lets the writer **say so in the
chain, at the cut**, instead of leaving the gap unexplained. The full
design, with the reader's rows and the decisions behind them, is
`retention-continuation.md`; this section is its normative core.

**When.** A writer that uses this kind writes a `SEGMENT_CONTINUATION`
event as the **first record of every segment it opens after a cut**,
before any other record of that segment, under the same lock as the cut.
Segments made after the fact by an offline tool carry none — inserting a
record would break the chain.

**Body.** `EVT_KIND` = 11 first; then, ascending by type: `EVT_DETAIL`
(optional — the policy that made the cut, metadata only),
`SEG_PREDECESSOR_HEAD`, `SEG_INDEX`, `SEG_RETENTION_S`, `SEG_PRIOR_ROOT`
— all four MUST be present. The record's own `seq` is the number of
records before it; no count tag exists because none is needed. The body
MUST be cleartext (`key_id = 0`), for the reason the `KEY_SHRED` note is
(§8): the declaration must stay readable after every key that protected
the deleted prefix is gone.

**What it does not do.** It is an ordinary `EVENT`, never a `GENESIS`,
and it never changes the core verdict: a chain whose first surviving
record is a continuation still reports the §4.2 violation, because a
verifier that forgave a missing genesis on the strength of an in-chain
claim would have moved trust into the log. What changes is what a
profile-aware *reader* can add beside that verdict — a named row stating
the declared continuation, and whether the predecessor it names matches
a segments manifest, contradicts it, or is declared only.

**Reader checks (advisory, never a rejection).** `SEG_PREDECESSOR_HEAD`
equals the record's `prev_hash`; the record is the first of its file;
`SEG_INDEX` increases from one continuation to the next, consecutively
when the full chain is present; `key_id` is 0.

**Why the root is from record 0.** `SEG_PRIOR_ROOT` commits to every
record ever written before the segment, not to a window. After any
number of deletions, the newest surviving continuation record still
covers all of them at once, and a `pala-consistency-proof/1` between it
and any later derived root proves that prefix intact without the deleted
records. A writer keeps this root incrementally (a Merkle frontier) so
that it can state it after the records are gone.

### 3.3 The writer's lifecycle *(r8)*

A chain that simply stops says nothing about why. The writer may have
been closed, or the process may have been killed, or the power cut — and
a power cut can be someone's choice. The core already makes one such stop
visible: a crash in the middle of a record leaves a torn tail, which the
resumed writer removes and records (kind 7). A stop *between* records
left no trace. These two kinds give it one.

- **`WRITER_OPEN` (13)** is written by a writer directly behind the first
  `GENESIS` or `BOOT` record it writes. It declares: *this writer writes
  `WRITER_CLOSE` when it is closed.* `EVT_DETAIL` MAY name the writer and
  its version — metadata, never content — which also tells a reader which
  release's rules the boot's digests follow (§11).
- **`WRITER_CLOSE` (12)** is the last record a writer writes, when it is
  closed in order. It carries nothing but its kind.

Both are cleartext (`key_id = 0`), carry no span, and are ordinary links
of the chain.

**What the pair means.** A boot that holds a `WRITER_OPEN` and ends with
`WRITER_CLOSE` was closed in order. A boot that holds a `WRITER_OPEN`, is
followed by another boot, and does not end with `WRITER_CLOSE` was
stopped without being closed. A boot with no `WRITER_OPEN` promises
nothing: every chain written before r8 is such a chain, and its boots
are not judged by this rule.

**What it does not mean.** `WRITER_CLOSE` says the writer was closed, not
that the work it recorded succeeded: a process that exits on an error
closes its writer on the way out. And an unclosed boot is not an altered
chain: the records are whole and the links hold.

**Reader check (advisory, never a rejection).** For every boot but the
last in what the reader holds: if it holds a `WRITER_OPEN` and its last
record is not a `WRITER_CLOSE`, the reader reports it. The last boot is
not judged — its writer may be writing still. That one case this profile
cannot close: a writer stopped for good, and never resumed, leaves a
chain that looks like one still being written. Only something outside
the chain can tell the two apart — an anchor that stops advancing, or a
watcher.

**The head of a closed chain** is the hash of its `WRITER_CLOSE`. A head
read from a running writer and anchored is the head of a chain that then
grew by that one record; a verifier holding the earlier head reports the
closed chain as extending one record beyond it. An emitter that anchors
at shutdown anchors after the close.

### 3.4 Reports that were refused *(r9)*

A client that reports its tool events to the serving layer can be turned
away before the report is read — it sends no credential, or the wrong
one — or after: the body is not a report the route takes, cannot be read
at all, or breaks the handler. From its own side nothing looks wrong: an agent's hook never blocks
the agent, and a plugin logs the failure and lets the tool run. From the
chain's side nothing looked wrong either: the calls that were not
reported are simply not there, and a chain with a hole in it and a quiet
chain are the same bytes. Measured on real clients: every report of a run
refused for a missing key, and 4 of 26 hook posts refused for an empty
one.

**`REPORTS_REFUSED` (14)** records that it happened:

| Tag | |
|---|---|
| `EVT_ROUTE` | the reporting route |
| `EVT_REFUSED_EMPTY` | reports refused for an absent or empty credential |
| `EVT_REFUSED_WRONG` | reports refused for a credential that is not the serving layer's |
| `EVT_ACCEPTED` | reports accepted on the same route |
| `EVT_REJECTED` | reports that were read and rejected: answered with an error other than the credential's |

The four counts are as they stood when the record was written, since the
serving layer started. All five tags MUST be present, and at least one of
the two refused counts and the rejected count is not zero. The record is
cleartext (`key_id = 0`) and carries no span: a refused request belongs
to no session the serving layer could name.

**When it is written.** The first refusal on a route in a run is recorded
at once — so it is on the chain even if the process is then stopped — and
so is the first rejection. The counts as they stand are recorded once
more when the serving layer stops, if they have moved since the route's
last record. **At most three records per route per run.**
The bound is part of the rule, not a tuning: the record is caused by a
request that failed — authentication, or being a report at all — and
anyone who can reach the port can cause one. It must not be possible to grow the chain that way.

**What it says, and what it does not.** That a party tried to report on
that route and did not get in, and how often. Not who: the serving layer
did not learn that. Not what the reports held: nothing of a refused or
rejected request is recorded, and no count of tool events can be derived from a
count of requests. A reader takes it as: *for this run, the absence of
reported events is not evidence that nothing happened.*

It does not see a client that reports nothing at all — one whose hooks
were never configured, or were skipped by the client itself. Nothing
reaches the serving layer then, and nothing in a chain can show a
request that was never sent.

**Reader check (advisory).** A reader reports each `REPORTS_REFUSED`
record with its route and counts.

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

None is open as of r7. Each is kept here with how it was closed, because
earlier revisions, the core specification and recorded runs refer to
them by number.

| # | Issue | Closed |
|---|---|---|
| 1 | **`MERKLE` leaf source.** Version 1 defined none, and said an inference chain SHOULD NOT emit `MERKLE` records until a revision did. | **r7 — §10.** The leaves are record hashes: a `MERKLE` record is a checkpoint over the chain itself. The content-level candidates of r1 (per-request metadata digests, per-token-batch digests) are not adopted and stay undefined; a later revision may add one under a new leaf-source mark, never by changing §10. |
| 2 | **Canonical config encoding for `ORIGIN_CONFIG_DIGEST`.** Must be byte-deterministic, or the same config produces different origins. | **r7.** SHA-256 over the configuration as one JSON object in the canonical form of RFC 8785 (§11). A key order, a number or a nesting written another way is the same origin; a changed value is a different one. A chain written before r7 (Palimpsests 0.9–0.14) carries digests under the writer's earlier rule — `key=value` lines, keys sorted, each value as Python's `str()` prints it, joined by a newline, UTF-8, SHA-256 — which another language could not reproduce for every value. Those digests compare among themselves and with a configuration checked under that rule; they do not compare with r7 digests, so a chain that spans the change shows a new origin at it. |
| 3 | **`EVT_KIND` completeness.** The enum grows with instrumentation. | **Not an issue but a rule, stated as one in r7:** kinds, tags and vocabulary values are added, never renumbered, renamed or given another meaning. r2–r7 each exercised it with the envelope untouched. A reader meets a kind or a value it does not know and says so; it does not fail. |
| 4 | **Canonical tool-argument encoding for `EVT_PAYLOAD_DIGEST`.** | **By the writer (r3), pinned to a standard in r7.** SHA-256 over the value in the canonical form of RFC 8785 (§11); pre-canonicalized `bytes` are digested as they are. r3 said "JSON with sorted keys, compact separators, non-ASCII preserved", which left the writing of numbers and the order of keys to one library's serializer. The r7 form is the same bytes for every value that holds no non-integer or exponent-form number written by that serializer and no key outside the Basic Multilingual Plane — so those digests on existing chains still reproduce — and differs otherwise: `1.0` was digested as `1.0` and is digested as `1`. |
| 5 | **`EVT_OUTCOME = ok` is a return, not a confirmed effect.** | **Final as of r7.** On a `TOOL_RESULT` (kind 9), outcome 0 states that a result payload came back and re-entered generation. It does not state that the action took effect in the world: a payment tool can return `ok` on a request the downstream system later rejected, and a runtime at the model boundary cannot see that. Readers and reports MUST NOT render `ok` as "effect confirmed". This profile defines no confirmation record. A deployment that observes effects at another boundary records them as its own records from that vantage; if a later revision gives them a kind, it is added, and the meaning of outcome 0 does not move. |

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
| r4 | 2026-09-02 | Additive only: `EVENT` kind 10 (`TOOLS_OFFERED_NO_CALL`, §3.1); `EVT` tags 0x000F (`EVT_TOOLS_OFFERED`) and 0x0010 (`EVT_TOOLS_DIGEST`); the canonical offered-name digest (writer-owned, the §6.2 discipline applied to sorted names). No envelope byte, no core text, no byte of `test-vectors.json` changed; companion vectors for kind 10 extend `inference-vectors.json` in the implementing PR chain. |
| r5 | 2026-09-03 | Additive only: `EVT` tag 0x0011 (`EVT_SOURCE`) — the wire-parsed / client-reported evidence mark for kinds 8/9; absent means wire-parsed, so every prior record's meaning and bytes are unchanged. No envelope byte, no core text, no byte of `test-vectors.json` changed; companion vectors extend `inference-vectors.json` in the implementing PR chain. |
| r6 | 2026-10-10 | Additive only: `EVT_OUTCOME` value 4 (`unobserved`, §3.1) — a return whose failure the recording vantage could not observe; `EVENT` kind 11 (`SEGMENT_CONTINUATION`, §3.2); `EVT` tags 0x0012–0x0015 (`SEG_PREDECESSOR_HEAD`, `SEG_INDEX`, `SEG_RETENTION_S`, `SEG_PRIOR_ROOT`) — the retention-continuation design (`retention-continuation.md`) adopted. No envelope byte, no core text, no byte of `test-vectors.json` changed; `inference-vectors.json` gains four records (21 in all, every earlier record byte-identical), and the prefix-consistency vectors stay pinned to the 17-record r5 prefix and unchanged. |
| r7 | 2026-11-19 | Additive only, and the open issues closed (§6). `EVT_SOURCE` value 2 (`derived-from-telemetry`, §3.1) — a pair written from an exported telemetry span. `MERKLE` records defined for this profile as chain checkpoints whose leaves are record hashes (§10), which is what the writer has emitted since 0.10; the r1 "SHOULD NOT emit" is withdrawn. The digests over JSON values — `ORIGIN_CONFIG_DIGEST` and `EVT_PAYLOAD_DIGEST` — are taken over the RFC 8785 canonical form (§11): a new rule for the first, and for the second the r3 rule pinned to a standard, with the same bytes wherever r3 was unambiguous. Issues 3 and 5 recorded as closed without a change of bytes or meaning. No envelope byte, no core text, no byte of `test-vectors.json` changed; `inference-vectors.json` gains three records (24 in all, every earlier record byte-identical), and the prefix-consistency vectors stay pinned to the 17-record r5 prefix and unchanged. |
| r8 | 2026-11-19 | Additive only: `EVENT` kinds 12 (`WRITER_CLOSE`) and 13 (`WRITER_OPEN`), §3.3 — a writer marks where it began and that it was closed, so a boot stopped without a close is visible once the chain goes on. No new tag. No envelope byte, no core text, no byte of `test-vectors.json` changed; `inference-vectors.json` gains three records (27 in all, every earlier record byte-identical), and the prefix-consistency vectors stay pinned to the 17-record r5 prefix and unchanged. |
| r9 | 2026-11-19 | Additive only: `EVENT` kind 14 (`REPORTS_REFUSED`, §3.4) and `EVT` tags 0x0016–0x001A (`EVT_ROUTE`, `EVT_REFUSED_EMPTY`, `EVT_REFUSED_WRONG`, `EVT_ACCEPTED`, `EVT_REJECTED`) — reports to a reporting route that were refused before being read, or read and rejected, are on the chain, at most three records per route per run. No envelope byte, no core text, no byte of `test-vectors.json` changed; `inference-vectors.json` gains five records (32 in all, every earlier record byte-identical), and the prefix-consistency vectors stay pinned to the 17-record r5 prefix and unchanged. |

## 10. `MERKLE` — chain checkpoints *(r7)*

The core defines the `MERKLE` record and its tree (core §4.3) and leaves
to each profile what the leaves are. For this profile:

**A `MERKLE` record is a checkpoint over the chain itself.** Its leaves
are the record hashes (core §4.1) of every record after the previous
`MERKLE` record, *that record included*, up to but not including the new
one, in `seq` order. The first checkpoint of a chain starts at `seq` 0.
The windows therefore tile the chain: every record but the tail after the
last checkpoint is a leaf of exactly one window, and each checkpoint is a
leaf of the next.

| Field | Value |
|---|---|
| `MERKLE_TREE_HASH` (0x0011) | the core §4.3 root over those leaves |
| `MERKLE_LEAF_COUNT` (0x0012) | how many — the window is the `MERKLE_LEAF_COUNT` records ending at `seq − 1` |
| body | none (`body_len = 0`) |

When to write one is the emitter's choice — by count, by time, at a
session's end. Nothing in a reader depends on the cadence.

**What a disclosed leaf proves.** A record's header and its audit path
(core §4.3) show that the record is one of those the checkpoint commits
to: its `seq`, its type, its time claims and the digest of its body, as
the chain holds them — without the other records of the window. With the
body, the whole record. It proves nothing about a request beyond what
that one record says, and nothing about records that are not disclosed.

**What it is not.** Not the derived root of §3.2 and of the consistency
proofs, which is one tree over *every* record hash from `seq` 0 and is
computed by whoever holds the chain, never carried in a `MERKLE` record.
Both are the core §4.3 tree over record hashes; they differ in what they
span. And not a content digest: no leaf here is a digest of request or
completion text.

**Verification.** A `MERKLE` record is an ordinary link of the chain and
is verified as one. Whether its tree hash is the root of its window is
not one of the core's checks (core §7.4) and is not added here: a party
that builds or checks an audit path recomputes the window, and a tree
hash that is not its root makes every path of that window fail.

## 11. The canonical form of a JSON value *(r7)*

Two digests of this profile are taken over a JSON value: the engine's
configuration (`ORIGIN_CONFIG_DIGEST`) and a tool's arguments or result
(`EVT_PAYLOAD_DIGEST`). A digest is evidence only if another party can
compute it again from the value, in another language and without the
emitter's code. So the form is a published one:

**the JSON Canonicalization Scheme, RFC 8785, as UTF-8, then SHA-256.**

In short, and the RFC governs:

- no whitespace;
- object keys sorted by UTF-16 code unit;
- strings as they are, with `"` and `\` escaped, the short escapes for
  U+0008, U+0009, U+000A, U+000C and U+000D, and lowercase `\u00xx` for
  the other control characters;
- numbers as ECMAScript writes them: `1.0` is `1`, `1e21` is `1e+21`,
  `0.000001` stays as it is and `1e-7` is exponential.

Three consequences an emitter should know:

- **A number is an IEEE 754 double.** An integer beyond 2^53 is digested
  as the double nearest to it. An identifier that large belongs in a
  string.
- **NaN, the infinities and a lone surrogate have no canonical form.** A
  value holding one cannot be digested; the emitter records the event
  without a digest, or refuses it — it does not substitute a form of its
  own.
- **A value handed over as bytes is digested as those bytes.** That is
  for an emitter whose protocol already has a canonical encoding, and it
  is what the tool-loop vectors of r3–r6 do.

`EVT_TOOLS_DIGEST` (r4) is unchanged: the sorted names as a JSON array
of strings is already the same bytes under RFC 8785.
