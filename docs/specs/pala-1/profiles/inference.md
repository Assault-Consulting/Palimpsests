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

| `EVT_KIND` | Meaning |
|---|---|
| 1 | `MODEL_LOAD` — a model became the active origin |
| 2 | `MODEL_UNLOAD` |
| 3 | `KV_SAVE` — session state serialized (`EVT_BLOB_DIGEST` present) |
| 4 | `KV_RESTORE` — session state restored (`EVT_BLOB_DIGEST` present) |
| 5 | `PREFIX_COPY` — a shared prefix copied into a session slot (`EVT_TOKEN_COUNT` = prefix length) |
| 6 | `PREFIX_WARM` — a prefix holder decoded a prefix for sharing |
| 7 | `RECOVERY_TRUNCATED_TAIL` — on resume, the writer removed a torn (never-complete) trailing record left by a crash; `EVT_DETAIL` carries the byte count and offset |

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

Operation metadata is not personal data, so an inference `EVENT` body
SHOULD be cleartext (`key_id = 0`) — the same reasoning the core applies
to `AGGREGATE`. The `EVT_DETAIL` clip at 200 bytes carries over the
emitting library's existing rule for error text in audit rows: exception
strings can embed URLs with tokens, and they do not belong in a
metadata-only log.

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
| 3 | **`EVT_KIND` completeness.** The enum will grow under Phase 3–4 instrumentation (shed classes, engine switches, context-memory events). Additions before freeze are expected; renumbering is not. |

---

## 7. Relationship to the writer

This profile is the contract Phase 3 implements: the writer emits
`GENESIS`/`BOOT`, session spans, §3 events, §4 guard refusals, §5
aggregates, `SHED` under saturation, `ANCHOR`/`WITNESS` per the core —
and the definition of done is the library verifying its own log:
`palimpsests pala verify` green on a stream this profile describes. The
first non-robotics chain in existence is the point: the format proves its
width by having two emitted profiles, not one dressed in generality.
