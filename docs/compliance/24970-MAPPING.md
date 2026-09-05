# ISO/IEC 24970 (AI system logging) Mapping

How Palimpsests and the PALA-1 audit log format support the logging
capabilities, requirements, and information model of ISO/IEC 24970
(*Artificial intelligence — AI system logging*), and where the
standard's obligations lie with the deploying organization rather than
with this software.

**Claim form.** ISO/IEC 24970 specifies *what* to log, *how events are
selected* (risk as the primary driver), and a supporting *information
model* — and is designed to be used **with a risk management system**.
Palimpsests is a runtime component: a verifiable, tamper-evident
logging **substrate**. It *enables* an organization to build a
24970-aligned logging programme; it does not, by itself, constitute
conformity. Selection of events, technical documentation of the logging
programme, and model-training auditability are properties of the
deployed system and its governance, not of this software. This is not a
conformity claim and not legal advice.

**Normative base — directional.** ISO/IEC FDIS 24970 reached stage
50.00 (final text for formal approval) on 18 May 2026; the European
adoption prEN ISO/IEC 24970 (CEN/CLC/JTC 21) adds **Annex Z**, mapping
the standard to Regulation (EU) 2024/1689 (AI Act) and thereby
supporting a presumption of conformity. **The final FDIS text is
paywalled.** The clause references below (5.2, 6.4, 6.5, 7.1, 8.3.1, the Annex A
information model) follow the public CD/DIS structure and SC 42
commentary; clause numbering and field detail may shift in the approved
text. **Verify against the purchased FDIS before any external claim.**

**Status legend.** `Shipped (v0.7)` — present in the v0.7.0 release;
`Planned (v0.8)` — scheduled, additive only (the wire format is frozen
at PALA-1 v1.0; the EVT_KIND space grows without any change to framing
or the hash contract); `Deployer` — a 24970 requirement that lies with
the AI system or organization using Palimpsests, not with the
substrate; `N/A (scope)` — outside the scope of an inference runtime;
`Shipped (v0.11)` — present in the v0.11.0 release; `Planned
(post-0.12)` — on the roadmap, not yet scheduled, additive only.

**Provenance.** Verified against the `v0.7.0` tag (`7940dc3`). PALA-1
core and both profiles are frozen at v1.0 (tag `pala1-v1.0`);
`test-vectors.json` digest `476c05ce…8193`, byte-identical since the
freeze. Capability claims below were checked against the source at this
tag; the bounded-storage section was added later and checked against
`v0.11.0`. Read alongside `EU-AI-ACT-MAPPING.md`: 24970 operationalizes
the AI Act Article 12 record-keeping duty this project already maps.

---

## Information model (Annex A)

24970 offers an example information model for consistent representation
of log entries. PALA-1's record model already carries the generic
fields; the mapping is field-for-field (confirm names against the final
Annex A).

| 24970 information-model field | Mechanism | Status |
|---|---|---|
| Event identifier / ordering | `seq` (monotonic u64), fixed in the hash chain so ordering is provable, not merely asserted (spec §4.1) | Shipped (v0.7) |
| Timestamp | `wall_clock_ns` (Unix epoch, UTC) qualified by an explicit `time_trust` field; per-record `monotonic_ns` | Shipped (v0.7) |
| Execution context / session | `boot_id`; `span_id` / `parent_span_id` (a crash leaves a visibly unclosed span) | Shipped (v0.7) |
| Event type | `record_type` + `kind` (EVENT/SAFETY); unknown kinds are chained, not rejected (spec §7.6 forward compatibility) | Shipped (v0.7) |
| Model / version | Origin triple in header TLVs: `role`, SHA-256 `model_digest` of the weights file, order-independent `config_digest` — available even on an encrypted log | Shipped (v0.7) |
| Event payload / detail | Record body (TLV) or encrypted body; `body_digest = SHA-256(body)` binds it to the chain | Shipped (v0.7) |
| Confidentiality / classification | `key_id` (0 = cleartext, ≠0 = AES-256-GCM body); basis of cryptographic erasure (spec §4.4) | Shipped (v0.7) |
| Record integrity | `record_hash` / `prev_hash` (spec §1.2, §4.1) — exceeds a plain information model; see Beyond | Shipped (v0.7) |
| External witness / timestamp | `WITNESS_RECEIPT` (opaque): Rekor / RFC 3161, algorithm-agnostic | Shipped (v0.7) |

The generic entry structure is covered by the substrate. Domain-specific
*content* placed into these fields — which events, which detail — is
selected by the AI system (see Clause 7.1 and Deployer responsibilities).

## Clause 7.1 — Risk-driven selection of events to log

| Capability | Mechanism | Status |
|---|---|---|
| A place to record any selected event, tamper-evidently | The engine emits lifecycle events (model announce/load, session spans, KV operations, guard rejections, anchor); an application may emit further domain events through the writer API | Shipped (v0.7) |
| Which events are "relevant" (risk as primary driver, ISO/IEC 23894) | Determined by the deployer's risk-management process; the substrate does not decide what to log | Deployer |

## Clause 6.5 — Technical documentation of the logging system

| Capability | Mechanism | Status |
|---|---|---|
| Documented log structure, kinds, and verification | Spec + profiles + `docs/audit/` (reader/anchors/tailing/CLI); the information model and hash contract are fully specified | Shipped (v0.7) |
| Documented logging criteria, human-oversight interaction, frequency and scope | A property of the deployer's logging programme; the material above is an input, but the 6.5 dossier is authored by the deployer | Deployer |

## Clause 8.3.1 — Logging for ML model auditability

| Capability | Mechanism | Status |
|---|---|---|
| Model identity and configuration recorded | `MODEL_LOAD` / `MODEL_UNLOAD` origin triple (weights digest + config digest) | Shipped (v0.7) |
| Training step, current model parameters, model quality | Requires a *training* system; Palimpsests is an inference runtime and does not produce these | N/A (scope) |

## Traceability and integrity

24970 requires traceability of events and decisions across AI
components. PALA-1 makes traceability cryptographically verifiable, not
merely recorded.

| Capability | Mechanism | Status |
|---|---|---|
| Provable ordering and continuity across restarts | Sequence numbers + chain linking (§4.1); `BOOT` links to the previous boot's head; cross-boot resume | Shipped (v0.7) |
| Verifiable traceability of model provenance | Origin triple bound into the header and chain | Shipped (v0.7) |
| Independently verifiable integrity | `pala verify` (sound / violation / partial exit codes); byte-exact test vectors; four verifier implementations, two external (`INDEPENDENT-VERIFICATION.md`) | Shipped (v0.7) |

## Security, privacy, and retention

24970 addresses the security / privacy / performance trade-offs of
logging.

| Capability | Mechanism | Status |
|---|---|---|
| Integrity / tamper-evidence of the log itself | Per-record chain linking (§4.1); Merkle tree (§4.3); completeness against truncation/replacement via anchors | Shipped (v0.7) |
| Confidentiality of log content | AES-256-GCM bodies (`key_id`); header-only verification needs no key or payload (§1.2) | Shipped (v0.7) |
| Erasure without integrity loss (privacy) | Cryptographic erasure by per-record key destruction (§4.4); every chain and tree hash verifies unchanged after erasure (GDPR Art. 17 compatible) | Shipped (v0.7) |
| Performance cost of logging | Measured: audit emission has no measurable throughput cost during inference (lifecycle-level emission against a ~10⁵× writer headroom); per-kind footprint ≈ 181 B/record weighted (`results/audit-overhead-footprint-v0.7.0.md`) | Shipped (v0.7) |
| Retention guidance from measured bytes/record | docs/RETENTION.md — storage math from the measured per-kind footprint (~181 B/record weighted), archival at segment boundaries, ~4 s/GB resume cost | Shipped (v0.8) |
| Pruned prefix provably a prefix of the live chain | `pala-consistency-proof/1`: RFC 6962/9162 consistency proofs over the derived §4.3 tree of record hashes — O(log n) nodes, no wire change, verified against roots held outside the file (`docs/specs/pala-1/consistency-proof.md`, companion vectors) | Shipped (0.12) |

## Human oversight events

| Capability | Mechanism | Status |
|---|---|---|
| Oversight / intervention recorded tamper-evidently | `SAFETY` events for guard rejections, written before the exception propagates | Shipped (v0.7) |
| Which oversight interactions to log | Selected by the deployer's oversight design | Deployer |

## Clauses 5.2 and 6.4 — bounded storage and its boundary

24970 allows circular logging (5.2, a *may*) and requires that a log
signal when it reaches a storage boundary (6.4 d). The position taken
here is deliberate and worth stating plainly, because "circular" is
easy to over-claim.

**Overwrite-in-place is not supported, and will not be.** Overwriting
a record breaks the `prev_hash` link of every record after it (spec
§4.1), so an overwritten chain either fails verification or — worse —
verifies while silently omitting what was overwritten. The standard's
own integrity requirements weigh against the second outcome, and the
format's rule against silent loss (spec §3.3: a dropped record must be
recorded as dropped) rules it out. The operational goal of circular
logging — a log that does not grow without bound — is met a different
way: **bounded segment-ring retention**. The writer cuts segments at
deterministic thresholds, the manifest keeps every segment head, expired
segments are deleted *whole* once outside the retention window, and the
survivors still name the history they continue (`RETENTION.md` §3).
Rotation, segmentation and naming are storage concerns outside the
frozen wire format (spec §2.4), so this needs no format change.

| Capability | Mechanism | Status |
|---|---|---|
| Bounded storage without unbounded growth (5.2, operational goal) | `RotationPolicy` on the writer (`max_records` / `max_bytes` / `max_age_s`); segments verify alone via manifest `prev_head` seeds and as one chain across the cut; retention math from measured ≈ 181 B/record, ≈ 4 s/GB resume (`RETENTION.md` §1, §3, §4) | Shipped (v0.11) |
| Circular overwrite of the oldest records (5.2, literal) | Not supported by design — see above. The claim form is "bounded segment-ring retention", never "circular overwrite supported" | N/A (design) |
| Records dropped under saturation are recorded, never silent (6.4 d, boundary reached) | `SHED` — never-shed record class carrying class, count and window (spec §3.3); the writer fails open and says so in-chain | Shipped (v0.7) |
| Boundary crossing recorded at the storage layer (6.4 d) | Segment cut at a threshold is itself the boundary event: the chain continues unbroken into the successor file, and the atomically-updated manifest records the closed segment with its head and `prev_head` seed | Shipped (v0.11) |
| Boundary *approaching* signalled before it is reached (6.4 d, predictive) | An additive EVT kind emitted when projected exhaustion of the retention budget falls inside a configured horizon; a runtime task, no wire change | Planned (post-0.12) |
| Deletion of expired segments recorded in the surviving chain | A retention-continuation profile: the segment that follows a deletion attests to what it continues from (predecessor head and root), so a verifier reading only the survivors sees a declared continuation, not an unexplained start. Design under review; no code in 0.12 | Planned (post-0.12) |
| `SHED` class value for storage-boundary drops | The core defines `SHED_CLASS` as a u16 (spec §2.2) and leaves the value registry to profiles; a `storage` class is allocated in the inference profile, additively, when the predictive event ships — no change to frozen text | Planned (post-0.12) |

**What the deployer decides.** Retention window, segment size and the
predictive horizon are policy; the substrate makes them deterministic
and visible in-chain, it does not choose them (`RETENTION.md` §3 has
the sizing rule and worked examples).

## Beyond the requirements

24970 requires useful, auditable logging; it does not require
cryptographic integrity of the log. The following exceed the standard's
demands and are positioned as such:

- **Tamper evidence** — per-record chain linking (§4.1) and a Merkle
  tree over records (§4.3), enabling selective disclosure with inclusion
  proofs.
- **Completeness, not just integrity** — an external anchor detects
  tail truncation and wholesale replacement, which a plain chain check
  cannot (spec §7.1).
- **Erasure without integrity loss** — cryptographic erasure (§4.4)
  reconciling auditability with GDPR Art. 17.
- **Independent verifiability** — byte-exact test vectors and a
  verification protocol exercised by external implementers against real
  releases, packaged as a self-service verification kit.
- **Reproducible, signed distribution** — Sigstore / PEP 740
  attestations and a reproducible build, so the *tooling* that produces
  and verifies logs is itself accountable.

## Deployer responsibilities

To make the boundary explicit — these 24970 obligations lie with the AI
system or organization, not with Palimpsests:

- **Event selection (7.1)** — risk-driven determination of which events
  are relevant to log.
- **Technical documentation (6.5)** — the logging-programme dossier:
  criteria, human-oversight and automated-monitoring interaction, and
  recommended frequency and scope.
- **Model-training auditability (8.3.1)** — for training systems; out of
  scope for an inference runtime.
- **Integration with a risk management system** — ISO/IEC 23894 /
  ISO/IEC 42001 at the AI-management-system level; Palimpsests is a
  component within it.

## Other frameworks

This mapping complements `EU-AI-ACT-MAPPING.md`: ISO/IEC 24970
operationalizes the Article 12 record-keeping duty, and the EN adoption's
Annex Z carries the presumption of conformity under Regulation (EU)
2024/1689. Condensed mappings to ISO/IEC 42001 (6.1.2, 8.4, 9.1) and
ISO/IEC 23894 follow the same claim form and status legend — planned as
follow-up sections.
