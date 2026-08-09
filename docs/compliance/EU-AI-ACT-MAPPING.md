# EU AI Act Article 12 Mapping

How Palimpsests and the PALA-1 audit log format support the
record-keeping requirements of Regulation (EU) 2024/1689 (AI Act),
as amended by Regulation (EU) 2026/1744.

**Claim form.** Palimpsests is a runtime component. It *enables
providers and deployers to meet* Article 12; conformity is a property
of the deployed system, not of this software. Nothing in this
document is legal advice.

**Legal base.** Article numbering follows the final text of
Regulation (EU) 2024/1689 as amended by Regulation (EU) 2026/1744
(in force 27 July 2026). The 2026 amendment did not modify Articles
12, 19, or 26(6); application dates for high-risk obligations are
2 December 2027 (Annex III standalone) and 2 August 2028 (Annex I
embedded). Verify against the consolidated EUR-Lex text when citing.

**Status legend.** `Shipped (v0.7)` — present in the v0.7.0 release;
`Planned (v0.8)` — scheduled, additive only (the wire format is
frozen at PALA-1 v1.0; the EVT_KIND space grows without any change to
framing or the hash contract); `Planned (post-0.8)` — on the roadmap,
not yet scheduled.

**Provenance.** Verified against the `v0.7.0` tag (`7940dc3`). PALA-1
core and both profiles are frozen at v1.0 (tag `pala1-v1.0`);
`test-vectors.json` digest `476c05ce…8193`, byte-identical since the
freeze. Capability claims below were checked against the source at
this tag.

---

## Article 12(1) — automatic recording of events over the system lifetime

| Capability | Mechanism | Status |
|---|---|---|
| Append-only record stream; no retroactive modification | Spec §1.2 (header hashing), §4.1 (chain linking + sequence numbers), §7.1 (verification); single locked emit path in the writer; tamper demos (bit-flip, truncation, gap) in §8 | Shipped (v0.7) |
| Continuity across restarts | Spec §2.4 (segment boundaries invisible to the chain; `BOOT` links to the previous boot's head); writer-side resume of an existing chain with cross-boot test | Shipped (v0.7) |
| Recording cannot be silently disabled | No disable/pause API exists; enablement is an engine construction parameter, immutable within a process; degradation under load is itself recorded (`SHED` records, never-shed semantics) | Shipped (v0.7) |
| Automatic emission, independent of user action | Engine emits at lifecycle points: model announce/load, session spans, KV operations, guard rejections (recorded before the exception is raised), anchor on close | Shipped (v0.7) |

## Article 12(2) — events relevant for the three stated purposes

### (a) Identifying risk situations (Art. 79(1)) and substantial modification

| Capability | Mechanism | Status |
|---|---|---|
| Model/weights/configuration change as a first-class event | `MODEL_LOAD` / `MODEL_UNLOAD` events carrying the origin triple: SHA-256 digest of the weights file itself and a canonical configuration digest (order-independent, deterministic) | Shipped (v0.7) |
| Safety-relevant rejections recorded | `SAFETY` class events for guard rejections, written before the exception propagates | Shipped (v0.7) |
| Automatic incident candidates with documented, pre-registered trigger criteria | `INCIDENT_CANDIDATE` record kind | Planned (v0.8) |
| Recorded acknowledgement chain for incident handling | `ACK` record kind referencing the candidate | Planned (v0.8) |

### (b) Facilitating post-market monitoring (Art. 72)

| Capability | Mechanism | Status |
|---|---|---|
| Header-only verifiability (no keys, no payload content) | The chain and Merkle verification consume record headers only; payload bodies are never needed to verify integrity (spec §1.2) | Shipped (v0.7) |
| Packaged header-only export bundle | Export tooling in the audit package | Planned (v0.8) |
| Incident timeline reconstruction (supports Art. 73 reporting) | Proved ordering via sequence numbers; session spans (a crash leaves a visibly unclosed span); monotonic deltas per record | Shipped (v0.7) |
| Aggregation-friendly export (JSONL; each line carries sequence, record hash, and anchor reference so integrity is reconstructable from an archive) | Export tooling in the audit package | Planned (v0.8) |
| Syslog / CSV derived exports (explicitly non-authoritative) | Export tooling in the audit package | Planned (v0.8, stretch) |

### (c) Monitoring of operation by deployers (Art. 26(5))

| Capability | Mechanism | Status |
|---|---|---|
| Verification without developer tooling | `pala verify` CLI (exit codes for sound / violation / partial; explicit partial semantics when no anchor is available) | Shipped (v0.7) |
| Independently implementable verification | Written from spec + byte-exact test vectors alone; demonstrated by four verifier implementations, two of them external (see INDEPENDENT-VERIFICATION.md), and reproducible by anyone via the verification kit | Shipped (v0.7) |
| Graphical review tooling | Auditor application | Planned (post-0.8) |

## Article 12(3) — minimum logging for remote biometric systems (Annex III 1(a))

Palimpsests is not a biometric system; Article 12(3) applies to it
only by analogy. We treat 12(3) as the strictest logging baseline in
the Act and map to it deliberately.

| 12(3) item | Mechanism | Status |
|---|---|---|
| (a) Period of each use (start/end) | `SPAN_START` / `SPAN_END`; `wall_clock_ns` (Unix epoch, UTC) qualified by an explicit `time_trust` field; per-record `monotonic_ns` | Shipped (v0.7); verifier-side advisory monotonicity drift-check Planned (v0.8) |
| (b) Reference data identification | Stronger than an identifier: SHA-256 digest of the weights file plus configuration digest | Shipped (v0.7) |
| (c) Input data | Hash-by-default design: bodies in the inference profile are metadata-only; `body_digest` always present; raw payloads are never written by default. Retention of raw payloads, where required, is a deployer-side policy outside the log. Encrypted-payload profiles support cryptographic erasure (§4.4) | Shipped (v0.7); explicit design-position wording in the spec Planned (v0.8) |
| (d) Identification of natural persons involved in verification (Art. 14(5)) | Pseudonymous `operator_id` on `ACK` records; the mapping from identifier to person remains with the deployer — no PII enters the log | Planned (v0.8) |

## Article 14 — human oversight (related, not an Art. 12 requirement)

Oversight actions become part of the tamper-evident record via `ACK`
(with pseudonymous `operator_id`) — Planned (v0.8). This mapping
claims event recording only; it makes no claims about oversight user
interfaces.

## Articles 19(1) and 26(6) — log retention

| Capability | Mechanism | Status |
|---|---|---|
| Archival of whole segments without loss of verifiability | Spec §2.4; verification consumes the file sequence | Shipped (v0.7) |
| Bounded, explicit degradation when a prefix is absent | Verifying a chain whose prefix is absent — e.g. an archived-away head — reports exactly one explicit violation at position 0 (missing genesis) and verifies the remainder as sound; the loss is visible, never silent. (A truncated *tail* is a different case: it is invisible to the §7.1 chain check and is caught by the anchor, not by a position-0 violation.) | Shipped (v0.7) |
| Retention guidance for providers (≥ 6 months context) and deployers, with storage estimates from measured bytes/record | Documentation | Planned (v0.8) |
| Formal prefix-consistency proofs for pruning | Merkle consistency proofs across pruned prefixes | Planned (post-0.8) |

## Beyond the requirements

Article 12 requires recording; it does not require integrity
protection. The following exceed the Article's demands and are
positioned as such:

- **Tamper evidence**: per-record chain linking (§4.1) and a Merkle
  tree over records (§4.3) enabling selective disclosure with
  inclusion proofs.
- **Erasure without integrity loss**: cryptographic erasure by
  per-record key destruction (§4.4); every hash in the chain and
  tree verifies unchanged after erasure (GDPR Art. 17 compatibility).
- **Documented erasure**: an erasure note — reason code plus the
  target sequence references — recorded on the `KEY_SHRED` record
  itself, so an erasure is not only performed but accounted for in
  the log — Planned (v0.8); supports GDPR Art. 17 record-keeping.
- **Independent verifiability**: byte-exact test vectors and a
  verification protocol exercised by external implementers against
  real releases, and packaged as a self-service verification kit.

## Other frameworks

Condensed mappings to SOC 2 (CC6.1, CC7.2, CC8.1), ISO/IEC 42001
(6.1.2, 8.4, 9.1), and PCI DSS v4 (Req. 10) follow the same claim
form and status legend — planned as follow-up sections in this
document.
