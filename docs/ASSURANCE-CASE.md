# Assurance Case

A structured, **defeasible** argument that Palimpsests provides the
security and record-keeping properties it claims — stated as
**Claims → Arguments → Evidence**, with the limits of each claim named
rather than glossed. It exists for the same reason the
[threat model](THREAT_MODEL.md) does: to state guarantees *precisely*, so
a reviewer in a regulated or sensitive setting can check them instead of
taking an adjective on trust.

It is **defeasible** by design: every claim is paired with its residual,
and a [Defeaters](#defeaters) section lists the conditions that would
break specific claims. This is not a certification and makes no compliance
claim — see [What this does not assert](#what-this-does-not-assert).

## Scope

Applies to the Palimpsests **core library + CLI** in this repository, at
the current release. Downstream consumers (desktop, GUI, cloud
integrations) are out of scope. The case concerns four properties an
evaluator cares about: **record-keeping integrity**, **confidentiality and
residency**, **supply-chain verifiability**, and the **engineering-quality
substrate** the other three rest on.

## Top-level claim

**G0.** *Palimpsests is a local-first inference substrate whose audit
record is tamper-evident, whose at-rest data is confidential and
host-resident, and whose releases are cryptographically verifiable — such
that it **materially supports, but does not by itself satisfy**, high-risk-
AI record-keeping and software-supply-chain expectations, with the
residual responsibilities stated for the deployer.*

The clause **"does not by itself satisfy"** is load-bearing: the project
supplies primitives; the deploying organization carries configuration,
operational security, and the compliance determination itself. See the
regulated-sector mapping in [SECURITY.md](../SECURITY.md).

G0 decomposes into claims C1–C5.

---

## C1 — The audit log is tamper-evident

**Argument.** Alteration, deletion, or reordering of records is detected by
a per-row **hash chain**; wholesale replacement or rollback of the whole
store is detected by an **out-of-band head anchor**; and verification is
honest about *when* the replacement check actually ran, so a pass is never
read as stronger than it is.

**Evidence.**
- Hash chain: `row_hash = SHA-256(prev_hash || canonical(row))`, canonical
  encoding length-prefixed so no field value can forge a record boundary
  ([SECURITY.md](../SECURITY.md) → *Integrity*; [THREAT_MODEL.md](THREAT_MODEL.md)).
- Out-of-band anchor in the OS keychain, scoped to the database path;
  `verify()` compares chain head to anchor.
- `VerifyResult.head_anchored` states whether the replacement check ran;
  `anchor_lag` distinguishes an unanchored tail from a replacement.
- Tests tamper with the database file **directly, bypassing the API**;
  `palimpsests audit verify` exposes verification with distinct exit codes.
- The attacker-capability table in [SECURITY.md](../SECURITY.md) enumerates
  what is and is not detected.

**Residual.** Holding the key **and** keychain-write access forges chain
and anchor together (undetected — the anchor buys *two stores to
compromise, not one*, not a guarantee). Host compromise before an event is
written cannot be attested. Timestamps are process-supplied — the chain
proves *order and integrity*, not wall-clock accuracy. A legitimate append
after a replacement re-anchors the forged chain; run `audit verify` before
resuming writes to a suspect log. Not independently audited.

## C2 — At-rest data is confidential and host-resident

**Argument.** The audit store is encrypted at rest with a key the host
controls, and the design **fails closed** rather than silently degrading.
Inference itself runs on-host, so request content does not leave the
machine, and air-gapped operation is a supported mode.

**Evidence.**
- SQLCipher (AES-256), 256-bit key in the OS keychain; if no native
  SQLCipher build is present the log **refuses to open** — plaintext is
  available only by explicit opt-in and is still hash-chained
  ([SECURITY.md](../SECURITY.md) → *Confidentiality*).
- `encryption` / `keyring` extras isolate these dependencies
  (`pyproject.toml`); crypto is delegated, never hand-rolled, at AES-256
  with no weak-length option ([BADGE-STATUS.md](BADGE-STATUS.md) → Security).
- Local-first execution across levels 1–3; no third-party network call to
  answer a request ([SECURITY.md](../SECURITY.md) → *What the design gives
  you*).

**Residual.** Confidentiality is not integrity (that is C1). A compromised
host or a malicious operator holding the key is out of reach. Level 2's
managed `llama-server` listens on an **unauthenticated local port** — a
documented **single-user-host-only** constraint (accepted risk,
[SECURITY.md](../SECURITY.md)).

## C3 — Releases are supply-chain verifiable

**Argument.** Published artifacts carry cryptographic provenance binding
the exact file to this project's workflow and tag, produced without any
stored secret; and each release ships a machine-readable bill of materials.

**Evidence.**
- PyPI **Trusted Publishing (OIDC)** — no token stored; **Sigstore PEP 740
  attestations** bind artifact digest ↔ `release.yml` ↔ tag ↔ OIDC issuer
  ([RELEASING.md](../RELEASING.md); PyPI *Provenance* section, first
  recorded at v0.3.0).
- **CycloneDX SBOM** of the base-install closure attached to each GitHub
  Release, generated reproducibly from a clean environment
  ([RELEASING.md](../RELEASING.md) → *SBOM*; `release.yml`).
- Workflow least-privilege: read-only default, per-job scope, actions
  pinned by commit SHA ([BADGE-STATUS.md](BADGE-STATUS.md) → delivery_*).

**Residual.** Provenance covers the **PyPI distribution artifacts**, not
the Git tag objects (tag signing is not currently used — stated
boundary). The SBOM is the **base-install** closure; extras are opt-in and
declare their own dependency. The SBOM is **not yet attested** (binding it
to the artifact digest via `actions/attest-sbom` is a named next step).

## C4 — Capabilities are declared, not assumed

**Argument.** Behavior is programmed against *declared* capabilities rather
than implementation detail, and two settled boundaries keep behavior
predictable and reviewable.

**Evidence.**
- Engines advertise `engine.capabilities`; memory options are validated
  (e.g. KV-cache quantization requires flash attention)
  ([SECURITY.md](../SECURITY.md)).
- The three-level model and stateless/stateful split are documented and
  enforced in review; the **no-kernel** boundary and **library-not-
  application** scope are stated constraints ([ARCHITECTURE.md](../ARCHITECTURE.md),
  [CONTRIBUTING.md](../CONTRIBUTING.md)); architecture decisions recorded in
  [`docs/adr/`](adr/).

**Residual.** The correctness of a capability advertisement rests on tests,
not formal proof.

## C5 — The engineering-quality substrate

**Argument.** The claims above are only as trustworthy as the code beneath
them, so the project sustains automated quality and security gates
proportionate to a small team, and records its posture honestly.

**Evidence.**
- CI on **3 OS × Python 3.11/3.12**, tests ship with every behavioral
  change, escape/denial paths tested explicitly ([CONTRIBUTING.md](../CONTRIBUTING.md);
  `ci.yml`).
- **Bandit SAST** merge-blocking on every push/PR (`sast.yml`); pinned
  **ruff** lint gate merge-blocking.
- **Coverage-guided fuzzing (Atheris/libFuzzer)** of the untrusted-input
  **KV-state validator** that guards `load_state` — a short regression on
  every change plus a nightly budget (`fuzz.yml`).
- Systematic **OpenSSF Best Practices (passing)** posture, answered
  criterion-by-criterion ([BADGE-STATUS.md](BADGE-STATUS.md)); measurement
  discipline for claims ([BENCHMARKING.md](BENCHMARKING.md), Rule 0).

**Residual.** Branch coverage is not yet measured (`test_most` recorded
Unmet). Fuzzing is scoped to the **Python** validator, **not** the C parser
it guards — persisted blobs crossing into C are only a real boundary once a
disk-backed KV store ships, at which point they must be MAC'd (HMAC-SHA256)
and header-validated first (roadmap; accepted risk). Small-team review
limits are acknowledged, not hidden.

---

## Defeaters

The conditions that would break specific claims, stated plainly:

| Condition | Claim defeated |
|---|---|
| Attacker holds the encryption key **and** can write the keychain | C1 (chain + anchor forged together) |
| Host is compromised before an event is written | C1, C2 (nothing unwritten can be attested) |
| Level 2 enabled on a host shared with untrusted processes | C2 (unauthenticated local port) |
| `load_state` fed an externally-produced blob before the MAC boundary ships | C1, C5 (validator guards structure, not authenticity) |
| Relying on the log's timestamps as wall-clock truth | C1 (order proven, not time) |
| Reading this document as a compliance certification | G0 (out of scope) |

Each defeater is a *known* boundary with a stated mitigation or a "do not
do this," not a latent surprise.

## What this does not assert

- **Not** a certification or conformity assessment; **not** a claim that any
  deployment is regulation-compliant.
- **Not** independently audited or penetration-tested.
- Does **not** cover downstream consumers or a specific deployment
  configuration.
- Does **not** assert wall-clock accuracy, protection against a compromised
  host, or protection when the key and keychain are both held.

## Maintenance

Reviewed at each release and kept in lockstep with
[SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md). A
residual moves to *resolved* only when the evidence exists — for example,
the `state_set` MAC boundary will upgrade the C1/C5 residual when it ships,
and SBOM attestation will upgrade the C3 residual. Claims are never
advanced ahead of their evidence.
