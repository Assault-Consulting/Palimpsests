# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

- Use [GitHub's private security advisories](https://github.com/Assault-Consulting/Palimpsests/security/advisories/new)
  for this repository, **or**
- email as@assault.consulting

Include, where possible: affected version or commit, a description of the issue,
reproduction steps or a proof of concept, and the impact you foresee. We aim to
acknowledge a report within a few business days and to agree on a disclosure
timeline with you. Please give us reasonable time to investigate and ship a fix
before any public disclosure.

We do not currently run a paid bug-bounty program. We will credit reporters in
release notes unless you ask us not to.

## Supported versions

Palimpsests is pre-1.0 and evolving. Security fixes land on `main` and in the
latest published release. Older `0.x` releases are not maintained; please track
the latest version.

---

## Security posture

This section describes what the project provides today and what it deliberately
does **not** claim. It is written for security reviewers and for teams
evaluating Palimpsests in regulated or sensitive environments.

### What the design gives you

- **Local-first / air-gap capable.** The core (level 1 Ollama, level 2
  llama.cpp, level 3 pal-native) runs entirely on-host. No inference request
  content leaves the machine, and no component requires a network call to a
  third-party service to answer a request. This makes air-gapped deployment a
  supported operating mode, not a workaround. On-device inference trades raw
  speed for deployment properties that matter in regulated settings: no network
  dependency, no per-token cost to an external provider, and data residency on
  hardware you control.
- **Encrypted, tamper-evident audit log.** Every model and KV-state operation is
  recorded to an encrypted store (SQLCipher, key in the OS keychain), and each
  record is cryptographically chained to its predecessor so that alteration is
  *detectable*, not merely discouraged. The exact guarantee — and its limits —
  is specified in [Audit-log threat model](#audit-log-threat-model) below.
- **Capabilities are declared, not assumed.** Each engine advertises exactly
  what it supports (`engine.capabilities`), and memory options are validated
  (e.g. KV-cache quantization requires flash attention). Callers program against
  declared capabilities, never against implementation details.

### What this is **not**

- Palimpsests is an **inference library**, not a certified compliance product.
  It has **not** undergone any formal certification or conformity assessment
  (e.g. against a harmonized standard), and using it does not by itself make a
  deployment compliant with any regulation.
- The audit log's tamper-evidence is implemented and tested (see below), but the
  implementation has **not** been independently audited or penetration-tested.
  Treat it as a strong default to build on, not a certified guarantee.
- Encryption at rest protects the audit store's *contents*; the hash chain
  protects its *integrity*. Neither protects against a compromised host or a
  malicious operator who holds both the encryption key and write access to the
  keychain. Threat-model your deployment accordingly.

---

## Accepted risks

Risks we know about, have decided not to fix yet, and state here so the person
carrying the risk is the person who knows about it. Tracked in
[`docs/security/AUDIT-2026-07.md`](docs/security/AUDIT-2026-07.md).

### Level 2 (managed `llama-server`) is single-user-host only

When level 2 is enabled, Palimpsests spawns and manages a `llama-server` child
process that listens on a **local HTTP port with no authentication**
(`--api-key` is not set). Consequences on a shared host:

- **Any other process running on the same machine can reach that port** — send
  its own prompts into your slots, read model output, or exhaust the server.
  `llama-server`'s own built-in endpoints raise the ceiling on what a local
  attacker can do there.
- Port selection has a **time-of-check/time-of-use race**: a free port is chosen
  and then bound, so a hostile local process can, in principle, occupy the port
  first and impersonate the server to Palimpsests.

**Therefore: do not enable level 2 on a host you share with untrusted users or
untrusted processes.** Levels 1 and 3 are unaffected — level 1 talks to a daemon
you already run, and level 3 runs in-process with no listening socket.

This is **deferred by decision**, not overlooked. Level 3 is planned to split
into a separate distribution, which changes the HTTP exposure model entirely;
the mitigation (a per-launch random `--api-key`, plus verifying the
health-checked process owns the expected port) will land with that work. Until
then, treat the level-2 adapter as a single-user-host component.

### `state_set` is not yet a validated trust boundary

`NativeSession.load_state` passes blob bytes to llama.cpp's
`llama_state_seq_set_data`, which parses them in C. Today those blobs are
produced in-process by `save_state` and held in memory, so no untrusted input
reaches that parser. This becomes a real boundary the moment a **disk-backed KV
store** or blob sharing between hosts ships — both of which are on the roadmap.
Before either lands, persisted blobs must be MAC'd (HMAC-SHA256 under a
keychain-derived key) and header-validated before `state_set` sees them. Until
then, do not feed `load_state` a blob you did not produce.

---

## Audit-log threat model

The audit log is the project's compliance surface, so its guarantees are stated
precisely rather than by adjective. Two mechanisms, two different properties.
The full model — assets, attacker capabilities, and which guarantees are in
force under which configuration — is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Confidentiality — encryption at rest

The store is SQLCipher-encrypted with a 256-bit key held in the OS keychain
(Keychain, Credential Manager, Secret Service). Without the key, the file's
contents are not readable.

If no native SQLCipher build is present, the log **refuses to open**. The
operator may accept a plaintext log deliberately — `allow_unencrypted=True` in
the API, or `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` for the CLI — but it is never
a silent fallback. A plaintext log is still chained, so tampering remains
evident; only confidentiality is given up.

### Integrity — hash chain plus out-of-band anchor

Encryption is not integrity. Anyone holding the key can open the database and
rewrite rows. Two mechanisms make that detectable:

1. **Hash chain.** Every row stores `prev_hash` (its predecessor's hash) and
   `row_hash = SHA-256(prev_hash || canonical(row fields))`. The canonical
   encoding is length-prefixed, so no field value can forge a record boundary,
   and `NULL` encodes distinctly from the empty string. **Altering, deleting, or
   reordering any row breaks the chain**, and `AuditLog.verify()` reports the
   first row that fails.

2. **Out-of-band head anchor.** A chain alone cannot detect *wholesale
   replacement*: an attacker with the key can drop the table and build a fresh,
   internally consistent chain. The chain's current head hash is therefore also
   stored **outside the database**, in the OS keychain, scoped to that database's
   path, refreshed as rows are written and flushed on close. `verify()` compares
   the chain's head to the anchor; a mismatch means the history was replaced or
   rolled back.

`verify()` returns a `VerifyResult` whose `head_anchored` flag states whether the
replacement check was actually performed. **A passing result with
`head_anchored=False` means the chain is internally consistent but wholesale
replacement would not have been detected** — for example on a headless host with
no keychain. The flag exists so that a passing verification is never read as
stronger than it is. A stale anchor that still names a row *inside* the chain is
reported separately as `anchor_lag` (an unanchored tail, e.g. after a crash
between commit and anchoring), not as a replacement.

### What an attacker can still do

Stated plainly, because the boundary matters more than the mechanism:

| Attacker capability | Detected? |
|---|---|
| Reads the database file, no key | Contents unreadable (encrypted) |
| Edits, deletes, or reorders rows, holding the key | **Yes** — chain breaks |
| Replaces the whole database with a valid fresh chain, holding the key | **Yes** — head anchor mismatch |
| Restores an older snapshot of the database, holding the key | **Yes** — the anchor names no row in the old chain |
| Holds the key **and** can write to the keychain | **No** — chain and anchor can be forged together |
| Compromises the host before events are written | **No** — nothing unwritten can be attested |

Detecting the fifth row requires committing the chain head somewhere outside the
host's trust boundary — a remote append-only log, a notary, or a transparency
log. **Palimpsests does not do this, and does not claim it.** What the anchor
buys is that tampering must compromise two separate stores rather than one file.

The sixth row is inherent to any local logging: a log can only attest to what
reached it.

### Residual weaknesses we know of

Named here rather than discovered by someone else:

- **Timestamps are process-supplied** (`datetime.now(UTC)` at write time). A
  compromised process can write a truthful-looking chain with false times. The
  chain proves *order and integrity*, not *wall-clock accuracy*.
- **The anchor is refreshed every `anchor_every` rows** (default: every write).
  If raised for performance, the most recent rows are chained but not yet
  anchored until the next refresh or `close()`. Keychain write failures are
  counted (`AuditLog.anchor_failures`) and warned about once, rather than
  silently dropping the guarantee.
- **A legitimate append after a replacement re-anchors the forged chain.** Run
  `palimpsests audit verify` before resuming writes to a log you suspect.
- **No independent audit.** The implementation is tested — including tests that
  tamper with the database file directly, bypassing the API — and has been
  reviewed internally (`docs/security/AUDIT-2026-07.md`), but has not been
  reviewed by a third party.

---

### Why these primitives map to regulated-sector needs

Regulated deployments — finance, defense, healthcare, public sector — commonly
require three things that a cloud inference API cannot offer at once: the data
never leaves controlled infrastructure, every automated decision is traceable
after the fact, and that trace cannot be silently rewritten. Local-first
execution addresses the first; an encrypted, tamper-evident audit log addresses
the second and third.

The **EU AI Act** (Regulation (EU) 2024/1689, in force since 1 August 2024, with
obligations phasing in under Article 113) makes record-keeping a legal
requirement for *high-risk* AI systems, and an agent that calls tools and acts on
the results is a strong candidate for the high-risk (Annex III) classification:

- **Article 12(1)** requires high-risk AI systems to *technically allow for the
  automatic recording of events (logs) over the lifetime of the system* — logging
  the system itself generates, not manual documentation.
- **Article 12(2)** requires those logs to cover risk-relevant situations,
  post-market monitoring (Article 72), and operational monitoring by deployers
  (Article 26(5)).
- **Article 26(6)** requires the automatically generated logs to be retained for
  a period appropriate to the intended purpose, and **at least six months**.

Notably, Article 12 does not use the word *tamper-proof* — but a log that can be
silently altered, and whose integrity you cannot demonstrate on demand, has
little evidentiary value in an audit. The hash chain and head anchor described
above are aimed squarely at that gap: they let a deployer *demonstrate* integrity
on demand rather than assert it.

A few honest caveats on the regulatory picture, current as of mid-2026:

- **The technical standards are not final.** There is no finalized technical
  standard for Article 12 logging yet; drafts such as prEN 18229-1 (AI logging
  and human oversight) and ISO/IEC DIS 24970 (AI system logging) are still in
  progress. Palimpsests targets the *outcome* the regulation describes, not a
  settled standard.
- **The timeline is moving.** The Digital Omnibus agreement of 7 May 2026 shifted
  several deadlines: high-risk Annex III enforcement moved from 2 August 2026 to
  2 December 2027, and Annex I (AI in regulated products) to 2 August 2028. The
  first new binding deadline is 2 December 2026 (Article 50 transparency). Check
  the current text before relying on any specific date.
- **Reach is extraterritorial.** Under Article 2, the Act applies to providers
  placing AI systems on the EU market regardless of where they are established.
- **Adjacent regimes may also apply**, depending on sector and data — GDPR
  (personal data), and DORA for EU financial entities. We name these as context,
  not as a compliance claim.

Nothing here is legal advice. It explains *which primitives the project provides*
and *which obligations they are designed to help address*; whether a given
deployment is compliant is a determination for the deploying organization and its
advisors.
