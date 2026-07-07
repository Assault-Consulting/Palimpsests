# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue.

- Use [GitHub's private security advisories](https://github.com/Assault-Consulting/Palimpsests/security/advisories/new)
  for this repository, **or**
- email **[INSERT SECURITY CONTACT — e.g. security@your-domain]**.

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
  recorded to an audit log backed by an encrypted store (SQLCipher, with the key
  held in the OS keychain). The intent is an audit trail whose integrity can be
  demonstrated after the fact — not merely application logs that live on mutable
  infrastructure and can be silently altered.
- **Capabilities are declared, not assumed.** Each engine advertises exactly
  what it supports (`engine.capabilities`), and memory options are validated
  (e.g. KV-cache quantization requires flash attention). Callers program against
  declared capabilities, never against implementation details.

### What this is **not**

- Palimpsests is an **inference library**, not a certified compliance product.
  It has **not** undergone any formal certification or conformity assessment
  (e.g. against a harmonized standard), and using it does not by itself make a
  deployment compliant with any regulation.
- The audit log's tamper-evidence is a property of the design; it has **not**
  been independently audited or penetration-tested. Treat it as a strong default
  to build on, not a certified guarantee.
- Encryption at rest protects the audit store; it does not protect against a
  compromised host, a leaked keychain, or a malicious operator with local
  privileges. Threat-model your deployment accordingly.

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
little evidentiary value in an audit. An encrypted, tamper-evident audit trail is
aimed squarely at that gap.

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
