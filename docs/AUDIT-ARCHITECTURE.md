# Where the audit layer sits

The citable one-page answer to "at which layer does Palimpsests audit,
and why there?" — for readers arriving from the specification, the
compliance mapping, or a standards document. The engine's own
architecture (the three-level model, the scheduler, memory) is
[ARCHITECTURE.md](../ARCHITECTURE.md); this page is about the **audit
boundary**.

## The stack, and the line through it

```
  agent frameworks / applications        (decisions, memory, policy)
  ────────────────────────────────────── ← agent-level audit lives here
  Palimpsests serving runtime (L1–L3)    (sessions, KV, tool loop,
    │  emits PALA-1 about itself          scheduling, guards)
  ────────────────────────────────────── ← THIS project's audit boundary
  inference engine / kernels             (llama.cpp, GPU kernels)
  ────────────────────────────────────── ← attestation / TEE line
  hardware                               (CPU/GPU, optionally TEE-class)
```

Every layer can and should account for itself; they answer different
questions. Agent-level trails record *what the agent decided*; execution
attestation records *what silicon ran*. The runtime layer in between is
the one component that **directly observes serving**: which model
weights were the active origin, which sessions existed and when they
ended, which persisted state entered or left the process, which tool
invocations were dispatched and what came back, which guard refused
what, and what was dropped under load. Nothing above it sees those
events first-hand; nothing below it has words for them.

## What the runtime's chain asserts — and refuses to assert

Palimpsests emits **PALA-1**
([the specification](specs/pala-1/PALA-1.md), frozen v1.0): an
append-only, hash-chained, verifier-independent binary format. Three
properties, each checkable by anyone from the spec alone:

1. **Integrity** — the records are the bytes the writer produced, in
   order (§7.1);
2. **Completeness** — nothing was silently truncated, against an anchor
   held outside the log (§7.2);
3. **Erasure without contradiction** — GDPR-class deletion by key
   destruction, on the record, with the chain intact (§4.4).

The refusals are load-bearing. The chain records *dispatches*, never
"decisions" — judgment is not faked at a layer that does not have it.
Bodies are metadata-only: prompts and completions do not enter the log.
And a consistent liar with root is out of scope by design — which is
exactly why the trust story is **graduated** rather than binary.

## Commodity hardware, below the TEE line

The assurance tiers (§6) grade what the *environment* adds: tier A
(process-level, any machine), tier B (device identity), B+ (hardware
counters), and the witness path (§7.3) for existence-at-a-time via
transparency logs or RFC 3161. TEE-grounded anchoring is a documented
composition ([ANCHOR-SOURCES.md](specs/pala-1/ANCHOR-SOURCES.md)), not
a floor: the format is deliberately useful on the edge and consumer
hardware where no enclave exists — the deployments regulation actually
meets.

## Verification is the product

Five independent implementations (three external and unaffiliated) have
reproduced the specification's expected results from the text and
vectors alone
([INDEPENDENT-VERIFICATION.md](specs/pala-1/INDEPENDENT-VERIFICATION.md)).
The regulatory reading of all of the above — EU AI Act Art. 12/14/19,
GDPR — is maintained separately in
[compliance/EU-AI-ACT-MAPPING.md](compliance/EU-AI-ACT-MAPPING.md),
mapping obligations to *checkable* properties rather than assurances.
