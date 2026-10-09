---
title: PALA-1: three design principles for verifiable audit logs
slug: pala-1-three-design-principles
date: 2026-10-09
description: Verification without disclosure, integrity through a hash chain, and checking a log with no remote service: the ideas behind the PALA-1 format and where each one stops.
tags: pala-1, audit-log, design
---

An audit trail should stay verifiable when the system is offline, when the hardware is limited, and when the records hold information an auditor must not read. [PALA-1](https://palimpsests.dev/pala-1/), the Portable Append-only Log for Audit, is designed around those conditions.

AI systems now often run where keeping a record isn't enough. A team has to be able to show that the record hasn't changed and that its order is intact. It also has to let an outside party check this without handing over the data inside.

Air-gapped deployments, embedded systems and strict data-residency rules make that harder. A remote verification service may be unavailable by design. Signing every event costs computation that a small device may not have to spare. Giving an auditor full access to the record can expose information that should stay private.

PALA-1 answers with three principles: verification without disclosure, integrity through chaining, and verification with no external dependency.

## 1. Verification must not require disclosure

An audit shouldn't force an organization to reveal everything it records.

Traditional reviews often tie access to evidence to access to the underlying information. For an AI system that can mean exposing prompts, responses, personal data, internal instructions or operational details, just to show that a log hasn't been modified.

PALA-1 keeps these apart. Each record has a header and a body, and the body can be encrypted. The header carries a SHA-256 digest of the body. Verification checks the headers and compares each body with its digest, without decrypting anything. The auditor gets the evidence needed to validate the chain and nothing more. The check is described step by step on [verify without reading](https://palimpsests.dev/verify-without-reading/).

This matters in healthcare, finance, industrial systems and anywhere else data minimization is a requirement rather than a preference. The right to verify a record shouldn't come bundled with the right to read it.

A successful check doesn't prove that every recorded event was true, though. It establishes properties of the evidence in front of the verifier. Whether the runtime behaved honestly before or during recording is a separate question.

## 2. Integrity should come from the chain

A pile of individually stored records doesn't add up to a trustworthy history. If someone can edit, delete, reorder or replace records without detection, the file may still look plausible while no longer matching what happened.

PALA-1 links records into an append-only hash chain. Each record carries the hash of the one before it, so a verifier checks the sequence instead of trusting how individual entries look:

- if a record is modified, its hash no longer matches the link stored in the next record;
- if a record in the middle is removed, the link to the next one breaks and the sequence numbers show a gap;
- if records are reordered, the links and the sequence numbers no longer line up.

Verification is portable too. The specification and its [test vectors](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/test-vectors.json) are public domain, and anyone can reproduce the checks without our software. Five independent implementations have done exactly that, and the [verification runs](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/INDEPENDENT-VERIFICATION.md) are on record.

One limit needs stating. A valid chain doesn't prove its last record is the last one that ever existed. If someone presents an earlier prefix that is still internally valid, only an anchor kept outside the log can reveal it. Integrity and completeness are related, but they are different properties.

## 3. Verification must work without a remote witness

Many security designs assume another service is around to confirm, sign or register events. That isn't true everywhere. An air-gapped computer may have no network route at all. An embedded controller may have a tight power budget. A deployment policy may forbid outbound connections even where a network exists.

PALA-1 is built for those conditions. Its chain can be checked offline, and the integrity check needs no key material. Records are linked by hashing rather than by an asymmetric signature on every record, which keeps routine verification cheap and needs no remote service just to confirm internal consistency.

External witnessing still has a place. If an organization needs evidence that a particular chain head existed by a particular time, it can register that head with a transparency service. Since version 0.11, Palimpsests can send one signed statement per published head to a SCITT service, and no record content leaves the device. [What a receipt proves and what it doesn't](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/INTEROP-SCITT.md) is written up separately. The anchor can also stay local, in a file or on a hardware token, as described on [air-gapped](https://palimpsests.dev/air-gapped/#anchors).

So offline verification is the core capability, and external witnessing is an extra layer of trust on top of it.

## What this means in practice

A deployment can keep its records locally, let an independent verifier check their integrity without giving that verifier the content, and run routine checks without depending on a live external service.

PALA-1 defines the record format and the verification procedure. [Palimpsests](https://palimpsests.dev/) is the reference implementation, built for local-first language-model inference where requests and tool calls need an auditable record and the data must not leave the machine.

The format is described in an Internet-Draft, [draft-sparysh-pala-audit](https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/). It's an individual submission with Informational status, a work in progress and not an approved IETF standard. The [specification](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/PALA-1.md) in the repository is the normative text.

None of this replaces a threat model, access controls, encryption, retention policies or other deployment-specific measures. The limits of the current implementation are listed in its [security policy and threat model](https://github.com/Assault-Consulting/Palimpsests/blob/main/SECURITY.md). A consistent log is evidence about a sequence of records. It isn't a guarantee about the system that produced them.

## Check it yourself

The most useful way to judge an audit format is to run its verification and try to break it. The [verification kit](https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/specs/pala-1/verification-kit) has the inputs and a run-record template. The quickest local try is:

```
pip install palimpsests
palimpsests demo
palimpsests pala verify palimpsests-demo.pala
```

Then change one byte in the middle of the file and run the check again.

For teams that run AI systems locally, on restricted networks or on modest hardware, the useful test is whether their logs stay independently verifiable under the conditions the system actually works in. The source code and all verification material are on [GitHub](https://github.com/Assault-Consulting/Palimpsests).
