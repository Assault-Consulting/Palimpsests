---
title: Anatomy of a tamper-evident audit log: PALA-1, a PKCS#11 anchor and SCITT
slug: anatomy-of-a-tamper-evident-audit-log
date: 2026-10-23
description: The three layers of a Palimpsests audit log taken apart: the PALA-1 hash chain, the chain head on a PKCS#11 token and SCITT receipts. What each one proves alone, and what they prove together.
tags: tamper-evident, pkcs11, scitt
---

A tamper-evident audit log has to answer three separate questions. Was any record changed, removed or reordered? Is this the whole log, or was the end cut off? Did this history exist before a given time?

No single mechanism answers all three. Palimpsests uses a separate layer for each: the PALA-1 chain, a copy of the chain's head on a PKCS#11 token, and receipts from a SCITT transparency service. This note takes them apart one at a time and then puts them back together. The general idea behind each layer is in [tamper-evident audit logs: how they work](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/).

## Layer 1: the PALA-1 chain

[PALA-1](https://palimpsests.dev/pala-1/) is the record format, frozen at v1.0. Every record has a header and a body. The header holds a sequence number, the hash of the previous record and a SHA-256 digest of the body. The body holds the content and can be encrypted with AES-256-GCM.

A verifier walks the headers in order and checks each body against its digest. It never decrypts anything, so it never needs the key.

What it proves: nothing inside the file was altered, removed or moved, and if something was, which record is the first bad one.

What it can't prove: that the file is complete. A chain with its last records deleted is still a valid chain. It also says nothing about time, because whoever writes the log also controls its clock.

What it costs: one hash per record. The check is described on [verify without reading](https://palimpsests.dev/verify-without-reading/).

## Layer 2: the head on a PKCS#11 token

The head is the hash of the latest record, 32 bytes. Keep a copy of it somewhere else, compare the chain's end with that copy, and a cut-off end or a swapped file shows up. That copy is the anchor.

A file or the operating system's keychain can hold the anchor, and both are supported. Their weakness is that they sit inside the same machine as the writer, so whoever takes over the host takes over the anchor too. A PKCS#11 token or HSM moves the anchor onto separate hardware. Palimpsests stores the head there as a private data object, and the writer updates it as the chain grows. A verifier with the token's PIN reads it and checks the chain against it.

Version 0.12 tightened this after a problem we found ourselves. Reading the anchor now requires the PIN. If a second object appears under the same name, the read fails with an error instead of picking one. A planted decoy is treated as evidence, never filtered away.

What it proves: the chain ends where the token says it should, so records cut from the end or a wholesale replacement are detected unless the attacker can also rewrite the token.

What it can't prove: anything about time.

Limits worth stating: CI runs against SoftHSM, a software token, which proves the code path but not the hardware guarantee. That needs a real token or HSM. If the PIN sits in a config file next to the writer, the gain is smaller than it looks. A signature made by a key that never leaves the token is planned, not shipped. The design record is [ADR-0004](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/adr/0004-tier-b-pkcs11-anchor-and-signing.md).

## Layer 3: SCITT receipts

For each head you choose to publish, Palimpsests builds a small signed statement: a COSE_Sign1 that holds the head, the range of sequence numbers it covers and the format name. Since version 0.13 the statement can also carry a root computed over every earlier record. That part is still experimental until someone reproduces it independently. The statement goes to a SCITT transparency service, which adds it to its own append-only log and returns a receipt. No record content leaves the machine, only hashes.

What it proves: this head existed by the time the service recorded it, under the service's identity and clock. A receipted head also makes a strong anchor, because it's held by someone outside your organisation. With the roots in the statements and the consistency proofs added in 0.12, two registered heads can be linked without the chain itself. That shows the log only grew between them.

What it can't prove: anything about the content or its quality. The service saw a digest, nothing more, and its receipt is only as trustworthy as the service.

Where it stands: the statement construction has been reproduced byte for byte from the RFCs twice, and one registration with a verified receipt is on record. It was done against the reference implementation, whose receipt format predates the final RFC. A run against a hosted service with final-format receipts is next. The details are in [what a receipt proves and what it doesn't](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/INTEROP-SCITT.md).

## What the layers do together

Take someone who controls the host and holds the encryption key, and wants to change record 500.

Editing the record breaks the chain, so they have to rebuild every record after it. With the key, that's possible.

The rebuilt chain ends in a different head. The token still holds the old one, so the check fails unless they also replace the object on the token. That needs the PIN and an authenticated session, and with real hardware it can also need physical access or another person.

If a head covering record 500 was registered with a SCITT service before the change, the rebuilt chain can't produce that head again. The service's log and its receipt still show the original existed by a certain time. The forgery is detectable even when the attacker holds the host, the key and the token.

So with all three layers, the records someone could still rewrite unnoticed are only those written after the last registered head. How often you register decides how small that window is. A successful forgery stops being a matter of editing a file. It needs the host, the key, the token and the transparency service's log.

Two more things come from the combination. None of the layers needs the content, so the whole log can be checked by someone who isn't allowed to read it. And the first two layers work fully offline. The SCITT step needs a link out only when you register a head.

## Choosing a setup

Not every deployment needs all three:

- the chain alone is enough when you trust the storage and only need to catch edits;
- the chain with a file or keychain anchor also catches a cut-off end, as long as the host itself is trusted;
- the chain with a token moves the completeness check off the host;
- the chain with a token and SCITT adds proof of time and an anchor held outside your organisation.

## What none of the layers proves

Together they show that the record wasn't changed after it was written, that it's complete up to an anchor, and that it existed by a given time. They don't show that the recorded events were true, or that a tool a client reported actually ran. The threat model and the known limits are in [SECURITY.md](https://github.com/Assault-Consulting/Palimpsests/blob/main/SECURITY.md), and the offline side of anchors is on [air-gapped](https://palimpsests.dev/air-gapped/#anchors).
