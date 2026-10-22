---
title: What makes an audit log tamper-evident
slug: what-makes-an-audit-log-tamper-evident
date: 2026-10-20
description: How hash chains, anchors and witnesses make changes to a log detectable, what each one proves, and the questions to ask before trusting a tamper-evident claim.
tags: audit-log, tamper-evident, security
---

"Tamper-evident" appears on a lot of logging products. It should mean something specific: if someone changes the log, a person who didn't make the change can detect it later. It doesn't mean the change is impossible. That would be tamper-proof, and no log stored on a computer someone controls can promise that.

Detection relies on several separate mechanisms. Each one answers its own question, and a log can have one without the others.

## The hash chain

Each record stores the hash of the record before it. Change a record and its hash changes, so the next record's link stops matching. Remove a record from the middle and the link to the next one breaks. Reorder records and both the links and the sequence numbers go wrong.

A chain answers the question "was anything inside this file altered?" Anyone with the file and the specification can check it, and the check needs no key. In PALA-1 the record bodies can even stay encrypted during the check, because each header carries a digest of its body. That part is explained in [how to check an AI log without reading it](https://palimpsests.dev/notes/checking-an-ai-log-without-reading-it/).

## The anchor

A chain has one blind spot. If the last records are deleted, what remains is still a valid chain, only shorter. The same is true when a whole file is swapped for another consistent chain.

To catch that, the latest hash has to be kept somewhere else, such as a separate file, the operating system's keychain or a hardware token. That copy is the anchor. Checking the chain against it answers a second question: "is this the whole log?" An anchor only helps if whoever could rewrite the log can't rewrite the anchor as well. That's why a hardware token is stronger than a file on the same disk.

## The witness

The third question is about time. Did this history exist before a certain moment? Nothing inside the log can prove it, because whoever controls the log also controls its clock. Someone outside has to sign a statement.

In Palimpsests that witness can be a SCITT transparency service. Palimpsests registers one signed statement per published head. The statement holds a hash and no record content. The receipt shows that the head existed by the time it was registered, and since a head commits to every record before it, so did those records.

## Proofs that travel

Two more tools help when you can't hand over the whole log. An inclusion proof shows that a particular record belongs to a tree whose root you already trust, using a handful of hashes. A consistency proof shows that an older head is a prefix of a newer one, so the log only ever grew. Both use the same construction as Certificate Transparency (RFC 6962 and RFC 9162).

## Deletion that explains itself

Logs can't grow forever. Retention rules say how long records stay, and after that they're deleted. In a hash chain, deleting the oldest records leaves a gap at the start, and a gap normally looks like tampering.

Since version 0.13, Palimpsests opens each new segment with a continuation record. It names the previous segment's last hash and the retention period that applied, and it commits to every earlier record. When old segments are removed under that policy, the rest of the log still explains where its beginning went. The standards background for this is in [AI logging standards in draft](https://palimpsests.dev/notes/ai-logging-standards-24970-18229/).

## Other approaches

Hash chains aren't the only way to do this. Signed syslog (RFC 5848) signs batches of messages. The systemd journal can seal its files with forward-secure keys, so an attacker who takes over a machine can't rewrite what was sealed before. Some storage systems simply refuse to change data once it's written. Each of these puts the trust somewhere different: in a signing key, a sealing key or a storage vendor. For any of them it's worth asking who you have to trust, and whether that's the same party you're worried about.

## Questions to ask before trusting the claim

- Can someone outside the team check the log with a published specification, without your software?
- Does the check need the decryption key, or can it run without reading the content?
- What does the check report when it has no anchor? It should say completeness wasn't checked.
- Where is the anchor kept, and who can change it?
- What happens to the log when old records are deleted?
- What isn't covered? A tamper-evident log shows the record wasn't changed. It doesn't show the recorded events were true.

The format behind all of this is [PALA-1](https://palimpsests.dev/pala-1/). The reasoning behind its design is in [three design principles for verifiable audit logs](https://palimpsests.dev/notes/pala-1-three-design-principles/).
