---
title: Protecting an audit log from being rewritten from scratch
slug: protecting-an-audit-log-from-being-rewritten
date: 2026-11-05
description: A hash chain catches an edited record but not a log rebuilt from the first record. What closes that gap, from which record on, and what stays open.
tags: audit-log, tamper-evident, security, anchors
---

A hash-chained audit log catches the obvious attack. Change one record and every record after it stops matching, and the check points at the first broken link. That makes it easy to forget the attack the chain can't see on its own: throwing the log away and writing a new one.

This note is about that attack. It explains why the chain alone doesn't catch it, what does, from which record on, and what remains possible however the log is set up.

## Why the chain alone can't see it

Each record holds the hash of the one before it. That proves the records are in order and unchanged *relative to each other*. It doesn't prove they are the records that were written.

Rebuilding a chain needs no secret. Whoever can write the file can start from the first record, change whatever they like, and recompute every hash. The new chain is internally perfect. Every link verifies, because every link was made for it. A verifier that only reads the file has nothing to compare it with, so it reports the chain as consistent. That is true, and it isn't enough.

The same goes for two quieter versions of the attack: cutting records off the end, and restoring an old copy of the file over a newer one. Both leave a chain whose links all hold.

## What closes it: a head kept somewhere else

The hash of the latest record, the head, is 32 bytes. Copy it to a place the writer of the log can't change, and every later check can compare the chain's end with that copy. In PALA-1 that copy is called the anchor, and comparing with it is the completeness check.

```
palimpsests pala verify audit.pala --anchor-file head.txt
```

A rebuilt chain ends in a head the anchor has never seen. The verifier says so in words, not only in its exit code:

```
completeness: FAILED — the anchored head names no record in this chain —
the log was replaced, rolled back, or truncated
```

A chain that simply grew past the anchor gets a different sentence, because the anchored head is still in it:

```
completeness: FAILED — chain extends 2 record(s) beyond the anchored head —
an unanchored tail, not a replacement
```

Both exit with code 1. The difference matters to whoever investigates. The first means the history you hold isn't the history that was anchored. The second usually means the writer stopped between writing records and copying out the head, for example after a crash.

Without an anchor the check can't answer the question at all. It exits with code 2 and says that completeness wasn't checked. A scheduled check that treats code 2 as a pass doesn't detect a rewrite.

## The window that stays open

An anchor protects the records up to the head it holds. Records written after the last copy are protected by nothing yet, and someone who can write the file can still change them. To the check, that looks like an unanchored tail, the same as after a crash.

So how often the head is copied out sets the size of that window. Copying it after every record shrinks the window to the record being written, and costs a write elsewhere each time. Copying it hourly leaves up to an hour of records exposed. Either choice is fine if it is stated. It isn't fine to leave it unstated.

## Where the copy lives decides who it stops

An anchor stops anyone who can rewrite the log but can't also rewrite the anchor. That is the whole question when choosing where to keep it.

- **A file or the operating system's keychain on the same machine** stops a careless process and a user without full rights. It doesn't stop someone with administrator access, who can change both.
- **A hardware token** (PKCS#11) puts the head where reading it needs a PIN, and where a second object planted under the same name makes the read fail instead of being picked. To get past it, the attacker has to defeat the token too.
- **A transparency service** (SCITT) takes the head outside your organisation. It countersigns a statement over the head with its own key and clock. After that, nobody on your side, administrators included, can make the old head go away. The service's record says it existed, and when.

The [anatomy note](https://palimpsests.dev/notes/anatomy-of-a-tamper-evident-audit-log/) walks through these three layers together.

## Old records you delete on purpose

Logs aren't kept forever. Deleting expired segments under a retention policy removes the start of the chain, and without more information that looks exactly like a rewrite: the first remaining record isn't the first record ever written.

PALA-1 handles this with a record that declares the cut. When a writer starts a new segment, the segment's first record states which head it continues from, under what retention period, and the root of everything before it. A verifier then reports a declared continuation and checks it against the segments manifest, instead of reporting an unexplained missing start. A whole set of segments can be checked at once. The result keeps two answers apart: whether everything present is consistent, and whether anything is missing. Retention makes a set incomplete. It never makes it inconsistent.

## Showing the history only grew

An anchor answers "is this the chain I anchored?". A second question comes up as soon as you publish heads regularly: does today's chain extend last quarter's?

Since construction v3 a published statement carries the root of the whole chain up to its head. Two such statements and a short consistency proof show that the later chain contains the earlier one unchanged, without handing anyone the records. Someone who kept last quarter's statement can check this quarter's in seconds.

## What none of this proves

- That the records were true when they were written. The chain proves what was recorded, not that it was right.
- Anything about records written after the last head left the machine.
- Anything against an attacker who controls both the log and every copy of its head. The point of a token or a transparency service is to make that set of copies impossible for one party to hold.

## Further reading

- [Tamper-evident audit logs: how they work and how to build one](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/)
- [Anatomy of a tamper-evident audit log](https://palimpsests.dev/notes/anatomy-of-a-tamper-evident-audit-log/)
- [The PALA-1 format](https://palimpsests.dev/pala-1/)
- [Verifying a log without reading it](https://palimpsests.dev/verify-without-reading/)
