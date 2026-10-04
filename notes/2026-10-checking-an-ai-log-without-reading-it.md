---
title: How to check an AI log without reading it
slug: checking-an-ai-log-without-reading-it
date: 2026-10-04
description: Why the person who checks an AI system's log often shouldn't read it, and how a hash-chained format makes that possible.
tags: audit-log, security, verification
---

Prompts sent to a language model often contain things people would rather keep private, such as names or medical details. When someone later needs to confirm that the log of those prompts is intact, they usually don't need to see any of it. Most of the time they shouldn't.

The common way to protect a log is to encrypt it. Then, to check it, you hand over the key. It works, but it gives the person doing the check far more than they asked for.

## Two permissions instead of one

In PALA-1, the format Palimpsests writes, every record has a header and a body. The body holds the content and can be encrypted. The header holds a SHA-256 hash of the body and the hash of the previous record.

To check the log you only need the headers. You go through them in order and confirm two things for each record: that its body still matches the hash in its header, and that it points to the record before it. If anything was changed, removed or moved, one of those links breaks. The bodies are never decrypted.

So reading the log and checking it become separate permissions. You can give one without giving the other.

## What a check can tell you

From the file alone, a check answers one question. Was anything inside it altered? If so, it names the first record where the chain breaks.

It can't tell you whether records were removed from the end. A shortened chain is still a valid chain. To notice that, the latest hash has to be kept somewhere outside the log, for example in a file you control or on a hardware token. That stored copy is called an anchor. With it, the check can also confirm that the log is complete.

Proving that the log existed by a certain date needs something else again: a signed statement from an outside witness.

A good verifier keeps these answers apart. If it was given no anchor, it should say completeness wasn't checked. A green result in that situation invites people to believe something nobody verified.

## Trying it

The Palimpsests package has a demo that writes a small log and checks it:

```
pip install palimpsests
palimpsests demo
palimpsests pala verify palimpsests-demo.pala
```

Without an anchor, the last command reports that completeness wasn't checked and exits with code 2. Pass the right hash with `--anchor` and it exits with 0. Change one byte in the middle of the file and it exits with 1, naming the records where the chain broke.

## Where this stops

Someone who holds both the encryption key and write access to the anchor can rebuild the chain and the anchor together. That's why the format is called tamper-evident and not tamper-proof, and why it helps to keep the anchor off the machine that writes the log.

The format, its specification and its independent implementations are described on [PALA-1](https://palimpsests.dev/pala-1/). A longer explanation of the check is on [verify without reading](https://palimpsests.dev/verify-without-reading/).

*Written with AI assistance and checked against the project repository and a real run.*
