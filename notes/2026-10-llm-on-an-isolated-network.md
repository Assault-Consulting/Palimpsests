---
title: Running a language model on an isolated network, with a log you can prove
slug: llm-on-an-isolated-network
date: 2026-10-04
description: What changes when an LLM runs with no network at all: installing it, timestamps, anchors and checking the log offline.
tags: air-gapped, llm, audit-log
---

Some networks are cut off from the internet on purpose. Hospitals and defence sites are the usual examples. If a language model has to work inside one, it can't call a hosted API, and the services that normally back up a log aren't there either. You lose cloud logging, public time servers and any online way to timestamp a record.

Palimpsests was built for exactly this. The model, its working state and the log all stay on the machine that holds the data. Here's what that looks like in practice.

## Getting the software in

The machine has no internet, so the packages travel on a drive. On a connected computer, download them with pip. Then install from that folder on the isolated machine:

```
pip download palimpsests -d ./wheels
pip install --no-index --find-links ./wheels palimpsests
```

Releases are signed and ship with a list of their dependencies (an SBOM). You can check what you're carrying in before it crosses over.

## Time you can't fully trust

Isolated machines drift. Some have no reliable clock at all, and the log doesn't pretend otherwise. Each record carries a time trust level: UNKNOWN, UNSYNCED, HW_RTC or NTP_SYNCED. A record marked UNKNOWN contains no wall-clock time at all.

The order of events doesn't depend on the clock. It comes from sequence numbers in the chain, so even if every timestamp were wrong you could still see what happened before what.

## Keeping the anchor

A hash chain shows that nothing inside the log was changed. To also notice records removed from the end, you keep a copy of the latest hash somewhere else. Offline, that can be a file outside the log. Since version 0.11 it can also be a PKCS#11 hardware token, which the host can read but can't quietly overwrite.

If your rules ever allow a single link outside, the latest hash can also be sent to a SCITT transparency service as a signed statement. Only the hash leaves the machine.

## Checking without the network

Verification works on the same machine or any other one, with no connection. It doesn't need the decryption key, because all it does is compare stored hashes:

```
palimpsests pala verify serve.pala --anchor <latest-hash>
```

Verification was measured on a test chain of one million records. On an Intel Core Ultra 9 machine running Windows 11, verifying with version 0.11 needed 4.77 GB of memory. Version 0.12 brought that down to 0.57 GB. On an integrated Intel Arc GPU, the engine's tool loop runs as fast as a hand-tuned llama-server, without a separate server process.

There's no measurement on a discrete GPU yet. The log implementation also hasn't had an independent penetration test.

More detail, including what we don't claim, is on [air-gapped](https://palimpsests.dev/air-gapped/). The project itself is at [palimpsests.dev](https://palimpsests.dev/).

*Written with AI assistance and checked against the project repository.*
