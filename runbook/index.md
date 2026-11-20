---
title: Runbook: self-hosted LLM setup and AI agent logging, step by step
updated: 2026-11-16
description: Short recipes you can copy for running language models on your own machine and recording what AI agents do, each with what it needs, how to check it worked and what it does not do.
seo_title: Runbook: self-hosted LLM setup and AI agent logging
seo_description: Short recipes for running language models on your own machine and recording what AI agents do: what each needs, how to check it, what it does not do.
---

Palimpsests is one open-source Python package that does three kinds of jobs. It runs language models on your own computer, through Ollama or llama.cpp. It writes down what an AI agent did, which tools it called and what came back, in a log that cannot be changed without the change showing. And it lets anyone check that log later, without having to trust you or us.

This runbook is a set of short recipes. Each one does one job in a few commands. Each says what you need first, how to check that it worked, and what it does not do.

## Before you start

- Python 3.11 or newer, and `pip`.
- Recipes that run a model need [Ollama](https://ollama.com) with a model pulled, or the `llama-server` program from llama.cpp. Recipes that only record an agent need no local model at all.
- Most recipes start the Palimpsests server with `palimpsests serve`. Next to the log of tool calls, it keeps a log of its own operations, and that one is encrypted by default. For a first try, let it be stored unencrypted. It stays hash-chained either way.

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
```

In Windows PowerShell, the second line is `$env:PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT = "1"`. To keep that log encrypted instead, install `'palimpsests[serve,keyring,encryption]'` on a computer with a system keychain, and leave the variable unset.

## The log in one paragraph

Each entry carries a fingerprint of the entry before it. Change an entry, remove one or swap two, and the fingerprints stop matching from that point on. Checking them needs no key and never opens what the entries hold. One change the log cannot show by itself is a cut at the very end. For that, you keep a copy of the latest fingerprint somewhere else, called an anchor. More in [what makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/) and [verify without reading](https://palimpsests.dev/verify-without-reading/).

## What it is not

- Not a compliance product. It gives you a record. What your rules require of that record is still yours to decide.
- Not faster than a well-tuned llama.cpp server. On speed, measured, it matches one.
- Not a copy of your content. The log holds operations and fingerprints of data, not prompts, replies or files.
