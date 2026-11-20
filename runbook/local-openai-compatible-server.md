---
title: Run a local LLM behind an OpenAI-compatible API
slug: local-openai-compatible-server
group: run
order: 1
updated: 2026-11-16
description: Start an OpenAI-compatible server on your own machine in front of Ollama or llama.cpp, point any OpenAI client at it, and keep a tamper-evident record of the tool calls that pass through.
next: opencode-with-a-local-model, chat-longer-than-context-window
seo_title: Run a local LLM behind an OpenAI-compatible API
seo_description: Start an OpenAI-compatible server on your machine in front of Ollama or llama.cpp, point any OpenAI client at it, and keep a record of its tool calls.
---

Chat apps, editor plugins and agent frameworks mostly speak the OpenAI API. If the model runs on your own machine, you can offer them that same API locally. `palimpsests serve` does it with one command.

If you already run Ollama, note that Ollama has an OpenAI-compatible endpoint of its own. What this server adds is a key in front of the endpoint and a record: every tool call that crosses it is written to a log that cannot be changed without the change showing.

## You need

- Python 3.11 or newer.
- [Ollama](https://ollama.com) running on the same machine with a model pulled, for example `ollama pull llama3.1:8b`. Or the `llama-server` program from llama.cpp on your `PATH` and a GGUF model file named in `PALIMPSESTS_LLAMACPP_MODEL`.

## Steps

### 1. Install

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
```

The second line lets the server keep its own operations log unencrypted. The [runbook's first page](https://palimpsests.dev/runbook/) explains it, and how to keep that log encrypted instead.

### 2. Start the server with a key

```bash
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
palimpsests serve
```

It listens on `http://127.0.0.1:11435/v1` and asks every request for that key. It listens on this computer only, unless you give it `--host`. Without a key, any program on this computer can use it.

### 3. List your models

```bash
curl -H "Authorization: Bearer $PALIMPSESTS_SERVE_API_KEY" http://127.0.0.1:11435/v1/models
```

The names are the ones your engine knows. With Ollama, they are the names `ollama list` shows.

### 4. Call it from code

With the `openai` Python package:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:11435/v1", api_key="choose-a-long-random-string")
reply = client.chat.completions.create(
    model="llama3.1:8b",
    messages=[{"role": "user", "content": "Say hello in five words."}],
)
print(reply.choices[0].message.content)
```

Any other OpenAI-compatible client works the same way: give it the base URL and the key.

## Check that it works

Stop the server with Ctrl+C, then check its log:

```bash
palimpsests pala verify ~/.config/palimpsests/serve.pala
```

Stop it first because a file that is still being written can end in half an entry, which reads as damage. The check answers three questions. Consistency says whether the entries still hold together. Completeness stays open on purpose, and the command exits with code 2: whether the end of the log was cut off cannot be seen from inside the log. Closing that question takes an anchor: the latest fingerprint, kept somewhere the log's owner cannot rewrite. [Verify without reading](https://palimpsests.dev/verify-without-reading/) explains what the check proves.

## What is recorded, and what is not

- Operations, not content: the tool's name, a fingerprint of its arguments and of its result, and how it ended. Prompts and replies are not in this log.
- Only tool calls the model returns as structured calls. Some models write the call as plain text, and the client then runs it itself; the server cannot see that as a call. When tools were offered and no structured call came back, the server records exactly that, so the gap is visible.
- In our runs, `llama3.1:8b` in Ollama returned structured calls, while `qwen2.5-coder` (7B and 14B) in Ollama wrote its calls as text.
- The record shows the call the model asked for and the result your client sent back. It does not show that the tool did what it reported.
- Speed: it matches a tuned llama.cpp server. It is not faster.

## Last checked

- Windows 11, palimpsests 0.10.0, Ollama 0.33.2, August 2026: the server returned structured tool calls from `llama3.1:8b` and recorded them. [Run record](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/oleksandr/ws-e-opencode-smoke/WS-E-run-record.md).
- The commands on this page are those of palimpsests 0.14.1.

## Reference

- [Usage guide: the server, settings and environment variables](https://github.com/Assault-Consulting/Palimpsests/blob/v0.14.1/docs/USAGE.md)
- [Air-gapped and on-prem use](https://palimpsests.dev/air-gapped/)
