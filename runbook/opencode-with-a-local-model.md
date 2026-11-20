---
title: Use a local model in OpenCode
slug: opencode-with-a-local-model
group: run
order: 3
updated: 2026-11-16
description: Point OpenCode at a model on your own machine through Palimpsests' OpenAI-compatible server, with the configuration printed for you, and know which of its tool calls reach the record.
next: local-openai-compatible-server, mcp-tool-call-logging
seo_title: Use a local model in OpenCode
seo_description: Point OpenCode at a model on your own machine through Palimpsests' OpenAI-compatible server, and know which of its tool calls reach the record.
---

OpenCode is a coding agent for the terminal. It can use any model behind an OpenAI-compatible API, including one on your own machine. This recipe puts the Palimpsests server between OpenCode and Ollama, so the model stays local and the server keeps a record.

Read "What reaches the record" below before you rely on that record. With small local models, OpenCode's tool calls often do not cross the server as calls.

## You need

- OpenCode installed.
- [Ollama](https://ollama.com) with a model pulled, for example `ollama pull llama3.1:8b`.
- Python 3.11 or newer.

## Steps

### 1. Install and start the server

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
palimpsests serve
```

The second line is explained on the [runbook's first page](https://palimpsests.dev/runbook/).

### 2. Print the configuration for OpenCode

In a second terminal:

```bash
palimpsests-serve --print-opencode-config
```

It prints a provider block for `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "palimpsests": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Palimpsests (local, audited)",
      "options": {
        "baseURL": "http://127.0.0.1:11435/v1"
      },
      "models": {
        "MODEL_ID": {
          "name": "MODEL_ID"
        }
      }
    }
  }
}
```

### 3. Add it to OpenCode's configuration

Put the `provider` block into your `opencode.json`, and replace both `MODEL_ID` with your model's name, for example `llama3.1:8b`.

OpenCode also needs a credentials entry for this provider, even when the server has no key. The printed text names the file, `~/.local/share/opencode/auth.json`. Add:

```json
{"palimpsests": {"type": "api", "key": "choose-a-long-random-string"}}
```

Use the same key the server was started with.

### 4. Pick the model

Start OpenCode and choose the Palimpsests model from its list of models.

## What reaches the record

- When the model returns a structured tool call, the call crosses the server and is recorded: the tool's name, fingerprints of its arguments and its result, and how it ended.
- When the model writes the call as text, OpenCode reads that text and runs the tool itself. The server never sees a call. It records only that tools were offered and no structured call came back. OpenCode shows both kinds the same way on screen.
- Measured with OpenCode 1.18.25 and four local models in Ollama: under OpenCode's own system prompt, about 9,500 characters long, none of the four returned structured calls, so no tool call reached the record. With a short prompt, `llama3.1:8b` returned structured calls for the same tools.
- To record the tools OpenCode runs either way, use the [OpenCode plugin](https://github.com/Assault-Consulting/Palimpsests/blob/v0.14.1/integrations/opencode/README.md). It reports them from inside OpenCode, marked as reported by the client.

## Last checked

- Windows 11, palimpsests 0.10.0, OpenCode 1.18.25, Ollama 0.33.2, August 2026. [Run record](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/oleksandr/ws-e-opencode-smoke/WS-E-run-record.md).
- The printed configuration on this page is that of palimpsests 0.14.1.

## Reference

- [OpenCode plugin, with its status on each OpenCode version](https://github.com/Assault-Consulting/Palimpsests/blob/v0.14.1/integrations/opencode/README.md)
- [All integrations and their limits](https://palimpsests.dev/integrations/)
