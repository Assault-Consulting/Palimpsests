---
title: Keeping the audit log on your own machine when your agents use cloud models
slug: audit-log-for-agents-on-cloud-models
date: 2026-10-20
description: Agents that call hosted models can still keep their tool-call record locally. How Palimpsests records Claude Code, Codex, OpenTelemetry and LiteLLM tool calls, and what that record proves.
tags: ai-agents, integrations, audit-log
---

[Palimpsests](https://palimpsests.dev/) started as a runtime for models that run on your own hardware, often on networks with no internet at all. Many teams work differently. Their agents run on their own servers or laptops, while the model behind them is a hosted one reached through an API. The prompts leave the building. The question is whether the record of what the agent did has to leave with them.

It doesn't. The way we put it: the audit record stays on your machine, even when the model doesn't.

## Why keep a separate record

The model provider keeps its own logs, and they may well be good. They're still the provider's logs. You can't verify them independently and you don't decide how long they're kept. They also record what the model said, not what your agent then did with your files and systems.

The EU AI Act asks deployers of high-risk systems to keep the automatically generated logs that are under their control. For an agent, the part that's fully under your control is its tool loop: which tools it called, with what input, and what came back. That's what these integrations record.

## What gets recorded

A local Palimpsests server receives each tool call and its result from the client and writes them into a PALA-1 chain. Arguments and results are stored as SHA-256 digests of a canonical form, never as content. Each pair is marked as reported by the client, so it can't be confused with a call the runtime made itself.

Since version 0.13 each result also states what its recorder could see. Where a client reports failures, the result is recorded as ok or error. Where it can't tell a failed call from a successful one, the result is recorded as unobserved. An ok means a result came back. It never means the action succeeded.

## Coding agents: Claude Code and Codex

Claude Code can send its hooks over HTTP. You add three entries to its settings file, pointing PreToolUse, PostToolUse and PostToolUseFailure at the local server, and there's nothing to install. Claude Code reports failures, so its results are recorded as ok or error.

Codex only runs command hooks, so a small forwarder script passes each event to the server. Codex has no failure hook, which means its results are recorded as unobserved. One thing to watch: Codex skips an untrusted hook without any warning, and the tools then run with nothing recorded. The README explains how to check for it.

Both adapters were written against what the hooks actually send, measured on Claude Code 2.1.288 and Codex CLI 0.160.0. The details are in the [agent hooks README](https://github.com/Assault-Consulting/Palimpsests/tree/main/integrations/agent-hooks).

## Frameworks with OpenTelemetry

Many agent frameworks already emit OpenTelemetry traces, with one span per tool execution under the GenAI conventions. Point the trace exporter at the server and those spans become recorded tool calls:

```
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:11435/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
```

A span with an error status is recorded as an error. To get digests of the arguments and results, turn on content capture in the instrumentation. Without it the pair is recorded with no digests, which makes a weaker record. This path was tested against a real framework's export from pydantic-ai 2.57.0. Setup is in the [OpenTelemetry README](https://github.com/Assault-Consulting/Palimpsests/tree/main/integrations/otel).

## Gateways and tool servers

If your agents reach hosted models through LiteLLM, its callback reports every structured tool loop that passes through it. If they use MCP servers over standard input and output, a small proxy in front of each server records both the request and the response of every tool call. Both are covered in [recording the tool calls your agent already makes](https://palimpsests.dev/notes/recording-agent-tool-calls/).

## Limits

A reported record shows what the client said happened and that nobody changed the report later. It doesn't prove the tool ran, and it can't see a tool the client never reports. Hook interfaces change between client versions, so we probe them regularly and note the version each claim was checked on. The record is only as trustworthy as the chain it sits in, and what makes that chain trustworthy is covered in [what makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/).

The full list of integrations is on [integrations](https://palimpsests.dev/integrations/).
