---
title: Recording the tool calls your agent already makes
slug: recording-agent-tool-calls
date: 2026-10-04
description: Adapters for LiteLLM, MCP servers and OpenCode that put tool calls on a tamper-evident log, and what such a record proves.
tags: ai-agents, litellm, mcp
---

When an agent calls a tool, it does something real. It might read a file or send a message on someone's behalf. Those calls are what people look at first when something goes wrong, and they're often the worst-recorded part of the system.

Most agents already send their tool calls through something you run. That might be a gateway like LiteLLM, an MCP server or a coding agent like OpenCode. Version 0.12 of Palimpsests added small adapters for these. Each one passes the tool calls it sees to a local Palimpsests server, which writes them into a hash-chained log.

## Setting up the server

```
pip install 'palimpsests[serve]'
palimpsests serve
```

By default the server listens on 127.0.0.1:11435. It stores hashes of the arguments and results, not the content itself. If you start it with an API key, give the adapters the same key in the PALIMPSESTS_SERVE_API_KEY variable.

## LiteLLM

The LiteLLM adapter is one Python file, registered as a callback. It sees the tool calls the model asks for and the results that come back into the conversation:

```
import litellm
from palimpsests_audit import PalimpsestsAudit
litellm.callbacks = [PalimpsestsAudit()]
```

It never sees the tool itself run. A result marked ok only means it went back to the model.

## MCP servers

For MCP servers that talk over standard input and output, the adapter is a small proxy. You put it in front of the server command in your client's configuration. Sitting in the middle, it sees both the request and the response of every tool call. It passes every byte through unchanged and never blocks a call.

## OpenCode

OpenCode gets a plugin: a single JavaScript file you copy into .opencode/plugins/ for one project, or ~/.config/opencode/plugins/ for all of them. It reports the tools OpenCode actually runs. That includes calls the model wrote as plain text, which a server on its own wouldn't recognise.

## What these records prove

Records from an adapter are marked as reported by the client. They show what the client said happened and when, and that nobody changed the report afterwards. They don't prove the tool actually ran. The server keeps them apart from the calls it handled itself, so anyone reading the log can tell the two kinds apart.

## Where things stand

The LiteLLM and MCP adapters have been tested against a live server with made-up tool calls. Neither has been run on real traffic yet. For OpenCode 1.18.31, one reported call from a real session has reached the log. It was a failed file read, and it was recorded correctly. We haven't yet seen a successful result arrive the same way.

Client hook interfaces change between versions, so each adapter's README says which version its behaviour was checked on.

Setup details and limits for all three are on [integrations](https://palimpsests.dev/integrations/). How to check the resulting log without the key is on [verify without reading](https://palimpsests.dev/verify-without-reading/).

*Written with AI assistance and checked against the project repository.*
