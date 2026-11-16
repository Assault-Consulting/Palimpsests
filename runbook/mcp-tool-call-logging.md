---
title: Log MCP tool calls with a one-file proxy
slug: mcp-tool-call-logging
group: record
order: 3
updated: 2026-11-16
description: Put a small proxy in front of any MCP server that speaks stdio, and every tools/call lands in a tamper-evident log on your machine, with whether it came back ok, as an error or not at all.
next: claude-code-hooks-not-working, log-claude-code-tool-calls
---

An MCP server gives an AI agent tools: files, a database, a browser. The agent's client starts the server as a local program and talks to it over standard input and output. A proxy placed on that line sees both halves of every tool call, what was asked and what came back. It reports each pair to Palimpsests, which writes it into a log that cannot be changed without the change showing.

The proxy is one Python file with no dependencies. It forwards every byte unchanged and never blocks a call.

## You need

- An MCP client that starts its servers as local commands, and the server you want to record.
- Python 3.11 or newer for the Palimpsests server. The proxy itself needs only Python 3.

## Steps

### 1. Start the server with a key

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
palimpsests serve
```

The second line is explained on the [runbook's first page](https://palimpsests.dev/runbook/).

### 2. Download the proxy

```bash
curl -O https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/v0.14.1/integrations/mcp/palimpsests_audit_mcp.py
```

### 3. Put it in front of your MCP server

Wherever the server's command is configured, put the proxy first and keep the original command after `--`:

```text
python3 /path/to/palimpsests_audit_mcp.py -- <server command> [args...]
```

In a client that takes its MCP configuration as JSON, a filesystem server becomes:

```json
{
  "mcpServers": {
    "fs": {
      "command": "python3",
      "args": ["/path/to/palimpsests_audit_mcp.py", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": {"PALIMPSESTS_SERVE_API_KEY": "choose-a-long-random-string"}
    }
  }
}
```

The proxy reads the key from `PALIMPSESTS_SERVE_API_KEY`, and the server's address from `PALIMPSESTS_SERVE_URL` when it is not `http://127.0.0.1:11435`. If your client cannot set variables per server, start the client from a shell where the key is set. On Windows the command is often `python` rather than `python3`, and `npx` and `uvx` work by name.

### 4. Check

```bash
palimpsests doctor mcp
```

Then make one tool call through your client, and look for it:

```bash
palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_CALL"'
```

## What is recorded, and what is not

- A `tools/call` request: the tool's name and a fingerprint of its arguments.
- Its answer, matched by request id: `ok` if the server returned a result, `error` if the result says `isError` or the server answered with an error, and `cancelled` if the server exited without answering.
- `ok` means the server answered. It does not mean the action took effect in the world.
- The arguments and results go to the Palimpsests server, which keeps only their fingerprints.
- Only servers that speak stdio. A server your client reaches over HTTP is outside this proxy.
- Everything else on the line, such as listing tools or notifications, passes through and is not recorded.

## Last checked

- Linux on 13 November 2026 and Windows 11 on 14 November 2026, palimpsests 0.14.0: one call and its result reached the log, in surface checks.
- Windows 11, palimpsests 0.13.0, 26 October 2026: a real Claude Code session through a filesystem server, eleven calls and eleven results. Ten were `ok` and one `error`, for a file that did not exist, each with the real tool name.
- [Every check, with its date and machine](https://github.com/Assault-Consulting/Palimpsests/blob/main/integrations/COMPATIBILITY.md)

## Reference

- [MCP proxy: README](https://github.com/Assault-Consulting/Palimpsests/blob/v0.14.1/integrations/mcp/README.md)
- [The real MCP session, recorded](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/independent-runs/traffic-0.14-r5-mcp/RUN-RECORD.md)
- [Recording agent tool calls](https://palimpsests.dev/notes/recording-agent-tool-calls/)
