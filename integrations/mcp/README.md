# Palimpsests audit wrapper for MCP servers

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

One file, standard library only. Put it in front of any MCP server that
speaks the stdio transport, and every `tools/call` the client makes lands
on a Palimpsests chain as a `TOOL_CALL` / `TOOL_RESULT` pair marked
`reported-by-client`, through the serve's ingestion surface.

## Why a proxy, and what it sees

The wrapper sits *between* the client and the server, so unlike a
model-side hook it observes both halves of every invocation: the request
the client sent and the response the server returned. That is a better
vantage than an inference runtime has — closer to the boundary where the
tool ran — and it is still a report, not the runtime's own observation, so
the records are marked accordingly.

| It observes | It reports |
|---|---|
| `tools/call` request | `TOOL_CALL` — tool name + digest of the arguments |
| the matching response (by JSON-RPC id), no `isError` | `TOOL_RESULT`, outcome `ok` |
| a response with `isError: true`, or a JSON-RPC error | `TOOL_RESULT`, outcome `error` |
| the server exits with the request unanswered | `TOOL_RESULT`, outcome `cancelled` |

`ok` means the server returned a result. Whether the action took effect
in the world is not something this proxy, or the chain, asserts.
Arguments and results are sent to the serve, which stores only digests.

## Install

Wherever the server command is configured, wrap it:

```
python3 /path/to/palimpsests_audit_mcp.py -- <server command> [args...]
```

For a client that takes an MCP configuration:

```json
{"mcpServers": {"fs": {
  "command": "python3",
  "args": ["/path/to/palimpsests_audit_mcp.py", "--",
           "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]}}}
```

| Variable | Meaning | Default |
|---|---|---|
| `PALIMPSESTS_SERVE_URL` | base URL of the serve | `http://127.0.0.1:11435` |
| `PALIMPSESTS_SERVE_API_KEY` | bearer key when the serve runs with `--api-key` | unset |
| `PALIMPSESTS_AUDIT_REPORT` | `0` disables reporting (the proxy still forwards) | enabled |

## For your coding agent — paste this

```text
Wrap an MCP server with the Palimpsests audit proxy.

1. Copy `integrations/mcp/palimpsests_audit_mcp.py` from the
   Assault-Consulting/Palimpsests repository somewhere on disk. It needs
   only Python 3; do not pip-install anything for it.
2. In the MCP client's server configuration, change the command to
   `python3 /path/to/palimpsests_audit_mcp.py -- <original command and args>`.
   Leave the original command and arguments exactly as they were after
   the `--`.
3. Start the serve: `pip install 'palimpsests[serve]' && palimpsests serve`
   (default http://127.0.0.1:11435). If it runs with --api-key, export
   PALIMPSESTS_SERVE_API_KEY with the same value in the client's
   environment for that server.
4. Make one tool call through the client, then:
   `palimpsests pala export serve.pala | grep -c '"kind_name":"TOOL_CALL"'`
   should be > 0 and those lines carry `"source":1`.

Rules: the proxy forwards every byte unchanged in both directions and
never blocks or alters a call; a failed report is logged to stderr and
the traffic continues. Reported records prove that a call was made and
what the server answered — not that the action took effect. Do not
describe this as "verified tool execution".
```

## Contract

- **Never blocks, never alters.** Forwarding and reporting are
  independent; the proxy exits with the server's exit code.
- **Framing** is newline-delimited JSON-RPC, the MCP stdio transport.
  Anything that is not a `tools/call` request or its response is
  forwarded and otherwise ignored.
- **Ids** may be strings or numbers; the serve keys calls by their JSON
  form.

## Tested

`tests/test_adapters.py` runs the proxy between a fake client and a fake
stdio server against a live serve: a normal call (forwarded unchanged,
`ok`), an `isError` result and a JSON-RPC error (`error`), a call the
server never answers (`cancelled`), and the disabled switch (forwarding
continues, nothing reported).
