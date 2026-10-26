# MCP proxy on real traffic — run 5, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Eleven calls and eleven results from a ten-prompt Claude Code session
driving a filesystem MCP server through the audit proxy, none without a
result, every one `reported-by-client`. Ten resolved `ok` and one
`error` — the server's `isError` on a file that does not exist. This is
the only run in the series whose chain carries **real tool names** —
`list_directory`, `read_text_file`, `write_file`, `read_multiple_files`,
`list_allowed_directories` — because the proxy sits at the MCP boundary
rather than behind an agent's shell tool.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `C:\runs\venv`) |
| Palimpsests | `palimpsests 0.13.0 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | Claude Code 2.1.310 |
| MCP server | `@modelcontextprotocol/server-filesystem` over `npx`, scoped to `C:\runs\scratch`, 14 tools |
| Model | Claude Fable 5.1 (the client's own model; not configured by this run) |
| Adapter file SHA-256 | `palimpsests_audit_mcp.py` — `add077ee26ad1493cb965b61a6f1eeb8518b6fe82a78048e6ebf894a29a673a0` |
| Serve | `palimpsests-serve --api-key ***REDACTED***`, config dir `C:\runs\r5`, fresh for this run |

## What was done

1. The HTTP hooks from run 1 were removed from
   `%USERPROFILE%\.claude\settings.json` before this run, so no tool call
   could be recorded twice — once by a hook and once by the proxy.
2. The serve was started on a fresh `C:\runs\r5` (200 with the bearer,
   401 without).
3. **The documented Windows defect was reproduced deliberately**, before
   the session, by starting the proxy with a bare command name:

       python palimpsests_audit_mcp.py -- npx -y @modelcontextprotocol/server-filesystem C:\runs\scratch

   It failed in `_winapi.CreateProcess` with
   `FileNotFoundError: [WinError 2] The system cannot find the file specified`.
   See *Findings*.
4. The server was registered with the full path that `where.exe npx`
   reports:

       claude mcp add fs -e PALIMPSESTS_SERVE_API_KEY=***REDACTED*** --
         C:/runs/venv/Scripts/python.exe C:/runs/palimpsests_audit_mcp.py --
         "C:/Program Files/nodejs/npx.cmd" -y @modelcontextprotocol/server-filesystem C:/runs/scratch

   `claude mcp list` reported `fs … ✔ Connected`.
5. Claude Code was started in `C:\runs\scratch`; `/mcp` showed `fs`
   connected with 14 tools.
6. Ten prompts, one at a time, each naming the server so the client would
   not answer with its own tools:

   1. `Using the fs MCP server, list the files.`
   2. `Using the fs MCP server, read notes.txt.`
   3. `Using the fs MCP server, read missing.txt.`
   4. `Using the fs MCP server, show me the contents of dates.txt.`
   5. `Using the fs MCP server, create a file r5.txt containing the word five.`
   6. `Using the fs MCP server, read r5.txt back.`
   7. `Using the fs MCP server, list the files again and tell me how many there are.`
   8. `Using the fs MCP server, search for the word "hello" in the files.`
   9. `Using the fs MCP server, read notes.txt and dates.txt and compare them.`
   10. `Using the fs MCP server, delete r5.txt and list the files to confirm.`

7. The session was exited, the serve stopped, the chain read, and the
   server deregistered with `claude mcp remove fs`.

No step was retried.

## Result

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 5982 bytes, SHA-256 `63374eb2b1f87e7e52137c972ed23186aad5a3f32f332b06497b603e35f25f59`
- verify: chain_ok **True**, 24 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `list_allowed_directories` | `ok` | `reported-by-client` |  |
| 3 | `list_directory` | `ok` | `reported-by-client` |  |
| 6 | `read_text_file` | `ok` | `reported-by-client` |  |
| 8 | `read_text_file` | `error` | `reported-by-client` |  |
| 10 | `read_text_file` | `ok` | `reported-by-client` |  |
| 12 | `write_file` | `ok` | `reported-by-client` |  |
| 14 | `read_text_file` | `ok` | `reported-by-client` |  |
| 16 | `list_directory` | `ok` | `reported-by-client` |  |
| 18 | `read_multiple_files` | `ok` | `reported-by-client` |  |
| 20 | `read_multiple_files` | `ok` | `reported-by-client` |  |
| 22 | `list_directory` | `ok` | `reported-by-client` |  |

- calls: **11**, results: **11**, calls without a result: **0**
- outcomes: `error` × 1, `ok` × 10

`palimpsests pala verify C:\runs\r5\serve.pala` exit code: **2**

Serve access log: 22 posts to `/v1/pala/events` — eleven calls and eleven
results — **all accepted**, no refusals.

## What did not land, and why

- **No search tool and no delete tool appear.** Prompts 8 and 10 asked
  for a search and a deletion. The chain shows `read_multiple_files` and
  `list_directory` where they were, so the model answered both by reading
  and listing instead of calling a dedicated tool. Whether the filesystem
  server exposes such tools among its fourteen, and whether the deletion
  took effect at all, is **not established by this run** — the chain
  records what crossed the MCP boundary, and no delete call did.
- **Nothing else was lost.** Every `tools/call` that crossed the proxy
  produced a pair, and every pair resolved.
- **Eleven pairs from ten prompts**, with a `list_allowed_directories`
  call the prompts did not ask for: the client issued it on its own,
  presumably on first contact with the server. It is on the chain because
  it crossed the boundary — which is the proxy's point.

## Limits of this run

One machine, one client, one MCP server, one session. The proxy was in
front of a filesystem server only; servers with other transports or
long-running calls are untested here. No call was abandoned, so the
proxy's `cancelled`-on-exit path is not exercised. The model was the
client's own and was not controlled for. `ok` here means the server
returned a result without `isError` — not that the action took effect in
the world, which this proxy cannot assert and does not.

## Findings

**The proxy cannot start a server by bare command name on Windows.**
Reproduced above: `npx` resolves to `npx.cmd`, and `subprocess` without
`shell=True` cannot execute a `.cmd` by bare name —
`FileNotFoundError: [WinError 2]` from `_winapi.CreateProcess`. The
documented workaround, a full path to `npx.cmd`, works and was used.
This is the same defect that broke the OpenCode probe in the surface
checker: two call sites, one cause. A fix in both would be to resolve the
command with `shutil.which()` and invoke the resolved path.

**The serve start line does not work**, as recorded in run 1:
`palimpsests serve --api-key …` exits with `No such option: --api-key`,
and moving the key into `PALIMPSESTS_SERVE_API_KEY` starts an endpoint
that does not require it. This run used
`palimpsests-serve --api-key ***REDACTED***`, measured to answer 401
without the bearer.

---

This run was carried out with AI assistance.
