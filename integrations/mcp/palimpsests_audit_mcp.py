#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Palimpsests audit wrapper for MCP servers (stdio transport).

One file, standard library only. Put it in front of any MCP server that
speaks the stdio transport and every ``tools/call`` the client makes lands
on a Palimpsests chain as a ``TOOL_CALL`` / ``TOOL_RESULT`` pair carrying
``EVT_SOURCE = reported-by-client`` (inference profile r5), through the
serve's ingestion surface ``POST /v1/pala/events``.

Usage — wherever you configured the server command, wrap it::

    palimpsests_audit_mcp.py -- npx -y @modelcontextprotocol/server-filesystem /data

e.g. in a client's MCP configuration::

    {"mcpServers": {"fs": {
        "command": "python3",
        "args": ["/path/to/palimpsests_audit_mcp.py", "--",
                 "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]}}}

Configuration by environment, the same variables the serve, the OpenCode
plugin and the LiteLLM callback read:

    PALIMPSESTS_SERVE_URL      default http://127.0.0.1:11435
    PALIMPSESTS_SERVE_API_KEY  bearer key when the serve runs with --api-key
    PALIMPSESTS_AUDIT_REPORT   "0" disables reporting (the proxy still forwards)

What it sees, and what it reports
---------------------------------
The proxy sits *between* the client and the server, so unlike a model-side
hook it observes both halves of every tool invocation: the request the
client sent and the response the server returned. That is a better
vantage than an inference runtime has — closer to the boundary where the
tool ran — and it is still a report, not the runtime's own observation,
so the records are marked accordingly.

* ``tools/call`` request → ``TOOL_CALL`` with the tool name and the
  digest of its arguments (the arguments go to the serve, which stores
  only the digest);
* the matching response (by JSON-RPC id) → ``TOOL_RESULT``: ``ok`` when
  the server answered a result without ``isError``, ``error`` when it
  answered ``isError: true`` or a JSON-RPC error;
* a request the server never answers before it exits → ``cancelled``.

``ok`` means the server returned a result; whether the action took effect
in the world is not something this proxy, or the chain, can assert
(profile open issue 5).

Contract
--------
* Never blocks, never alters. Every byte is forwarded unchanged in both
  directions; reporting happens beside the stream, and a failed report
  is logged to stderr while the traffic continues.
* Framing: newline-delimited JSON-RPC, the MCP stdio transport. Lines
  that are not JSON, or JSON that is not a request/response the proxy
  understands, are forwarded and otherwise ignored.
* The proxy exits with the server's exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:11435"


def _post(events: list[dict]) -> None:
    if not events or os.environ.get("PALIMPSESTS_AUDIT_REPORT") == "0":
        return
    url = (os.environ.get("PALIMPSESTS_SERVE_URL") or DEFAULT_URL).rstrip("/")
    key = os.environ.get("PALIMPSESTS_SERVE_API_KEY", "")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(
        f"{url}/v1/pala/events",
        data=json.dumps({"events": events}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for r in data.get("results", []):
            if r.get("error"):
                print(
                    f"palimpsests-audit-mcp: serve rejected {r.get('id')}: {r['error']}",
                    file=sys.stderr,
                    flush=True,
                )
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"palimpsests-audit-mcp: report failed: {e}", file=sys.stderr, flush=True)


class Proxy:
    """One wrapped server: forwards stdio both ways, reports tools/call pairs."""

    def __init__(self, command: list[str]) -> None:
        self.command = command
        self.pending: dict[str, str] = {}  # JSON-RPC id -> tool name
        self.lock = threading.Lock()

    # ── observation ─────────────────────────────────────────────────────
    def on_client_line(self, line: bytes) -> None:
        msg = _parse(line)
        if not isinstance(msg, dict) or msg.get("method") != "tools/call":
            return
        rid = msg.get("id")
        params = msg.get("params") or {}
        name = params.get("name")
        if rid is None or not isinstance(name, str) or not name:
            return  # a notification, or malformed: forwarded, not reported
        key = _idkey(rid)
        with self.lock:
            if key in self.pending:
                return
            self.pending[key] = name
        args = params.get("arguments")
        _post(
            [
                {
                    "type": "tool_call",
                    "id": key,
                    "name": name,
                    "arguments": args if isinstance(args, dict) else {},
                }
            ]
        )

    def on_server_line(self, line: bytes) -> None:
        msg = _parse(line)
        if not isinstance(msg, dict) or "id" not in msg or "method" in msg:
            return  # notifications and requests from the server are not results
        key = _idkey(msg.get("id"))
        with self.lock:
            name = self.pending.pop(key, None)
        if name is None:
            return
        if "error" in msg:
            outcome, content = "error", msg["error"]
        else:
            result = msg.get("result")
            is_error = isinstance(result, dict) and bool(result.get("isError"))
            outcome, content = ("error" if is_error else "ok"), result
        _post(
            [
                {
                    "type": "tool_result",
                    "call_id": key,
                    "outcome": outcome,
                    "content": json.dumps(
                        content, sort_keys=True, separators=(",", ":"), default=str
                    ),
                }
            ]
        )

    def on_server_exit(self) -> None:
        with self.lock:
            orphans = list(self.pending)
            self.pending.clear()
        if orphans:
            _post(
                [
                    {"type": "tool_result", "call_id": k, "outcome": "cancelled", "content": ""}
                    for k in orphans
                ]
            )

    # ── the pump ────────────────────────────────────────────────────────
    def run(self) -> int:
        proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr
        )
        assert proc.stdin is not None and proc.stdout is not None
        client_in = sys.stdin.buffer
        client_out = sys.stdout.buffer

        def pump_client_to_server() -> None:
            try:
                for line in iter(client_in.readline, b""):
                    self.on_client_line(line)
                    proc.stdin.write(line)
                    proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        t = threading.Thread(target=pump_client_to_server, daemon=True)
        t.start()
        try:
            for line in iter(proc.stdout.readline, b""):
                client_out.write(line)
                client_out.flush()
                self.on_server_line(line)
        except (BrokenPipeError, OSError):
            pass
        rc = proc.wait()
        self.on_server_exit()
        return rc


def _parse(line: bytes):
    try:
        return json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _idkey(rid) -> str:
    # JSON-RPC ids may be strings or numbers; the serve keys calls by string.
    return json.dumps(rid, separators=(",", ":"))


def main(argv: list[str]) -> int:
    if "--" in argv:
        command = argv[argv.index("--") + 1 :]
    else:
        command = argv[1:]
    if not command:
        print("usage: palimpsests_audit_mcp.py -- <server command> [args...]", file=sys.stderr)
        return 2
    return Proxy(command).run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
