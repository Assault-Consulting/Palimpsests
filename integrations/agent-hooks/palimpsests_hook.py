#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Command hook that forwards an agent's tool hook events to a Palimpsests serve.

For clients that run hooks only as commands — Codex — and for anyone who
prefers a command hook to an HTTP one in Claude Code. One file, standard
library only. The agent runs it with the hook event as JSON on stdin; it
POSTs the event, unchanged, to the serve's hook route, which records the
call and its result on the chain as ``reported-by-client``.

Usage in a hook configuration::

    python3 /ABS/PATH/palimpsests_hook.py --client codex

``--client`` picks the route: ``codex`` → ``/v1/pala/hooks/codex``,
``claude`` → ``/v1/pala/hooks/claude``. The route decides what a result
may claim: Codex sends no failure event, so its results are recorded as
``unobserved``; Claude Code's are ``ok`` or ``error``.

Configuration is by environment, the same variables the serve reads:

    PALIMPSESTS_SERVE_URL      default http://127.0.0.1:11435
    PALIMPSESTS_SERVE_API_KEY  bearer key when the serve runs with --api-key
    PALIMPSESTS_AUDIT_REPORT   "0" disables forwarding

Contract: **never block, never alter.** It always exits 0 and writes
nothing to stdout, so the agent sees no decision and the tool proceeds;
a failure to report is one line on stderr. It never reads or prints the
event's content beyond sending it to the serve, which stores digests
only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:11435"
ROUTES = {"codex": "/v1/pala/hooks/codex", "claude": "/v1/pala/hooks/claude"}
TIMEOUT_S = 3


def _client(argv: list[str]) -> str:
    if "--client" in argv:
        i = argv.index("--client")
        if i + 1 < len(argv):
            return argv[i + 1]
    return "codex"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if os.environ.get("PALIMPSESTS_AUDIT_REPORT") == "0":
        return 0
    client = _client(argv)
    route = ROUTES.get(client)
    if route is None:
        print(f"palimpsests-hook: unknown --client {client!r}", file=sys.stderr)
        return 0
    try:
        body = sys.stdin.buffer.read()
        json.loads(body)  # forward only what is JSON; never the serve's problem to guess
    except (OSError, ValueError) as e:
        print(f"palimpsests-hook: event is not JSON ({e})", file=sys.stderr)
        return 0
    url = (os.environ.get("PALIMPSESTS_SERVE_URL") or DEFAULT_URL).rstrip("/") + route
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("PALIMPSESTS_SERVE_API_KEY", "")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        print(f"palimpsests-hook: the serve refused the event ({e.code})", file=sys.stderr)
    except (urllib.error.URLError, OSError) as e:
        print(f"palimpsests-hook: report failed ({e})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
