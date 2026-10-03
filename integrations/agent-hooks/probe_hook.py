#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Probe — what does an agent's tool hook actually deliver, on this version?

A no-op command hook for clients that follow the PreToolUse / PostToolUse
convention (Claude Code, Codex). It reads the hook's JSON from stdin,
appends one line describing it to a JSONL file, prints nothing, and
always exits 0 — it never blocks a tool and never changes one.

It records **shape, not content**: every field's name and JSON type,
and the values of four fields that are identifiers rather than data —
``hook_event_name``, ``tool_name``, ``tool_use_id`` (or ``tool_call_id``),
``session_id``. Tool inputs, tool outputs, prompts and paths are
described by type and size only. The output can therefore be pasted
into a run record without redaction.

Why it exists: the integration for these clients is written against
what the hook really sends, not against documentation. Sources already
disagree on whether a successful call's result arrives as
``tool_response`` or ``tool_output``, and one client sends it as a
string for some tools and an object for others. Ten minutes with this
probe answers that for the version installed today.

    export PALIMPSESTS_PROBE_LOG=~/agent-hook-probe.jsonl
    # register this script as a PreToolUse, PostToolUse and
    # PostToolUseFailure command hook — see README.md beside it
    # use the agent for one turn that reads a file and runs a command
    cat ~/agent-hook-probe.jsonl

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

IDENTIFIERS = ("hook_event_name", "tool_name", "tool_use_id", "tool_call_id", "session_id")


def _shape(value, depth: int = 0):
    """JSON type of a value; objects and arrays one level deep, never content."""
    if isinstance(value, dict):
        if depth >= 1:
            return {"type": "object", "keys": len(value)}
        return {"type": "object", "fields": {k: _shape(v, depth + 1) for k, v in value.items()}}
    if isinstance(value, list):
        return {"type": "array", "items": len(value)}
    if isinstance(value, str):
        return {"type": "string", "chars": len(value)}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, (int, float)):
        return {"type": "number"}
    if value is None:
        return {"type": "null"}
    return {"type": type(value).__name__}


def main() -> int:
    log = Path(
        os.environ.get("PALIMPSESTS_PROBE_LOG")
        or Path.home() / "agent-hook-probe.jsonl"
    )
    line: dict = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else None
        if isinstance(payload, dict):
            line["ids"] = {k: payload[k] for k in IDENTIFIERS if k in payload}
            line["fields"] = {k: _shape(v) for k, v in payload.items()}
        else:
            line["unexpected"] = _shape(payload)
        line["argv"] = sys.argv[1:]  # e.g. a --client tag from the hook config
    except Exception as exc:  # a probe that fails must still not block the tool
        line["probe_error"] = repr(exc)[:200]
    try:
        with log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
