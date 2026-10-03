# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The agent-hook probe never blocks a tool and never records content."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROBE = Path(__file__).resolve().parents[1] / "integrations" / "agent-hooks" / "probe_hook.py"


def _run(stdin: str, log: Path, *args: str) -> int:
    return subprocess.run(
        [sys.executable, str(PROBE), *args],
        input=stdin, text=True, capture_output=True,
        # inherit the environment: Windows Python will not start without
        # SYSTEMROOT, and the CI matrix includes Windows
        env=dict(os.environ, PALIMPSESTS_PROBE_LOG=str(log)),
        check=False,
    ).returncode


def test_records_shape_and_identifiers_never_content(tmp_path):
    log = tmp_path / "p.jsonl"
    secret = "TOP-SECRET-CONTENT"
    post = {
        "session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Read",
        "tool_use_id": "toolu_01", "tool_input": {"file_path": f"/home/u/{secret}"},
        "tool_response": {"content": secret},
    }
    assert _run(json.dumps(post), log, "--client", "claude-code") == 0
    text = log.read_text()
    assert secret not in text and "/home/u" not in text
    line = json.loads(text)
    assert line["ids"] == {
        "hook_event_name": "PostToolUse", "session_id": "s1",
        "tool_name": "Read", "tool_use_id": "toolu_01",
    }
    assert line["fields"]["tool_response"]["type"] == "object"
    assert line["argv"] == ["--client", "claude-code"]


def test_a_string_result_is_told_apart_from_an_object(tmp_path):
    # the D4 question: one client sends a result as a string for some tools
    log = tmp_path / "p.jsonl"
    post = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_use_id": "c1", "tool_response": "stdout text"}
    assert _run(json.dumps(post), log) == 0
    assert json.loads(log.read_text())["fields"]["tool_response"] == {"type": "string", "chars": 11}


def test_garbage_input_still_exits_zero(tmp_path):
    log = tmp_path / "p.jsonl"
    assert _run("not json", log) == 0
    assert "probe_error" in json.loads(log.read_text())


def test_an_unwritable_log_still_exits_zero(tmp_path):
    # a probe that fails must never block the tool it is observing
    assert _run('{"hook_event_name": "PreToolUse"}', tmp_path / "missing-dir" / "p.jsonl") == 0
