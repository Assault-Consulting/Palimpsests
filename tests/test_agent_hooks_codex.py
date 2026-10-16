# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Codex hooks: the route, the outcome rule, and the command-hook forwarder.

Codex sends the Claude hook schema, but only as command hooks and with no
failure event: a failed call arrives as a ``PostToolUse`` carrying the
command's output as a string (PROBE-RESULTS.md). So its results are
recorded ``unobserved`` (profile r6), never ``ok``, and the forwarder —
a command hook — carries the event to the serve.
"""
from __future__ import annotations

import json
import os
import pytest
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
from palimpsests.audit.pala_writer import (  # noqa: E402
    OUTCOME_OK,
    OUTCOME_UNOBSERVED,
    SOURCE_REPORTED_BY_CLIENT,
    canonical_tool_args_digest,
)
from palimpsests.server.agent_hooks import HookIngest  # noqa: E402

FORWARDER = Path(__file__).resolve().parent.parent / "integrations/agent-hooks/palimpsests_hook.py"


def _pre(call_id="call_1", command="cat hello.txt"):
    return {
        "session_id": "s", "turn_id": "t", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_use_id": call_id, "tool_input": {"command": command},
        "cwd": "/tmp", "model": "m", "permission_mode": "default",
    }


def _post(call_id="call_1", output="hello\n", command="cat hello.txt"):
    return dict(_pre(call_id, command), hook_event_name="PostToolUse", tool_response=output)


class _FakeAudit:
    def __init__(self):
        self.calls, self.results = [], []

    def tool_called(self, name, args_digest, span, *, source=0):
        self.calls.append((name, args_digest, source))
        return len(self.calls), bytes([len(self.calls)]) * 32

    def tool_result(self, seq, call_hash, outcome, digest, span, *, source=0):
        self.results.append((seq, call_hash, outcome, digest, source))


def _ingest():
    audit, pending = _FakeAudit(), {}
    return audit, pending, HookIngest(audit, pending, client="codex")


# ── the outcome rule ───────────────────────────────────────────────────────


def test_a_codex_result_is_unobserved_success_and_failure_alike():
    audit, _, hooks = _ingest()
    for cid, out in (("call_1", "hello\n"), ("call_2", "cat: x: No such file or directory\n")):
        assert hooks.handle(_pre(cid))[0] == 200
        assert hooks.handle(_post(cid, out))[0] == 200
    assert [r[2] for r in audit.results] == [OUTCOME_UNOBSERVED, OUTCOME_UNOBSERVED]
    assert all(r[4] == SOURCE_REPORTED_BY_CLIENT for r in audit.results)
    # the string result is digested by the same canonical rule as Claude's objects
    assert audit.results[0][3] == canonical_tool_args_digest("hello\n")
    assert audit.calls[0][1] == canonical_tool_args_digest({"command": "cat hello.txt"})


def test_a_result_without_its_call_still_lands_as_a_pair():
    audit, _, hooks = _ingest()
    assert hooks.handle(_post("call_9"))[0] == 200
    assert len(audit.calls) == 1 and audit.results[0][2] == OUTCOME_UNOBSERVED


def test_a_failure_event_codex_never_sends_is_refused_before_any_write():
    audit, pending, hooks = _ingest()
    event = dict(_pre("call_3"), hook_event_name="PostToolUseFailure", error="boom")
    status, _ = hooks.handle(event)
    assert status == 400
    assert audit.calls == [] and audit.results == [] and pending == {}


def test_codex_and_claude_ids_never_collide_on_one_serve():
    audit, pending = _FakeAudit(), {}
    claude = HookIngest(audit, pending)
    codex = HookIngest(audit, pending, client="codex")
    claude.handle(dict(_pre("same_id"), tool_name="Read"))
    codex.handle(_pre("same_id"))
    assert len(pending) == 2  # two open calls, not one overwritten
    claude.handle(dict(_post("same_id"), tool_name="Read"))
    codex.handle(_post("same_id"))
    assert sorted(r[2] for r in audit.results) == [OUTCOME_OK, OUTCOME_UNOBSERVED]


def test_an_unknown_client_is_a_programming_error():
    with pytest.raises(ValueError):
        HookIngest(_FakeAudit(), {}, client="nope")


# ── the forwarder, end to end ──────────────────────────────────────────────


class _Serve:
    def __init__(self, tmp_path):
        uvicorn = pytest.importorskip("uvicorn")
        from palimpsests.audit.pala_writer import PalaWriter
        from palimpsests.providers.native.audit import NativeAudit
        from palimpsests.server.openai_api import create_app

        self.log = tmp_path / "hooks.pala"
        self.audit = NativeAudit(PalaWriter(self.log))
        app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                         audit=self.audit, api_key="k-test")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.url = f"http://127.0.0.1:{s.getsockname()[1]}"
            port = s.getsockname()[1]
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)
        self.audit.writer.close()


def _forward(event, *, url, key="k-test", client="codex", extra_env=None, raw=None):
    env = dict(os.environ, PALIMPSESTS_SERVE_URL=url, PALIMPSESTS_SERVE_API_KEY=key)
    env.pop("PALIMPSESTS_AUDIT_REPORT", None)
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, str(FORWARDER), "--client", client],
        input=raw if raw is not None else json.dumps(event).encode(),
        capture_output=True, env=env, timeout=20,
    )


def test_the_forwarder_carries_a_codex_pair_onto_the_chain(tmp_path):
    from palimpsests.audit.reader import AuditReader

    with _Serve(tmp_path) as serve:
        for event in (_pre("call_7"), _post("call_7", "cat: nope: No such file or directory\n")):
            proc = _forward(event, url=serve.url)
            assert proc.returncode == 0 and proc.stdout == b""  # no decision, ever
            assert proc.stderr == b""
    with AuditReader.open(serve.log) as r:
        recs = [d for d in r.records() if d.kind_name in ("TOOL_CALL", "TOOL_RESULT")]
        assert r.verify().chain.chain_ok
    assert [d.kind_name for d in recs] == ["TOOL_CALL", "TOOL_RESULT"]
    assert recs[1].outcome_name == "unobserved"
    assert {d.source_name for d in recs} == {"reported-by-client"}


def test_the_forwarder_serves_claude_command_hooks_too(tmp_path):
    from palimpsests.audit.reader import AuditReader

    with _Serve(tmp_path) as serve:
        _forward(dict(_pre("toolu_1"), tool_name="Read"), url=serve.url, client="claude")
        _forward(dict(_post("toolu_1"), tool_name="Read"), url=serve.url, client="claude")
    with AuditReader.open(serve.log) as r:
        outcomes = [d.outcome_name for d in r.records() if d.kind_name == "TOOL_RESULT"]
    assert outcomes == ["ok"]


def test_the_forwarder_never_blocks_when_the_serve_is_down():
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    t = time.monotonic()
    proc = _forward(_pre(), url=dead)
    assert proc.returncode == 0 and proc.stdout == b""
    assert b"report failed" in proc.stderr
    assert time.monotonic() - t < 10


def test_a_wrong_key_is_reported_on_stderr_and_still_does_not_block(tmp_path):
    with _Serve(tmp_path) as serve:
        proc = _forward(_pre(), url=serve.url, key="wrong")
    assert proc.returncode == 0 and proc.stdout == b""
    assert b"refused the event (401)" in proc.stderr


def test_disabled_and_malformed_input_are_quiet_no_ops():
    off = _forward(_pre(), url="http://127.0.0.1:9", extra_env={"PALIMPSESTS_AUDIT_REPORT": "0"})
    assert off.returncode == 0 and off.stdout == b"" and off.stderr == b""
    bad = _forward(None, url="http://127.0.0.1:9", raw=b"not json")
    assert bad.returncode == 0 and bad.stdout == b"" and b"not JSON" in bad.stderr
