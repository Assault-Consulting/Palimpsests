# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Agent tool hooks in the Claude schema → reported tool pairs.

The event shapes below are the ones measured on Claude Code 2.1.288
(integrations/agent-hooks/PROBE-RESULTS.md), not invented ones.
"""
from __future__ import annotations

import logging
import pytest
from palimpsests.audit.pala_writer import (
    OUTCOME_ERROR,
    OUTCOME_OK,
    SOURCE_REPORTED_BY_CLIENT,
    canonical_tool_args_digest,
)
from palimpsests.server.agent_hooks import HookIngest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402


def _pre(call_id="toolu_1", tool="Read", tool_input=None):
    return {
        "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool,
        "tool_use_id": call_id, "tool_input": tool_input or {"file_path": "/tmp/NOTES.md"},
        "cwd": "/tmp", "permission_mode": "default",
    }


def _post(call_id="toolu_1", tool="Read", response=None):
    return dict(_pre(call_id, tool), hook_event_name="PostToolUse",
                tool_response=response if response is not None else {"type": "text", "file": {}},
                duration_ms=3)


def _fail(call_id="toolu_2", tool="Bash", error="cat: nope: No such file or directory"):
    p = dict(_pre(call_id, tool, {"command": "cat nope"}), hook_event_name="PostToolUseFailure",
             error=error, is_interrupt=False, duration_ms=2)
    return p


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
    return audit, pending, HookIngest(audit, pending)


# --- the pairing logic ------------------------------------------------------ #

def test_pre_then_post_is_one_reported_pair_with_canonical_digests():
    audit, pending, h = _ingest()
    assert h.handle(_pre()) == (200, {})
    assert h.handle(_post()) == (200, {})
    assert audit.calls == [("Read", canonical_tool_args_digest({"file_path": "/tmp/NOTES.md"}),
                            SOURCE_REPORTED_BY_CLIENT)]
    seq, call_hash, outcome, digest, source = audit.results[0]
    assert (seq, call_hash) == (1, b"\x01" * 32)  # bound to its call
    assert outcome == OUTCOME_OK and source == SOURCE_REPORTED_BY_CLIENT
    assert digest == canonical_tool_args_digest({"type": "text", "file": {}})
    assert pending == {}


def test_a_failure_closes_the_pair_as_error():
    audit, _, h = _ingest()
    h.handle(_pre("toolu_2", "Bash", {"command": "cat nope"}))
    h.handle(_fail())
    _, _, outcome, digest, _ = audit.results[0]
    assert outcome == OUTCOME_ERROR
    assert digest == canonical_tool_args_digest("cat: nope: No such file or directory")


def test_a_result_without_its_call_still_lands_as_a_pair():
    audit, pending, h = _ingest()
    h.handle(_post("toolu_9"))
    assert len(audit.calls) == 1 and len(audit.results) == 1
    assert audit.results[0][0] == 1  # bound to the call recorded just before it
    assert pending == {}


def test_redelivered_events_do_not_duplicate_records():
    audit, _, h = _ingest()
    for event in (_pre(), _pre(), _post(), _post()):
        assert h.handle(event) == (200, {})
    assert len(audit.calls) == 1 and len(audit.results) == 1


def test_non_tool_hook_events_are_accepted_and_not_recorded():
    audit, _, h = _ingest()
    for name in ("UserPromptSubmit", "SessionStart", "Stop", "PreCompact"):
        assert h.handle({"hook_event_name": name, "session_id": "s"}) == (200, {})
    assert audit.calls == [] and audit.results == []


@pytest.mark.parametrize("bad", [[], "x", {"hook_event_name": "PreToolUse"},
                                 {"hook_event_name": "PostToolUse", "tool_name": "Read"}])
def test_malformed_tool_events_are_refused_without_recording(bad):
    audit, _, h = _ingest()
    status, body = h.handle(bad)
    assert status == 400 and "error" in body
    assert audit.calls == [] and audit.results == []


def test_a_hook_id_cannot_collide_with_another_paths_pending_call():
    audit, pending, h = _ingest()
    pending["toolu_1"] = (99, b"\x99" * 32, 0)  # an /v1/pala/events call with the same id
    h.handle(_pre())
    h.handle(_post())
    assert pending == {"toolu_1": (99, b"\x99" * 32, 0)}  # untouched
    assert audit.results[0][0] == 1


# --- through the serve ------------------------------------------------------ #

def _serve(tmp_path, api_key=None):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.providers.native.audit import NativeAudit

    audit = NativeAudit(PalaWriter(tmp_path / "s.pala"))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: ["m"],
                     audit=audit, api_key=api_key)
    return app, audit


def test_end_to_end_the_chain_carries_the_pair_marked_reported(tmp_path):
    from palimpsests.audit.reader import AuditReader

    app, audit = _serve(tmp_path)
    client = TestClient(app)
    for event in (_pre(), _post(), _pre("toolu_2", "Bash", {"command": "cat nope"}), _fail()):
        r = client.post("/v1/pala/hooks/claude", json=event)
        assert r.status_code == 200 and r.json() == {}
    audit.writer.close()
    with AuditReader.open(tmp_path / "s.pala") as reader:
        tools = [r for r in reader.records() if r.kind_name in ("TOOL_CALL", "TOOL_RESULT")]
        ver = reader.verify()
    assert [r.kind_name for r in tools] == ["TOOL_CALL", "TOOL_RESULT", "TOOL_CALL", "TOOL_RESULT"]
    assert {r.source_name for r in tools} == {"reported-by-client"}
    assert ver.chain.chain_ok
    assert not [i for i in ver.advisory.items if i.code.startswith("reference_")]


def test_the_hook_route_requires_the_bearer_and_names_an_empty_one(tmp_path, caplog):
    app, _ = _serve(tmp_path, api_key="sk-right")
    client = TestClient(app)
    ok = client.post("/v1/pala/hooks/claude", json=_pre(),
                     headers={"Authorization": "Bearer sk-right"})
    assert ok.status_code == 200
    wrong = client.post("/v1/pala/hooks/claude", json=_pre("t3"),
                        headers={"Authorization": "Bearer sk-wrong"})
    assert wrong.status_code == 401
    with caplog.at_level(logging.WARNING, logger="palimpsests.serve"):
        empty = client.post("/v1/pala/hooks/claude", json=_pre("t4"),
                            headers={"Authorization": "Bearer"})
    assert empty.status_code == 401
    assert "allowedEnvVars" in caplog.text


def test_a_wrong_bearer_is_not_mistaken_for_an_empty_one(tmp_path, caplog):
    app, _ = _serve(tmp_path, api_key="sk-right")
    with caplog.at_level(logging.WARNING, logger="palimpsests.serve"):
        TestClient(app).post("/v1/pala/hooks/claude", json=_pre(),
                             headers={"Authorization": "Bearer sk-wrong"})
    assert "allowedEnvVars" not in caplog.text


def test_no_audit_chain_is_a_503(tmp_path):
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: ["m"])
    assert TestClient(app).post("/v1/pala/hooks/claude", json=_pre()).status_code == 503


def test_concurrent_redelivery_still_records_each_call_once():
    # Route handlers run on a thread pool and an agent can run tools in
    # parallel: the same Pre and Post arriving at once from several
    # threads must still give one call and one result per tool_use_id.
    import threading

    audit, _, h = _ingest()
    ids = [f"toolu_{i}" for i in range(40)]
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        for i in ids:
            h.handle(_pre(i))
            h.handle(_post(i))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(audit.calls) == len(ids)
    assert len(audit.results) == len(ids)
