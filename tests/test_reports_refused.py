# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Inference profile r9: reports that were refused are on the chain.

A client turned away before its report is read — no key, an empty one, the
wrong one — sees nothing wrong, and neither did the chain: the calls that
were not reported are simply absent. The refusals were counted, in the
serving process's memory, and went with it. Measured on real clients: every
report of a run refused for a missing key, and 4 of 26 hook posts refused
for an empty one.
"""
from __future__ import annotations

import io
import json
import pytest
from palimpsests.audit.export import export_jsonl
from palimpsests.audit.pala import vectors
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import (
    ADVISORY_CODES,
    KIND_REPORTS_REFUSED,
    AuditReader,
    ReportsRefusedView,
    decode_reports_refused,
)
from palimpsests.audit.report import build_report

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

KEY = "sk-refused"
AUTH = {"Authorization": f"Bearer {KEY}"}
EVENTS, CLAUDE, CODEX, TRACES = ("/v1/pala/events", "/v1/pala/hooks/claude",
                                 "/v1/pala/hooks/codex", "/v1/traces")
CALL = {"events": [{"type": "tool_call", "id": "c", "name": "t"}]}


def _refused(path):
    with AuditReader.open(path) as reader:
        views = [decode_reports_refused(d) for d in reader.records()]
        ver = reader.verify()
        assert reader.is_consistent()
        advisories = [i for i in ver.advisory.items if i.code == "reports_refused"]
    return [v for v in views if v is not None], advisories


@pytest.fixture
def served(tmp_path):
    log = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit,
                     api_key=KEY)
    return TestClient(app), app, audit, log


def _stop(app, audit):
    app.state.cancel_pending()  # what `palimpsests serve` calls as it stops
    audit.writer.close()


# -- the writer and the reader -------------------------------------------------

def test_the_record_carries_the_route_and_the_three_counts(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        rh = w.reports_refused(CLAUDE, empty=4, wrong=1, accepted=22)
    assert KIND_REPORTS_REFUSED == 14
    with AuditReader.open(log) as reader:
        rec = reader.record_at(2)
        assert rec.record_hash == rh and rec.kind_name == "REPORTS_REFUSED"
        assert rec.header.key_id == 0 and rec.detail is None
        view = decode_reports_refused(rec)
        assert decode_reports_refused(reader.record_at(0)) is None
    assert view == ReportsRefusedView(seq=2, route=CLAUDE, refused_empty=4,
                                      refused_wrong=1, accepted=22, rejected=0)


@pytest.mark.parametrize("kwargs", [
    {"route": "", "empty": 1, "wrong": 0},
    {"route": "x" * 65, "empty": 1, "wrong": 0},
    {"route": EVENTS, "empty": 0, "wrong": 0},  # nothing was refused
    {"route": EVENTS, "empty": 0, "wrong": 0, "accepted": 9, "rejected": 0},
    {"route": EVENTS, "empty": 1, "wrong": 0, "rejected": -1},
    {"route": EVENTS, "empty": 1, "wrong": 0, "rejected": 2 ** 32},
    {"route": EVENTS, "empty": -1, "wrong": 1},
    {"route": EVENTS, "empty": 2 ** 32, "wrong": 0},
    {"route": EVENTS, "empty": True, "wrong": 0},
    {"route": EVENTS, "empty": 1, "wrong": 0, "accepted": 1.5},
])
def test_the_writer_refuses_what_is_not_a_count_of_refusals(tmp_path, kwargs):
    with PalaWriter(tmp_path / "w.pala") as w:
        w.genesis()
        before = w.seq
        with pytest.raises(ValueError):
            w.reports_refused(**kwargs)
        assert w.seq == before


def test_the_reader_reports_each_record_and_the_verdict_does_not_move(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.reports_refused(EVENTS, empty=0, wrong=3, accepted=0)
    views, advisories = _refused(log)
    assert len(views) == len(advisories) == 1
    assert advisories[0].at_seq == views[0].seq
    assert EVENTS in advisories[0].detail and "3 report(s)" in advisories[0].detail
    assert "reports_refused" in ADVISORY_CODES
    report = build_report(log).data
    assert report["verdict"] == "partial"  # an unanchored chain, as without the record
    assert "reports_refused" in [i["code"] for i in report["advisory"]["items"]]


def test_the_export_line_states_the_counts(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.reports_refused(TRACES, empty=2, wrong=5, accepted=9, rejected=3)
    out = io.StringIO()
    export_jsonl(log.read_bytes(), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    with_counts = [x for x in lines if "reports_refused" in x]
    assert len(with_counts) == 1 and with_counts[0]["kind_name"] == "REPORTS_REFUSED"
    assert with_counts[0]["reports_refused"] == {
        "route": TRACES, "empty_credential": 2, "wrong_credential": 5, "accepted": 9,
        "rejected": 3}


# -- the serve -----------------------------------------------------------------

def test_the_first_refusal_on_a_route_is_on_the_chain_at_once(served):
    client, _app, audit, log = served
    before = audit.writer.seq
    assert client.post(CLAUDE, json={}).status_code == 401
    assert audit.writer.seq == before + 1
    # the serve is killed here: no stop, no close — the record is already there
    audit.writer._fh.close()
    audit.writer._xlock.release()
    views, _ = _refused(log)
    assert views == [ReportsRefusedView(seq=before, route=CLAUDE, refused_empty=1,
                                        refused_wrong=0, accepted=0, rejected=0)]


def test_an_empty_key_and_a_wrong_key_are_counted_apart(served):
    client, app, audit, log = served
    client.post(EVENTS, json=CALL)                                           # no header
    client.post(EVENTS, json=CALL, headers={"Authorization": "Bearer"})      # empty
    client.post(EVENTS, json=CALL, headers={"Authorization": "Bearer nope"})  # wrong
    client.post(EVENTS, json=CALL, headers=AUTH)                             # accepted
    _stop(app, audit)
    views, _ = _refused(log)
    assert [(v.refused_empty, v.refused_wrong, v.accepted) for v in views] == [
        (1, 0, 0), (2, 1, 1)]
    assert {v.route for v in views} == {EVENTS}


def test_at_most_two_records_per_route_however_many_are_refused(served):
    """The record is caused by a request that failed authentication: anyone
    who reaches the port can cause one. It must not be a way to grow the
    chain."""
    client, app, audit, log = served
    before = audit.writer.seq
    for _ in range(200):
        for route in (EVENTS, CLAUDE, CODEX, TRACES):
            client.post(route, json={}, headers={"Authorization": "Bearer flood"})
    assert audit.writer.seq == before + 4  # one per route, at its first refusal
    _stop(app, audit)
    views, advisories = _refused(log)
    assert len(views) == len(advisories) == 8
    per_route = {}
    for v in views:
        per_route.setdefault(v.route, []).append(v.refused_wrong)
    assert per_route == {r: [1, 200] for r in (EVENTS, CLAUDE, CODEX, TRACES)}
    app.state.cancel_pending()  # stopping twice says nothing twice


def test_a_single_refusal_is_said_once(served):
    client, app, audit, log = served
    client.post(CODEX, json={})
    _stop(app, audit)
    views, _ = _refused(log)
    assert [(v.route, v.refused_empty) for v in views] == [(CODEX, 1)]


def test_a_run_with_nothing_turned_away_writes_no_such_record(served):
    client, app, audit, log = served
    assert client.post(EVENTS, json=CALL, headers=AUTH).status_code == 200
    assert client.post(EVENTS + "?dry_run=1", json=CALL, headers=AUTH).status_code == 200
    _stop(app, audit)
    assert _refused(log) == ([], [])


# -- read and rejected ---------------------------------------------------------

def test_the_first_rejected_report_on_a_route_is_on_the_chain_at_once(served):
    """A report that passed the key check and was then rejected is a report
    whose events are not on the chain, exactly like a refused one."""
    client, app, audit, log = served
    before = audit.writer.seq
    assert client.post(EVENTS, json=CALL, headers=AUTH).status_code == 200
    seq = audit.writer.seq
    r = client.post(EVENTS, json=[], headers=AUTH)  # not a report this route takes
    assert 400 <= r.status_code < 500 and r.status_code != 401
    assert audit.writer.seq == seq + 1
    client.post(EVENTS, json=[], headers=AUTH)
    client.post(EVENTS, json=[], headers=AUTH)
    assert audit.writer.seq == seq + 1  # only the first, until the stop
    _stop(app, audit)
    views, advisories = _refused(log)
    assert [(v.refused_empty, v.refused_wrong, v.accepted, v.rejected) for v in views] == [
        (0, 0, 1, 1), (0, 0, 1, 3)]
    assert len(advisories) == 2 and "3 read and rejected" in advisories[1].detail
    assert before < views[0].seq


def test_a_body_that_cannot_be_read_is_a_rejection_on_the_chain(served):
    client, app, audit, log = served
    deep = "[" * 60_000 + "]" * 60_000  # past the JSON parser's own stack
    for route in (EVENTS, CLAUDE, CODEX):
        r = client.post(route, content=deep,
                        headers={**AUTH, "Content-Type": "application/json"})
        assert 400 <= r.status_code < 500, (route, r.status_code)
    r = client.post(TRACES, content=b"{", headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 400
    r = client.post(CLAUDE, content=b"\xff not json",
                    headers={**AUTH, "Content-Type": "application/json"})
    assert 400 <= r.status_code < 500
    _stop(app, audit)
    views, _ = _refused(log)
    assert {(v.route, v.rejected) for v in views} == {
        (EVENTS, 1), (CODEX, 1), (TRACES, 1), (CLAUDE, 1), (CLAUDE, 2)}
    assert b"not json" not in log.read_bytes()


def test_a_report_that_breaks_the_handler_is_counted_and_recorded(tmp_path):
    log = tmp_path / "boom.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit,
                     api_key=KEY)
    client = TestClient(app, raise_server_exceptions=False)
    real = audit.tool_called

    def boom(*a, **k):
        raise RuntimeError("a defect in the handler")

    audit.tool_called = boom
    hook = {"hook_event_name": "PreToolUse", "tool_name": "T", "tool_use_id": "x",
            "tool_input": {}}
    assert client.post(CLAUDE, json=hook, headers=AUTH).status_code == 500
    audit.tool_called = real
    assert client.get("/v1/pala/status", headers=AUTH).json()["ingest"][CLAUDE][
        "rejected"] == 1
    _stop(app, audit)
    views, _ = _refused(log)
    assert [(v.route, v.rejected) for v in views] == [(CLAUDE, 1)]


def test_at_most_three_records_per_route_whatever_is_sent(served):
    client, app, audit, log = served
    for _ in range(50):
        client.post(EVENTS, json=CALL)                # refused
        client.post(EVENTS, json=[], headers=AUTH)    # rejected
        client.post(EVENTS, json=CALL, headers=AUTH)  # accepted
    _stop(app, audit)
    views, _ = _refused(log)
    assert [(v.refused_empty, v.accepted, v.rejected) for v in views] == [
        (1, 0, 0), (1, 0, 1), (50, 50, 50)]
    app.state.cancel_pending()


def test_the_stop_says_nothing_when_the_counts_have_not_moved(served):
    client, app, audit, log = served
    for _ in range(3):
        client.post(EVENTS, json=CALL, headers=AUTH)
    client.post(EVENTS, json=CALL)  # one refusal, after three accepted, then nothing
    _stop(app, audit)
    views, _ = _refused(log)
    assert [(v.refused_empty, v.accepted) for v in views] == [(1, 3)]


def test_only_reporting_routes_are_recorded(served):
    client, app, audit, log = served
    before = audit.writer.seq
    assert client.get("/v1/pala/status").status_code == 401
    assert client.get("/v1/models").status_code == 401
    assert client.post("/v1/chat/completions", json={}).status_code == 401
    assert client.get(EVENTS).status_code in (401, 405)  # not a report: not a POST
    assert audit.writer.seq == before
    _stop(app, audit)
    assert _refused(log) == ([], [])


def test_nothing_of_the_refused_request_is_recorded(served):
    client, app, audit, log = served
    secret = "what-the-refused-client-tried-to-say"
    client.post(CLAUDE, json={"hook_event_name": "PreToolUse", "tool_name": secret,
                              "tool_use_id": secret, "tool_input": {"q": secret}},
                headers={"Authorization": f"Bearer {secret}"})
    _stop(app, audit)
    assert secret.encode() not in log.read_bytes()


def test_a_refusal_after_the_chain_is_closed_is_still_a_401(served):
    client, app, audit, _log = served
    _stop(app, audit)
    assert client.post(TRACES, json={}).status_code == 401  # not a 500


def test_a_serve_without_a_key_or_without_a_chain_has_nothing_to_record(tmp_path):
    no_chain = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                     api_key=KEY))
    assert no_chain.post(EVENTS, json=CALL).status_code == 401
    log = tmp_path / "open.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    assert TestClient(app).post(EVENTS, json=CALL).status_code == 200  # no key: no refusal
    _stop(app, audit)
    assert _refused(log) == ([], [])


# -- the vectors ---------------------------------------------------------------

def test_the_vectors_hold_a_first_refusal_and_the_counts_at_the_stop(tmp_path):
    doc = vectors.load("inference")
    assert doc["profile_revision"] == "r9" and len(doc["records"]) == 32
    assert [r["label"] for r in doc["records"][27:]] == [
        "boot_3", "writer_open_3", "reports_refused_first", "reports_refused_at_stop",
        "writer_close_3"]
    path = tmp_path / "v.pala"
    path.write_bytes(b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in doc["records"]))
    views, advisories = _refused(path)
    assert len(advisories) == 2
    for view in views:
        expected = doc["semantics"][str(view.seq)]
        assert (view.route, view.refused_empty, view.refused_wrong, view.accepted) == (
            expected["route"], expected["refused_empty"], expected["refused_wrong"],
            expected["accepted"])
        assert view.rejected == expected["rejected"]
    assert [v.seq for v in views] == [29, 30]
    with AuditReader.open(path) as reader:
        assert len(reader.boots()) == 3
        assert not [i for i in reader.verify().advisory.items
                    if i.code == "boot_ended_without_close"]
