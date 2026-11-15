# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The serve and the disk: a call is on stable storage before the client
is told of it, and the policy in force is never a silent one."""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit import pala_writer  # noqa: E402
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.audit.reader import AuditReader  # noqa: E402
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.providers.native.audit import NativeAudit  # noqa: E402
from palimpsests.server import openai_api  # noqa: E402
from palimpsests.server.openai_api import (  # noqa: E402
    DURABILITY_VAR,
    ServeChainUnavailable,
    create_app,
    default_audit,
)

TOOLS = [{"type": "function", "function": {"name": "read", "parameters": {}}}]
CALL_TEXT = '<tool_call>{"name": "read", "arguments": {"path": "x"}}</tool_call>'


def _chat_calling_a_tool(**kwargs):
    yield ChatChunk(delta=CALL_TEXT)
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def _post(client, stream):
    return client.post("/v1/chat/completions", json={
        "model": "m", "stream": stream, "tools": TOOLS,
        "messages": [{"role": "user", "content": "read x"}],
    })


@pytest.mark.parametrize("stream", [False, True])
def test_a_tool_call_is_synced_before_the_client_learns_of_it(tmp_path, monkeypatch, stream):
    """The client runs the tool when it reads the response. With the record
    synced first, a power cut after the tool ran cannot leave a chain that
    never heard of the call."""
    path = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(path))
    log: list[tuple[str, int]] = []

    def sync(_fd):
        with AuditReader.open(path) as r:
            log.append(("sync", r.record_count))

    monkeypatch.setattr(pala_writer, "_sync_file", sync)
    client = TestClient(create_app(chat_fn=_chat_calling_a_tool, models_fn=lambda: [],
                                   audit=audit))
    try:
        response = _post(client, stream)
        assert response.status_code == 200
        body = response.text
        assert "tool_calls" in body and '"read"' in body
        with AuditReader.open(path) as r:
            kinds = [r.record_at(i).kind_name for i in range(r.record_count)]
            call_at = kinds.index("TOOL_CALL")
        # a sync that already saw the TOOL_CALL record in the file happened
        # during the request — before a byte of the response existed
        assert any(count > call_at for _what, count in log), (log, kinds)
    finally:
        audit.writer.close()


def test_the_response_is_built_after_the_record_not_beside_it(tmp_path, monkeypatch):
    """Order, directly: when the sync of the TOOL_CALL record runs, the
    handler has not returned."""
    path = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(path))
    order: list[str] = []
    monkeypatch.setattr(pala_writer, "_sync_file", lambda _fd: order.append("sync"))
    real = openai_api._sse_prebuilt

    def prebuilt(**kw):
        order.append("response")
        return real(**kw)

    monkeypatch.setattr(openai_api, "_sse_prebuilt", prebuilt)
    client = TestClient(create_app(chat_fn=_chat_calling_a_tool, models_fn=lambda: [],
                                   audit=audit))
    try:
        order.clear()
        assert _post(client, True).status_code == 200
        assert order and order[-1] == "response" and "sync" in order[:-1]
    finally:
        audit.writer.close()


def test_a_report_is_synced_before_it_is_acknowledged(tmp_path, _no_disk_sync):
    """A client's own report (hooks, events) comes after the fact; what the
    serve can promise is that a report answered 200 is on stable storage."""
    audit = NativeAudit(PalaWriter(tmp_path / "serve.pala"))
    client = TestClient(create_app(chat_fn=_chat_calling_a_tool, models_fn=lambda: [],
                                   audit=audit))
    try:
        before = (_no_disk_sync["file"], audit.writer.seq)
        r = client.post("/v1/pala/events",
                        json={"events": [{"type": "tool_call", "id": "c1", "name": "read"}]})
        assert r.status_code == 200
        written = audit.writer.seq - before[1]
        assert written >= 1 and _no_disk_sync["file"] - before[0] == written
    finally:
        audit.writer.close()


# ── the policy in force is never a silent one ───────────────────────────────


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv(DURABILITY_VAR, raising=False)
    return tmp_path


def test_the_serves_chain_syncs_every_record_unless_told_otherwise(config_dir, monkeypatch):
    audit = default_audit()
    assert str(audit.writer.durability) == "record"
    audit.writer.close()
    for spelled in ("os", "group", "group:0.5"):
        monkeypatch.setenv(DURABILITY_VAR, spelled)
        audit = default_audit()
        assert audit.writer.durability == pala_writer.Durability.parse(spelled)
        audit.writer.close()


def test_a_misspelled_policy_stops_the_serve(config_dir, monkeypatch):
    """`off`, `none`, `fsync`: whatever was meant, it must not become `os`."""
    for spelled in ("off", "none", "fsync", "group:fast"):
        monkeypatch.setenv(DURABILITY_VAR, spelled)
        with pytest.raises(ServeChainUnavailable, match=DURABILITY_VAR):
            default_audit()
    assert not (config_dir / "serve.pala").exists()  # refused before anything was opened


def test_the_status_route_states_the_policy(tmp_path):
    for policy in ("record", "os", "group:0.25"):
        audit = NativeAudit(PalaWriter(tmp_path / f"{policy[:2]}.pala", durability=policy))
        client = TestClient(create_app(chat_fn=_chat_calling_a_tool, models_fn=lambda: [],
                                       audit=audit))
        try:
            assert client.get("/v1/pala/status").json()["chain"]["durability"] == policy
        finally:
            audit.writer.close()


def test_a_relaxed_policy_is_announced_at_startup(config_dir, monkeypatch, capsys):
    import sys
    import types

    ran = {}
    fake = types.ModuleType("uvicorn")
    fake.run = lambda app, host, port: ran.setdefault("app", app)
    monkeypatch.setitem(sys.modules, "uvicorn", fake)
    monkeypatch.setattr(openai_api, "_default_deps", lambda: None)
    for spelled, expect in (("record", None), ("os", "'os'"), ("group:0.5", "0.5 s")):
        monkeypatch.setenv(DURABILITY_VAR, spelled)
        openai_api.run_serve("127.0.0.1", 0, "sk-x")
        err = capsys.readouterr().err
        if expect is None:
            assert "durability" not in err
        else:
            assert "audit durability" in err and expect in err and "anchor" in err
