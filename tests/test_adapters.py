# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The two adapters, driven end to end against a live serve.

Both report through ``POST /v1/pala/events`` and both are pinned on the
same thing the OpenCode plugin is: the chain that results carries
``TOOL_CALL`` / ``TOOL_RESULT`` pairs marked ``reported-by-client``,
bound by seq + hash, with the outcomes the adapter actually observed.

* LiteLLM: the ``Reporter`` logic on plain OpenAI-shaped dicts (always),
  and the real ``CustomLogger`` wiring through ``litellm.completion`` with
  ``mock_tool_calls`` when LiteLLM is installed (no provider needed).
* MCP: the stdio proxy between a fake client and a fake server, covering
  a normal call, an ``isError`` result, a JSON-RPC error, and a call the
  server never answers (``cancelled`` on exit).
"""

from __future__ import annotations

import importlib.util
import json
import os
import pytest
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")
from palimpsests.audit.pala import decode_tlvs, iter_records, record_hash  # noqa: E402
from palimpsests.audit.pala_writer import (  # noqa: E402
    EVT_KIND,
    EVT_OUTCOME,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    EVT_SOURCE,
    EVT_TOOL_NAME,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
    OUTCOME_CANCELLED,
    OUTCOME_ERROR,
    OUTCOME_OK,
    SOURCE_REPORTED_BY_CLIENT,
    PalaWriter,
)
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "integrations"
LITELLM_ADAPTER = ROOT / "litellm" / "palimpsests_audit.py"
MCP_PROXY = ROOT / "mcp" / "palimpsests_audit_mcp.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plain_chat(**kwargs):
    yield ChatChunk(delta="text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


class _Serve:
    """A real uvicorn serve on a loopback port, writing to a chain file."""

    def __init__(self, tmp_path: Path, api_key: str = "k-test"):
        from palimpsests.providers.native.audit import NativeAudit

        self.log = tmp_path / "adapters.pala"
        self.audit = NativeAudit(PalaWriter(self.log))
        app = create_app(
            chat_fn=_plain_chat, models_fn=lambda: [], audit=self.audit, api_key=api_key
        )
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.api_key = api_key
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        )
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

    def pairs(self) -> list[tuple[str, int, int]]:
        """(tool name, outcome, source-of-result) per bound call/result pair."""
        calls: dict[int, tuple[bytes, dict]] = {}
        results: list[dict] = []
        for i, (hb, body) in enumerate(iter_records(self.log.read_bytes())):
            if not body:
                continue
            tlvs = dict(decode_tlvs(body))
            if EVT_KIND not in tlvs:
                continue
            kind = struct.unpack("<H", tlvs[EVT_KIND])[0]
            if kind == KIND_TOOL_CALL:
                calls[i] = (hb, tlvs)
            elif kind == KIND_TOOL_RESULT:
                results.append(tlvs)
        out = []
        for r in results:
            seq = struct.unpack("<Q", r[EVT_REF_SEQ])[0]
            hb, c = calls[seq]
            assert r[EVT_REF_HASH] == record_hash(hb)
            assert struct.unpack("<H", c[EVT_SOURCE])[0] == SOURCE_REPORTED_BY_CLIENT
            outcome = struct.unpack("<H", r[EVT_OUTCOME])[0]
            if outcome != OUTCOME_CANCELLED:
                # a cancelled result is the serve's own shutdown observation,
                # written without the client mark; every reported result has it
                assert struct.unpack("<H", r[EVT_SOURCE])[0] == SOURCE_REPORTED_BY_CLIENT
            out.append((c[EVT_TOOL_NAME].decode(), outcome))
        return out, len(calls)


# ── LiteLLM ─────────────────────────────────────────────────────────────


def _response_with_calls(calls: list[tuple[str, str, str]]) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": cid, "type": "function", "function": {"name": n, "arguments": a}}
                        for cid, n, a in calls
                    ],
                }
            }
        ]
    }


def test_litellm_reporter_pairs_calls_with_the_next_requests_tool_messages(tmp_path, monkeypatch):
    mod = _load(LITELLM_ADAPTER, "palimpsests_audit_litellm")
    with _Serve(tmp_path) as serve:
        rep = mod.Reporter(url=serve.url, api_key=serve.api_key)
        # turn 1: the model asks for two tools
        ev1 = rep.observe(
            [{"role": "user", "content": "hi"}],
            _response_with_calls(
                [("c1", "fs.read", '{"path":"README.md"}'), ("c2", "web.search", "{}")]
            ),
        )
        assert [e["type"] for e in ev1] == ["tool_call", "tool_call"]
        # turn 2: the application feeds one result back; the model asks for nothing
        ev2 = rep.observe(
            [
                {"role": "user", "content": "hi"},
                {"role": "tool", "tool_call_id": "c1", "content": "# Palimpsests"},
                {"role": "tool", "tool_call_id": "zzz", "content": "never reported"},
            ],
            {"choices": [{"message": {"role": "assistant", "content": "done"}}]},
        )
        assert [e["type"] for e in ev2] == ["tool_result"] and ev2[0]["call_id"] == "c1"
        # the same tool message again is a no-op; a duplicate call id too
        assert rep.observe([{"role": "tool", "tool_call_id": "c1", "content": "x"}], None) == []
        assert rep.observe([], _response_with_calls([("c1", "fs.read", "{}")])) == []
    pairs, n_calls = serve.pairs()
    assert n_calls == 2
    # c2 was never answered: cancelled by the serve at shutdown
    assert sorted(pairs) == [("fs.read", OUTCOME_OK), ("web.search", OUTCOME_CANCELLED)]


def test_litellm_reporter_tolerates_a_result_hook_arriving_before_its_call(tmp_path):
    mod = _load(LITELLM_ADAPTER, "palimpsests_audit_litellm_early")
    with _Serve(tmp_path) as serve:
        rep = mod.Reporter(url=serve.url, api_key=serve.api_key)
        # hook for turn 2 fires first: the result is held, nothing is sent
        assert rep.observe([{"role": "tool", "tool_call_id": "c7", "content": "42"}], None) == []
        # hook for turn 1 fires next: call and the held result go out together, in order
        ev = rep.observe([], _response_with_calls([("c7", "calc", '{"a":6}')]))
        assert [e["type"] for e in ev] == ["tool_call", "tool_result"]
    pairs, n_calls = serve.pairs()
    assert n_calls == 1 and pairs == [("calc", OUTCOME_OK)]


def test_litellm_reporter_is_inert_when_disabled(tmp_path, monkeypatch):
    mod = _load(LITELLM_ADAPTER, "palimpsests_audit_litellm_off")
    monkeypatch.setenv("PALIMPSESTS_AUDIT_REPORT", "0")
    rep = mod.Reporter(url="http://127.0.0.1:9", api_key="")
    assert rep.post([{"type": "tool_call", "id": "x", "name": "t"}]) is None
    assert rep.enabled is False


@pytest.mark.skipif(importlib.util.find_spec("litellm") is None, reason="litellm not installed")
def test_litellm_custom_logger_wiring_end_to_end(tmp_path):
    import litellm

    mod = _load(LITELLM_ADAPTER, "palimpsests_audit_litellm_real")
    with _Serve(tmp_path) as serve:
        cb = mod.PalimpsestsAudit(url=serve.url, api_key=serve.api_key)
        old = litellm.callbacks
        litellm.callbacks = [cb]
        try:
            litellm.completion(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "read the readme"}],
                mock_tool_calls=[
                    {
                        "id": "call_9",
                        "type": "function",
                        "function": {"name": "fs.read", "arguments": '{"path":"README.md"}'},
                    }
                ],
            )
            litellm.completion(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": "read the readme"},
                    {"role": "tool", "tool_call_id": "call_9", "content": "# Palimpsests"},
                ],
                mock_response="ok, read it",
            )
            deadline = time.monotonic() + 5
            while cb.reporter._pending and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            litellm.callbacks = old
    pairs, n_calls = serve.pairs()
    assert n_calls == 1 and pairs == [("fs.read", OUTCOME_OK)]


# ── MCP ─────────────────────────────────────────────────────────────────

FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    rid = msg.get("id"); method = msg.get("method")
    if method == "initialize":
        out = {"jsonrpc": "2.0", "id": rid,
               "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}}
    elif method == "notifications/initialized":
        continue
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name == "boom":
            out = {"jsonrpc": "2.0", "id": rid,
                   "result": {"content": [{"type": "text", "text": "failed"}], "isError": True}}
        elif name == "rpcfail":
            out = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "nope"}}
        elif name == "hang":
            break  # exit without answering: the proxy must report cancelled
        else:
            out = {"jsonrpc": "2.0", "id": rid,
                   "result": {"content": [{"type": "text", "text": "42"}]}}
    else:
        out = {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown"}}
    sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()
"""


def test_mcp_proxy_reports_each_tools_call_with_its_observed_outcome(tmp_path):
    fake = tmp_path / "fake_server.py"
    fake.write_text(FAKE_SERVER)
    with _Serve(tmp_path) as serve:
        env = dict(
            os.environ, PALIMPSESTS_SERVE_URL=serve.url, PALIMPSESTS_SERVE_API_KEY=serve.api_key
        )
        proc = subprocess.Popen(
            [sys.executable, str(MCP_PROXY), "--", sys.executable, str(fake)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
        )
        assert proc.stdin and proc.stdout

        def rpc(rid, method, params=None):
            proc.stdin.write(
                json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
                + "\n"
            )
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        assert rpc(1, "initialize", {"protocolVersion": "2025-06-18"})["result"]["capabilities"]
        proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        proc.stdin.flush()
        r = rpc(2, "tools/call", {"name": "calc.multiply", "arguments": {"a": 6, "b": 7}})
        assert r["result"]["content"][0]["text"] == "42"  # forwarded unchanged
        assert rpc("s-3", "tools/call", {"name": "boom", "arguments": {}})["result"]["isError"]
        assert "error" in rpc(4, "tools/call", {"name": "rpcfail"})
        # the server exits on this one without answering
        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "hang", "arguments": {}},
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        proc.stdin.close()
        rc = proc.wait(timeout=20)
        assert rc == 0
    pairs, n_calls = serve.pairs()
    assert n_calls == 4
    assert sorted(pairs) == sorted(
        [
            ("calc.multiply", OUTCOME_OK),
            ("boom", OUTCOME_ERROR),
            ("rpcfail", OUTCOME_ERROR),
            ("hang", OUTCOME_CANCELLED),
        ]
    )


def test_mcp_proxy_forwards_when_reporting_is_disabled(tmp_path):
    fake = tmp_path / "fake_server.py"
    fake.write_text(FAKE_SERVER)
    env = dict(os.environ, PALIMPSESTS_AUDIT_REPORT="0", PALIMPSESTS_SERVE_URL="http://127.0.0.1:9")
    proc = subprocess.Popen(
        [sys.executable, str(MCP_PROXY), "--", sys.executable, str(fake)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    proc.stdin.write(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x", "arguments": {}},
            }
        )
        + "\n"
    )
    proc.stdin.flush()
    assert json.loads(proc.stdout.readline())["result"]["content"][0]["text"] == "42"
    proc.stdin.close()
    assert proc.wait(timeout=20) == 0
    assert "report failed" not in proc.stderr.read()
