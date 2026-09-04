# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The OpenCode reporter plugin, driven end to end against a live serve.

The plugin is JavaScript; this test runs it under Node with the hook
contract OpenCode exposes (``tool.execute.before`` / ``tool.execute.after``
and the ``message.part.updated`` fallback), pointed at a real
``palimpsests serve`` on a loopback port. What is asserted is the DoD of
WS-INT: kinds 8/9 with ``EVT_SOURCE = reported-by-client`` on the chain,
bound by seq+hash, produced by the client-side plugin — plus the two
robustness properties the plugin claims: the fallback path reports a
result when the ``after`` hook did not, and a duplicate never lands.
"""
from __future__ import annotations

import json
import os
import pytest
import shutil
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

fastapi = pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")
from palimpsests.audit.pala import decode_tlvs, iter_records  # noqa: E402
from palimpsests.audit.pala_writer import (  # noqa: E402
    EVT_KIND,
    EVT_OUTCOME,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    EVT_SOURCE,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
    OUTCOME_ERROR,
    OUTCOME_OK,
    SOURCE_REPORTED_BY_CLIENT,
    PalaWriter,
)
from palimpsests.engine.messages import ChatChunk  # noqa: E402
from palimpsests.server.openai_api import create_app  # noqa: E402

PLUGIN = (
    Path(__file__).resolve().parent.parent
    / "integrations"
    / "opencode"
    / "palimpsests-audit.js"
)
NODE = shutil.which("node")

# A tiny harness that loads the plugin as OpenCode would and drives the
# hooks with the payload shapes OpenCode passes (input/output split for
# the tool hooks; an event envelope for the fallback path).
DRIVER = r"""
import { pathToFileURL } from "node:url";
const mod = await import(pathToFileURL(process.argv[2]).href);
const logs = [];
const client = { app: { log: async (o) => { logs.push(o.body); } } };
const hooks = await mod.PalimpsestsAudit({ client });

// 1. normal path: before + after
await hooks["tool.execute.before"](
  { tool: "read", sessionID: "s1", callID: "c1" },
  { args: { filePath: "README.md" } },
);
await hooks["tool.execute.after"](
  { tool: "read", sessionID: "s1", callID: "c1", args: { filePath: "README.md" } },
  { title: "README.md", output: "# Palimpsests", metadata: {} },
);
// a late duplicate must be a no-op (already reported)
await hooks.event({ event: { type: "message.part.updated", properties: { part: {
  type: "tool", callID: "c1", state: { status: "completed", output: "# Palimpsests" } } } } });

// 2. fallback path: before fires, after never does, the part errors
await hooks["tool.execute.before"](
  { tool: "read", sessionID: "s1", callID: "c2" },
  { args: { filePath: "does-not-exist.txt" } },
);
await hooks.event({ event: { type: "message.part.updated", properties: { part: {
  type: "tool", callID: "c2", state: { status: "error", error: "ENOENT" } } } } });

// 3. unrelated events are ignored
await hooks.event({ event: { type: "session.idle", properties: {} } });
await hooks.event({ event: { type: "message.part.updated", properties: { part: {
  type: "text", text: "hi" } } } });

console.log(JSON.stringify({ logs }));
"""


def _plain_chat(**kwargs):
    yield ChatChunk(delta="just text")
    yield ChatChunk(delta="", done=True, finish_reason="stop")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _bodies_by_kind(path: Path) -> dict[int, list[tuple[int, dict, bytes]]]:
    out: dict[int, list] = {}
    for seq, (hb, body) in enumerate(iter_records(path.read_bytes())):
        if not body:
            continue
        tlvs = dict(decode_tlvs(body))
        if EVT_KIND not in tlvs:
            continue
        kind = struct.unpack("<H", tlvs[EVT_KIND])[0]
        out.setdefault(kind, []).append((seq, tlvs, hb))
    return out


@pytest.mark.skipif(NODE is None, reason="node not on PATH")
def test_plugin_reports_calls_and_results_onto_the_chain(tmp_path):
    from palimpsests.audit.pala import record_hash
    from palimpsests.providers.native.audit import NativeAudit

    log = tmp_path / "opencode.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(
        chat_fn=_plain_chat, models_fn=lambda: [], audit=audit, api_key="k-test"
    )
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "serve did not start"
        time.sleep(0.05)
    try:
        driver = tmp_path / "driver.mjs"
        driver.write_text(DRIVER)
        env = dict(
            os.environ,
            PALIMPSESTS_SERVE_URL=f"http://127.0.0.1:{port}",
            PALIMPSESTS_SERVE_API_KEY="k-test",
        )
        proc = subprocess.run(
            [NODE, str(driver), str(PLUGIN)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        logs = json.loads(proc.stdout.strip().splitlines()[-1])["logs"]
        assert not [entry for entry in logs if entry["level"] == "warn"], logs
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        audit.writer.close()

    kinds = _bodies_by_kind(log)
    calls = kinds.get(KIND_TOOL_CALL, [])
    results = kinds.get(KIND_TOOL_RESULT, [])
    assert len(calls) == 2, "two calls reported (c1, c2)"
    assert len(results) == 2, "one result per call — the duplicate did not land"

    # every reported record carries the mark
    for _, tlvs, _ in calls + results:
        assert struct.unpack("<H", tlvs[EVT_SOURCE])[0] == SOURCE_REPORTED_BY_CLIENT

    # results bind to their calls by seq AND hash, and carry the outcome
    # the client saw: c1 ok via the after hook, c2 error via the fallback
    by_ref = {
        struct.unpack("<Q", t[EVT_REF_SEQ])[0]: t for _, t, _ in results
    }
    outcomes = []
    for seq, _, hb in calls:
        res = by_ref[seq]
        assert res[EVT_REF_HASH] == record_hash(hb)
        outcomes.append(struct.unpack("<H", res[EVT_OUTCOME])[0])
    assert outcomes == [OUTCOME_OK, OUTCOME_ERROR]


def test_plugin_is_inert_when_disabled(tmp_path):
    if NODE is None:
        pytest.skip("node not on PATH")
    driver = tmp_path / "off.mjs"
    driver.write_text(
        'import { pathToFileURL } from "node:url";\n'
        "const mod = await import(pathToFileURL(process.argv[2]).href);\n"
        "const hooks = await mod.PalimpsestsAudit({ client: null });\n"
        "console.log(Object.keys(hooks).length);\n"
    )
    proc = subprocess.run(
        [NODE, str(driver), str(PLUGIN)],
        capture_output=True,
        text=True,
        env=dict(os.environ, PALIMPSESTS_AUDIT_REPORT="0"),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0"
