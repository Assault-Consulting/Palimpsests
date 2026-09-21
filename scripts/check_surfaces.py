#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Surface checker — are the outside interfaces we integrate with still there?

Run every week or two:

    python scripts/check_surfaces.py                 # all probes
    python scripts/check_surfaces.py litellm mcp     # named probes
    python scripts/check_surfaces.py --report results/

This does not test our adapters' logic — the test suite does that. It
tests whether each *client's* surface still delivers what the adapter
depends on, on the version installed today. Those surfaces change
without notice (OpenCode 1.18 stopped dispatching the hooks our plugin
was written against), and the point is to learn that from a red line
here rather than from a user.

Every probe drives the same thing: a real serve whose model is a
deterministic stub that asks for exactly one tool call. That removes the
model as a variable — a real model that never emits a structured call
made the first OpenCode traffic run unreadable — and leaves the client
surface as the only thing under test. A probe is GREEN when a
TOOL_CALL / TOOL_RESULT pair lands on the chain with the source mark
that integration is supposed to produce.

States:
    GREEN  the surface delivered a paired record
    RED    the client reached the serve and the record did not follow —
           the surface changed, which is what this checker exists to find
    SKIP   the client is not installed, or never reached the serve at all
           — a fact about the machine running the check, not about the
           surface, and not a pass

The RED/SKIP line is drawn by counting completions the stub model
served. Zero means the client never talked to us — no network to its
own backend, no credentials, a broken config — and blaming the surface
for that would send someone to rewrite a working adapter. That exact
confusion cost a round on the OpenCode integration.

Exit status is 1 if any probe is RED, 0 otherwise. SKIP never fails the
run, and never counts as green: the report says so, with the reason.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTED = 1  # EVT_SOURCE reported-by-client


@dataclass
class Result:
    name: str
    state: str  # GREEN / RED / SKIP
    version: str = "—"
    detail: str = ""
    evidence: dict = field(default_factory=dict)


# ── the stub serve ──────────────────────────────────────────────────────


class StubServe:
    """A real serve on a loopback port whose model always asks for one tool."""

    def __init__(self, workdir: Path, api_key: str = "sk-surface"):
        import uvicorn
        from palimpsests.audit.pala_writer import PalaWriter
        from palimpsests.engine.messages import ChatChunk
        from palimpsests.providers.native.audit import NativeAudit
        from palimpsests.server.openai_api import create_app

        self.chain = workdir / "surface.pala"
        self.api_key = api_key
        self.audit = NativeAudit(PalaWriter(self.chain))
        self.completions = 0  # how many times a client actually reached the model

        def chat_fn(**kw):
            self.completions += 1
            msgs = kw.get("messages") or []
            answered = any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs)
            call = '{"name": "read", "arguments": {"filePath": "NOTES.md"}}'
            body = "Done." if answered else f"<tool_call>{call}</tool_call>"
            yield ChatChunk(delta=body)
            yield ChatChunk(delta="", done=True, finish_reason="stop")

        self.app = create_app(
            chat_fn=chat_fn, models_fn=lambda: ["stub"], audit=self.audit, api_key=api_key
        )
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._server = uvicorn.Server(
            uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error")
        )
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self):
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("stub serve did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self._server.should_exit = True
        self._thread.join(timeout=10)
        self.audit.writer.close()

    def pairs(self) -> dict:
        """Count kind 8/9 records on the chain and their source marks."""
        from palimpsests.audit.reader import AuditReader

        out = {"calls": 0, "results": 0, "sources": set()}
        with AuditReader.open(self.chain) as reader:
            for rec in reader.records():
                kind = getattr(rec, "kind_name", None)
                if kind == "TOOL_CALL":
                    out["calls"] += 1
                elif kind == "TOOL_RESULT":
                    out["results"] += 1
                else:
                    continue
                out["sources"].add(getattr(rec, "source", None))
        out["sources"] = sorted(s for s in out["sources"] if s is not None)
        return out


def _verdict(
    name: str, version: str, pairs: dict, expect_source: int, completions: int | None = None
) -> Result:
    if completions == 0:
        return Result(
            name, "SKIP", version,
            "the client never reached the serve (0 completions) — an environment "
            "problem on this machine, not evidence about the surface",
            pairs,
        )
    ok = pairs["calls"] >= 1 and pairs["results"] >= 1 and pairs["sources"] == [expect_source]
    detail = (
        f"{pairs['calls']} call(s), {pairs['results']} result(s), sources {pairs['sources']}"
    )
    return Result(name, "GREEN" if ok else "RED", version, detail, pairs)


def _version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        text = (out.stdout or out.stderr).strip()
        return text.splitlines()[0] if text else "?"
    except (OSError, subprocess.TimeoutExpired):
        return "?"


# ── probes ──────────────────────────────────────────────────────────────


def probe_litellm(workdir: Path) -> Result:
    """LiteLLM's CustomLogger success hook still carries tool_calls and tool messages."""
    try:
        import importlib.metadata as md
        import litellm
        version = md.version("litellm")
    except Exception:
        return Result("litellm", "SKIP", detail="litellm not installed")
    sys.path.insert(0, str(ROOT / "integrations" / "litellm"))
    from palimpsests_audit import PalimpsestsAudit

    with StubServe(workdir) as serve:
        cb = PalimpsestsAudit(url=serve.url, api_key=serve.api_key)
        saved, litellm.callbacks = litellm.callbacks, [cb]
        try:
            litellm.completion(
                model="gpt-4o",
                messages=[{"role": "user", "content": "read"}],
                mock_tool_calls=[{"id": "c1", "type": "function",
                                  "function": {"name": "read", "arguments": "{}"}}],
            )
            litellm.completion(
                model="gpt-4o",
                messages=[{"role": "user", "content": "read"},
                          {"role": "tool", "tool_call_id": "c1", "content": "hello"}],
                mock_response="done",
            )
            time.sleep(1)
        finally:
            litellm.callbacks = saved
        # No completion count here: LiteLLM's mock answers locally, so the
        # stub model is never asked. The count distinguishes environment
        # from surface only for clients that reach the model through the
        # serve (OpenCode); passing it here would turn a real green into a
        # false skip, which is how the first version of this probe behaved.
        return _verdict("litellm", version, serve.pairs(), REPORTED)


def probe_mcp(workdir: Path) -> Result:
    """The MCP stdio framing and tools/call shape our proxy parses are unchanged.

    MCP is a published protocol rather than a client, so the probe drives
    the proxy with a spec-shaped server. It goes red when our reading of
    the protocol and the protocol disagree — run it after every MCP
    specification revision.
    """
    server = workdir / "mcp_server.py"
    server.write_text(
        "import json,sys\n"
        "for line in sys.stdin:\n"
        "    m=json.loads(line); rid=m.get('id')\n"
        "    if m.get('method')=='tools/call':\n"
        "        res={'content':[{'type':'text','text':'ok'}]}\n"
        "        out={'jsonrpc':'2.0','id':rid,'result':res}\n"
        "    elif rid is None: continue\n"
        "    else: out={'jsonrpc':'2.0','id':rid,'result':{}}\n"
        "    sys.stdout.write(json.dumps(out)+'\\n'); sys.stdout.flush()\n"
    )
    proxy = ROOT / "integrations" / "mcp" / "palimpsests_audit_mcp.py"
    with StubServe(workdir) as serve:
        env = dict(os.environ, PALIMPSESTS_SERVE_URL=serve.url,
                   PALIMPSESTS_SERVE_API_KEY=serve.api_key)
        p = subprocess.Popen([sys.executable, str(proxy), "--", sys.executable, str(server)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True)
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "read", "arguments": {}}}) + "\n")
        p.stdin.flush()
        p.stdout.readline()
        p.stdin.close()
        p.wait(timeout=20)
        return _verdict("mcp", "stdio / JSON-RPC 2.0", serve.pairs(), REPORTED)


def probe_opencode(workdir: Path) -> Result:
    """OpenCode still dispatches the plugin surface our plugin uses, on this version."""
    version = _version(["opencode", "--version"])
    if version is None:
        return Result("opencode", "SKIP", detail="opencode not on PATH")
    home = workdir / "home"
    (home / ".config" / "opencode" / "plugins").mkdir(parents=True)
    (home / ".local" / "share" / "opencode").mkdir(parents=True)
    shutil.copy(ROOT / "integrations" / "opencode" / "palimpsests-audit.js",
                home / ".config" / "opencode" / "plugins")
    repo = workdir / "scratch"
    repo.mkdir()
    (repo / "NOTES.md").write_text("hello\n")
    with StubServe(workdir) as serve:
        (home / ".config" / "opencode" / "opencode.json").write_text(json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "provider": {"palimpsests": {
                "npm": "@ai-sdk/openai-compatible", "name": "surface",
                "options": {"baseURL": serve.url + "/v1", "apiKey": serve.api_key},
                "models": {"stub": {"name": "stub"}}}},
            "model": "palimpsests/stub"}))
        (home / ".local" / "share" / "opencode" / "auth.json").write_text(
            json.dumps({"palimpsests": {"type": "api", "key": serve.api_key}}))
        env = dict(os.environ, HOME=str(home), PALIMPSESTS_SERVE_URL=serve.url,
                   PALIMPSESTS_SERVE_API_KEY=serve.api_key)
        try:
            subprocess.run(["opencode", "run", "read NOTES.md"], cwd=repo, env=env,
                           capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            pass  # the completion count below says whether it got anywhere
        return _verdict("opencode", version, serve.pairs(), REPORTED, serve.completions)


PROBES = {"litellm": probe_litellm, "mcp": probe_mcp, "opencode": probe_opencode}


# ── report ──────────────────────────────────────────────────────────────


def render(results: list[Result], when: str) -> str:
    mark = {"GREEN": "🟢", "RED": "🔴", "SKIP": "⚪"}
    lines = [
        "<!-- " + "SPDX-" + "FileCopyrightText: Assault Consulting -->",
        "<!-- " + "SPDX-" + "License-Identifier: Apache-2.0 -->",
        "",
        f"# Surface check — {when}",
        "",
        "Produced by `scripts/check_surfaces.py`. SKIP is not a pass: it "
        "means the client was not available on the machine that ran the check.",
        "",
        "| Surface | State | Version | Detail |",
        "|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.name} | {mark[r.state]} {r.state} | {r.version} | {r.detail} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("probes", nargs="*", help=f"subset of: {', '.join(PROBES)}")
    ap.add_argument("--report", type=Path, help="directory to write surfaces-DATE.md into")
    args = ap.parse_args(argv[1:])
    names = args.probes or list(PROBES)
    unknown = [n for n in names if n not in PROBES]
    if unknown:
        ap.error(f"unknown probe(s): {', '.join(unknown)}")

    results = []
    for name in names:
        with tempfile.TemporaryDirectory(prefix=f"surface-{name}-") as tmp:
            try:
                results.append(PROBES[name](Path(tmp)))
            except Exception as exc:  # a crashing probe is a red surface, named
                results.append(Result(name, "RED", detail=f"probe crashed: {exc!r}"))

    when = dt.date.today().isoformat()
    text = render(results, when)
    sys.stdout.write(text)
    if args.report:
        args.report.mkdir(parents=True, exist_ok=True)
        (args.report / f"surfaces-{when}.md").write_text(text, encoding="utf-8")
    return 1 if any(r.state == "RED" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
