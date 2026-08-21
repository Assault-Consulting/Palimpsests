# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``palimpsests demo`` — the whole point of the project in one command.

Runs a tiny deterministic agent turn with one tool call through the real
level-3 serving stack (scheduler, session, tool loop), records everything
into a real PALA-1 chain, then verifies that chain with the production
reader and prints what an auditor would see. No model download, no
network, no configuration: the backend is a deterministic stand-in, so
the demo shows the thing this project actually adds — the evidence — in
seconds on any machine.

Deliberately built on the public seams (writer → adapter → session →
reader) and not on shortcuts: this module is the seed of a future
``scriptorium run``, so it must only do what a real launcher would do.
"""
from __future__ import annotations

import typer
from collections.abc import Sequence
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.providers.native.audit import (
    NativeAudit,
    injected_backend_digest,
)
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession
from pathlib import Path

_LOG_OPTION = typer.Option(
    Path("palimpsests-demo.pala"),
    help="Where to write the demo audit chain (overwritten if present).",
)


class _DemoBackend:
    """Deterministic NativeBackend stand-in: real seams, fake entropy."""

    def __init__(self) -> None:
        self._vocab = 64
        self._script = [5, 6, 0, 7, 8, 0]  # turn, then post-tool continuation
        self._i = 0

    def tokenize(self, text: str, *, add_special: bool = True) -> list[int]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[int]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries):
        out = {}
        for entry in entries:
            token = self._script[self._i] if self._i < len(self._script) else 0
            self._i += 1
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    def seq_copy(self, src_seq, dst_seq, p0=-1, p1=-1) -> None:
        pass

    def seq_remove(self, seq_id, p0=-1, p1=-1) -> None:
        pass

    def state_get(self, seq_id) -> bytes:
        return b""

    def state_set(self, seq_id, state) -> None:
        pass

    def n_seq_max(self) -> int:
        return 4

    def close(self) -> None:
        return None


def demo(log: Path = _LOG_OPTION) -> None:
    """Run a tiny audited agent turn and verify its trail — in seconds."""
    if log.exists():
        log.unlink()

    typer.echo("1. Serving a turn through the level-3 engine (deterministic demo backend)")
    backend = _DemoBackend()
    writer = PalaWriter(log)
    audit = NativeAudit(writer)
    audit.model_loaded(
        injected_backend_digest(backend),
        b"\x00" * 32,
        detail="injected: demo backend, no model artifact",
    )
    span = audit.session_opened()
    session = NativeSession(
        backend,
        Scheduler(backend, max_active=1),
        stop_tokens=(0,),
        audit=audit,
        audit_span=span,
    )
    reply = "".join(c.delta for c in session.send("What is 6 x 7? Use the calculator."))
    typer.echo(f"   model replied: {reply!r}")

    typer.echo("2. The model asked for a tool — dispatching, on the record")
    session.note_tool_call("call_1", "calc.multiply", arguments={"a": 6, "b": 7})
    cont = "".join(c.delta for c in session.append_tool_result("call_1", "42"))
    typer.echo(f"   tool returned '42'; model continued: {cont!r}")
    session.close()
    writer.close()
    typer.echo(f"3. Audit chain written: {log}")

    typer.echo("4. Verifying with the production reader (what an auditor runs)")
    with AuditReader.open(log) as reader:
        ver = reader.verify()
        kinds = [dr.kind_name for dr in reader.records() if dr.kind_name]
    chain = ver.chain
    typer.echo(
        f"   records: {chain.count}   chain_ok: {chain.chain_ok}   "
        f"head: {chain.head.hex()[:16]}…"
    )
    typer.echo(f"   recorded events: {', '.join(kinds)}")
    typer.echo(f"   advisories: {len(ver.advisory.items)} (signals, never a verdict)")

    ok = chain.chain_ok and "TOOL_CALL" in kinds and "TOOL_RESULT" in kinds
    if not ok:
        typer.echo("DEMO FAILED: the trail did not verify — please file a bug.")
        raise typer.Exit(code=1)
    typer.echo(
        "\nDone. Every step above is in the chain — tamper one byte of "
        f"{log} and step 4 turns red. Try: palimpsests pala verify {log}"
    )
