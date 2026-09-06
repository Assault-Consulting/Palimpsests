# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""`pala consistency` / `pala consistency-verify` — the CLI over WS-PROOF.

The library is pinned in ``test_consistency_proofs.py``; this file pins
the shell: the document it writes is the library's ``to_json`` and
verifies with ``ConsistencyProof.from_json``; the exit codes are the
three the CLI contract fixes (0 consistent, 1 inconsistent, 3
unreadable); a supplied root that differs from the document's is
INCONSISTENT before any path is checked, because a proof between roots
you did not hold independently proves nothing; and a tampered path is
INCONSISTENT, never a traceback.
"""

from __future__ import annotations

import json
from palimpsests.audit.pala.proofs import ConsistencyProof, chain_root
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

runner = CliRunner()


def _chain(tmp_path: Path, n: int = 40) -> Path:
    log = tmp_path / "c.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        for i in range(n - 2):
            w.kv_save(bytes([i % 251]) * 32)
    return log


def test_consistency_emits_a_document_the_library_verifies(tmp_path):
    log = _chain(tmp_path)
    out = tmp_path / "proof.json"
    r = runner.invoke(app, ["pala", "consistency", str(log), "--first", "13", "--out", str(out)])
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text())
    assert doc["format"] == "pala-consistency-proof/1"
    cp = ConsistencyProof.from_json(doc)
    assert (cp.first, cp.second) == (13, 40) and cp.verify()
    with AuditReader.open(log) as reader:
        assert cp.first_root == chain_root(reader, 13)
        assert cp.second_root == chain_root(reader, 40)
    # stdout form is the same document
    r2 = runner.invoke(app, ["pala", "consistency", str(log), "--first", "13", "--second", "40"])
    assert r2.exit_code == 0 and json.loads(r2.output) == doc


def test_consistency_verify_exit_codes(tmp_path):
    log = _chain(tmp_path)
    out = tmp_path / "proof.json"
    made = runner.invoke(app, ["pala", "consistency", str(log), "--first", "8", "-o", str(out)])
    assert made.exit_code == 0
    doc = json.loads(out.read_text())

    ok = runner.invoke(app, ["pala", "consistency-verify", str(out)])
    assert ok.exit_code == 0 and "CONSISTENT: records 0..7 are a prefix of 0..39" in ok.output

    # roots held elsewhere, matching → still 0; one differing → 1 before any path check
    good = runner.invoke(
        app,
        [
            "pala",
            "consistency-verify",
            str(out),
            "--first-root",
            doc["first_root"],
            "--second-root",
            doc["second_root"].upper(),
        ],
    )
    assert good.exit_code == 0
    bad = runner.invoke(app, ["pala", "consistency-verify", str(out), "--first-root", "00" * 32])
    assert bad.exit_code == 1 and "differs from the proof's first_root" in bad.output

    # a tampered path: INCONSISTENT, not a traceback
    tampered = dict(doc)
    path = list(doc["path"])
    if path:
        path[0] = "ff" * 32
    tampered["path"] = path
    t = tmp_path / "tampered.json"
    t.write_text(json.dumps(tampered))
    r = runner.invoke(app, ["pala", "consistency-verify", str(t)])
    assert r.exit_code == 1 and "INCONSISTENT" in r.output

    # unreadable inputs: 3
    missing = runner.invoke(app, ["pala", "consistency-verify", str(tmp_path / "nope.json")])
    assert missing.exit_code == 3
    junk = tmp_path / "junk.json"
    junk.write_text("{}")
    assert runner.invoke(app, ["pala", "consistency-verify", str(junk)]).exit_code == 3


def test_consistency_rejects_counts_outside_the_chain(tmp_path):
    log = _chain(tmp_path, n=10)
    r = runner.invoke(app, ["pala", "consistency", str(log), "--first", "11"])
    assert r.exit_code == 3 and "UNREADABLE" in r.output
    r = runner.invoke(app, ["pala", "consistency", str(log), "--first", "5", "--second", "4"])
    assert r.exit_code == 3
    r = runner.invoke(app, ["pala", "consistency", str(tmp_path / "missing.pala"), "--first", "1"])
    assert r.exit_code == 3
