# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U8: the bundle re-verifies from its own contents — with no assembler code.

The second test is the acceptance the plan wrote (E-02 in spirit): unpack
the tar and reproduce every claim using spec-level operations only —
sha256, verify_headers, verify_proof — never the bundle module.
"""
from __future__ import annotations

import json
import tarfile
from hashlib import sha256
from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.bundle import assemble_bundle
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala.merkle import verify_proof
from palimpsests.audit.pala_writer import PalaWriter


def _chain(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()  # 0
    for _ in range(3):
        w.prefix_warm(token_count=5)  # 1..3
    merkle_checkpoint(w)  # 4 covers [0,3]
    w.prefix_warm(token_count=5)  # 5 tail
    w.close()
    return log


def test_assemble_reports_the_honest_split(tmp_path):
    log = _chain(tmp_path)
    res = assemble_bundle(log, tmp_path / "b.tar")
    assert res.chain_ok is True
    assert res.records == 6
    # unproven: the final checkpoint itself (per #163) and the tail
    assert res.proven == 4


def test_bundle_reverifies_without_assembler_code(tmp_path):
    log = _chain(tmp_path)
    out = tmp_path / "b.tar"
    assemble_bundle(log, out)

    with tarfile.open(out) as tar:
        member = {
            m.name: tar.extractfile(m).read() for m in tar.getmembers()
        }
    manifest = json.loads(member["MANIFEST.json"])

    # 1. every member digest in the manifest reproduces
    for name, meta in manifest["members"].items():
        assert sha256(member[name]).hexdigest() == meta["sha256"], name

    # 2. the records member chain-verifies and lands on the manifest head
    headers = [hb for hb, _ in iter_records(member["records.pala"])]
    result = verify_headers(headers)
    assert result.chain_ok is True
    assert result.head.hex() == manifest["source_head"]

    # 3. every non-null proof verifies against its chain-carried root
    proofs = json.loads(member["proofs.json"])["proofs"]
    checked = 0
    for _seq, p in proofs.items():
        if p is None:
            continue
        path = [(side, bytes.fromhex(h)) for side, h in p["path"]]
        assert verify_proof(
            bytes.fromhex(p["leaf"]), path, bytes.fromhex(p["root"])
        )
        checked += 1
    assert checked == 4

    # 4. time claims restate the headers exactly, trust by name
    claims = json.loads(member["time-claims.json"])["claims"]
    assert [c["seq"] for c in claims] == list(range(6))
    assert all(c["time_trust_name"] is not None for c in claims)


def test_deterministic_and_range_scoped(tmp_path):
    log = _chain(tmp_path)
    a, b = tmp_path / "a.tar", tmp_path / "b.tar"
    assemble_bundle(log, a)
    assemble_bundle(log, b)
    assert a.read_bytes() == b.read_bytes()  # same inputs, same bytes

    scoped = tmp_path / "r.tar"
    res = assemble_bundle(log, scoped, from_seq=2, to_seq=4)
    assert res.records == 3
    with tarfile.open(scoped) as tar:
        recs = tar.extractfile("records.pala").read()
    assert len(list(iter_records(recs))) == 3


def test_cli_bundle_command(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    log = _chain(tmp_path)
    out = tmp_path / "cli.tar"
    result = CliRunner().invoke(app, ["pala", "bundle", str(log), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "6 record(s) (4 with inclusion proofs)" in result.output
    assert out.exists()
