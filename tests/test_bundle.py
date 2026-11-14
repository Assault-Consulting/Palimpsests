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


# ── what the bundle says about a log that does not hold together ───────────
#
# Until 0.15 ``verification.json`` carried the header chain's answer and
# nothing about bodies or the container: a body altered after writing was
# bundled under ``chain_ok: true`` with no mark, and a file cut mid-record
# made the assembler raise instead of bundling what was whole.


def _members(path):
    with tarfile.open(path) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers()}


def _verification(path):
    return json.loads(_members(path)["verification.json"])


def _altered(tmp_path):
    """One byte inside a body flipped: headers untouched, chain still links."""
    log = _chain(tmp_path)
    raw = bytearray(log.read_bytes())
    offset, target, seq = 0, None, None
    for hb, body in iter_records(bytes(raw)):
        if body and target is None:
            target = offset + len(hb) + len(body) - 1
            seq = int.from_bytes(hb[12:20], "little")
        offset += len(hb) + len(body)
    raw[target] ^= 0x01
    out = tmp_path / "altered.pala"
    out.write_bytes(bytes(raw))
    return out, seq


def test_a_body_altered_after_writing_is_bundled_and_marked(tmp_path):
    log, seq = _altered(tmp_path)
    res = assemble_bundle(log, tmp_path / "b.tar")
    ver = _verification(tmp_path / "b.tar")
    assert ver["chain_ok"] is True  # the headers still chain: that is the trap
    assert ver["container"]["body_digest_mismatches"] == [seq]
    assert ver["consistent"] is False and res.consistent is False
    assert res.records == 6  # the evidence is all there, for inspection


def test_a_container_cut_mid_record_bundles_what_is_whole(tmp_path):
    log = _chain(tmp_path)
    cut = tmp_path / "cut.pala"
    cut.write_bytes(log.read_bytes()[:-11])
    res = assemble_bundle(cut, tmp_path / "b.tar")
    members = _members(tmp_path / "b.tar")
    ver = json.loads(members["verification.json"])
    assert res.records == 5 and len(list(iter_records(members["records.pala"]))) == 5
    assert ver["container"]["well_formed"] is False
    assert "cut short" in ver["container"]["malformed"]
    assert ver["container"]["bytes_parsed"] == len(members["records.pala"])
    assert ver["container"]["bytes_parsed"] < ver["container"]["bytes_total"]
    assert ver["consistent"] is False and res.consistent is False


def test_bytes_that_are_no_container_bundle_as_nothing_and_say_so(tmp_path):
    junk = tmp_path / "junk.pala"
    junk.write_bytes(b"not a container at all")
    res = assemble_bundle(junk, tmp_path / "b.tar")
    ver = _verification(tmp_path / "b.tar")
    assert res.records == 0 and res.consistent is False
    assert ver["container"]["well_formed"] is False and ver["container"]["bytes_parsed"] == 0


def test_the_bundle_the_report_and_pala_verify_agree_on_consistency(tmp_path):
    from palimpsests.audit.report import build_report
    from palimpsests.cli import app
    from typer.testing import CliRunner

    altered, _seq = _altered(tmp_path)
    cut = tmp_path / "cut.pala"
    cut.write_bytes((tmp_path / "w.pala").read_bytes()[:-11])
    for log in (tmp_path / "w.pala", altered, cut):
        assemble_bundle(log, tmp_path / "b.tar")
        ver = _verification(tmp_path / "b.tar")
        report = build_report(log).data
        assert ver["container"] == report["container"], log.name
        cli = json.loads(
            CliRunner().invoke(app, ["pala", "verify", str(log), "--json"]).output
        )
        assert ver["consistent"] == cli["consistency"]["ok"], log.name
        assert ver["consistent"] == (report["verdict"] != "violation"), log.name


def test_violations_carry_their_codes(tmp_path):
    log = _chain(tmp_path)
    raw = bytearray(log.read_bytes())
    offset = 0
    for hb, body in iter_records(bytes(raw)):
        last = offset
        offset += len(hb) + len(body)
    raw[last + 11] = 9  # the last record's time-trust byte: an undefined value
    bad = tmp_path / "v.pala"
    bad.write_bytes(bytes(raw))
    assemble_bundle(bad, tmp_path / "b.tar")
    ver = _verification(tmp_path / "b.tar")
    assert ver["violations"] and len(ver["violation_codes"]) == len(ver["violations"])
    assert [c for _s, c in ver["violation_codes"]] == ["time_trust_undefined"]
    assert ver["consistent"] is False


def test_the_keys_of_pala_bundle_1_are_kept(tmp_path):
    """The format is open: keys are added, never removed or renamed. These are
    the keys a 0.10 – 0.14 bundle had; each must still be there."""
    assemble_bundle(_chain(tmp_path), tmp_path / "b.tar")
    members = _members(tmp_path / "b.tar")
    assert list(members) == [
        "records.pala", "proofs.json", "verification.json", "time-claims.json",
        "MANIFEST.json",
    ]
    manifest = json.loads(members["MANIFEST.json"])
    assert manifest["format"] == "pala-bundle/1"
    assert {"format", "tool", "source_head", "range", "members"} <= manifest.keys()
    assert {"from_seq", "to_seq", "records"} <= manifest["range"].keys()
    ver = json.loads(members["verification.json"])
    assert {
        "chain_ok", "records", "head", "breaks", "gaps", "violations", "uninterpretable",
        "completeness", "anchor", "anchor_attempts", "advisory",
    } <= ver.keys()
    assert {"checked", "ok", "anchor_lag"} <= ver["completeness"].keys()
    claim = json.loads(members["time-claims.json"])["claims"][0]
    assert {"seq", "monotonic_ns", "wall_clock_ns", "time_trust", "time_trust_name"} <= claim.keys()
    proof = next(p for p in json.loads(members["proofs.json"])["proofs"].values() if p)
    assert {"leaf", "path", "root", "root_seq"} <= proof.keys()


def test_the_cli_does_not_call_an_altered_log_sound(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    altered, _seq = _altered(tmp_path)
    res = CliRunner().invoke(app, ["pala", "bundle", str(altered), "-o", str(tmp_path / "b.tar")])
    assert res.exit_code == 0  # assembling broken evidence is not a failure
    assert "BROKEN" in res.output and "holds" not in res.output
    ok = CliRunner().invoke(
        app, ["pala", "bundle", str(tmp_path / "w.pala"), "-o", str(tmp_path / "c.tar")]
    )
    assert "consistency inside: holds" in ok.output and "sound" not in ok.output


def test_the_cli_bundles_a_torn_file_without_a_traceback(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    log = _chain(tmp_path)
    cut = tmp_path / "cut.pala"
    cut.write_bytes(log.read_bytes()[:-11])
    res = CliRunner().invoke(app, ["pala", "bundle", str(cut), "-o", str(tmp_path / "b.tar")])
    assert res.exit_code == 0 and res.exception is None, res.output
    assert "bundled 5 record(s)" in res.output and "BROKEN" in res.output
