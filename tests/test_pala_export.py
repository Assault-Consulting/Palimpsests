# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The pala2json exporter (WS4): derived, deterministic, never gating.

The properties under test are the spec's (§1.1): the export is a tool
outside the hashing contract — so it must name every record by seq and
record_hash (the way back to the authoritative bytes), byte-reproduce
from the same container, say "derived" out loud in its summary, and
export a damaged chain as readily as a green one.
"""
from __future__ import annotations

import io
import json
from palimpsests.audit.export import export_jsonl
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala.codec import record_hash
from palimpsests.audit.pala_writer import (
    CAT_GUARD_ESCALATION,
    DISP_ACKNOWLEDGED,
    PalaWriter,
)
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

runner = CliRunner()
OPERATOR = bytes.fromhex("0e5a70120e5a70120e5a70120e5a7012")
VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _vectors_blob() -> tuple[bytes, dict]:
    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    return blob, v


def test_export_is_deterministic_and_matches_the_published_chain():
    blob, v = _vectors_blob()
    a, b = io.StringIO(), io.StringIO()
    assert export_jsonl(blob, a) == export_jsonl(blob, b) == 8
    assert a.getvalue() == b.getvalue()  # same bytes in, same bytes out

    lines = [json.loads(line) for line in a.getvalue().splitlines()]
    assert len(lines) == 9  # 8 records + 1 summary
    summary = lines[-1]
    assert summary["summary"] is True and summary["format"] == "pala-jsonl/1"
    assert summary["chain_head"] == v["chain_head"]
    assert summary["chain_ok"] is True and summary["records"] == 8
    assert "authoritative" in summary["note"]  # derived, said out loud


def test_every_line_names_its_record_by_seq_and_hash():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    export_jsonl(blob, out)
    lines = [json.loads(line) for line in out.getvalue().splitlines()][:-1]
    truth = {}
    for hb, _body in iter_records(blob):
        import struct

        (seq,) = struct.unpack_from("<Q", hb, 12)
        truth[seq] = record_hash(hb).hex()
    for line in lines:
        assert line["record_hash"] == truth[line["seq"]]


def test_r2_semantics_and_encryption_render_correctly():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    export_jsonl(blob, out)
    by_seq = {
        line["seq"]: line
        for line in (json.loads(x) for x in out.getvalue().splitlines())
        if "summary" not in line
    }
    assert by_seq[4]["kind_name"] == "INCIDENT_CANDIDATE"
    assert by_seq[5]["kind_name"] == "OVERSIGHT_ACK"
    # the encrypted deployment-content body: present, opaque, never decoded
    assert by_seq[3]["key_id"] == 9
    assert by_seq[3].get("body_opaque") is True
    assert "body_tlvs" not in by_seq[3]
    # the KEY_SHRED body exports its §8 TLVs (cleartext by MUST)
    tags = {t["tag"] for t in by_seq[6]["body_tlvs"]}
    assert {"0x0001", "0x0002", "0x0003"} <= tags


def test_a_damaged_chain_exports_with_the_damage_reported(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(CAT_GUARD_ESCALATION, 2)
        w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
    data = bytearray(log.read_bytes())
    data[40] ^= 0xFF  # flip a byte in GENESIS: the chain breaks at seq 1
    out = io.StringIO()
    export_jsonl(bytes(data), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    summary = lines[-1]
    assert summary["chain_ok"] is False and summary["breaks"] == [1]
    assert len(lines) == 5  # every record still exported — evidence, shown


def test_cli_export_writes_the_file_and_exits_zero(tmp_path):
    blob, v = _vectors_blob()
    src = tmp_path / "chain.pala"
    src.write_bytes(blob)
    dst = tmp_path / "chain.jsonl"
    result = runner.invoke(app, ["pala", "export", str(src), "-o", str(dst)])
    assert result.exit_code == 0
    lines = dst.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 9
    assert json.loads(lines[-1])["chain_head"] == v["chain_head"]


def test_cli_export_unreadable_file_exits_three(tmp_path):
    result = runner.invoke(app, ["pala", "export", str(tmp_path / "missing.pala")])
    assert result.exit_code == 3
