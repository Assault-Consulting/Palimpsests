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
    published = len(v["records"])  # the vectors file is self-describing;
    # it grows additively across profile revisions, and this test pins the
    # relationship (export count == published chain), not a revision's size
    a, b = io.StringIO(), io.StringIO()
    assert export_jsonl(blob, a) == export_jsonl(blob, b) == published
    assert a.getvalue() == b.getvalue()  # same bytes in, same bytes out

    lines = [json.loads(line) for line in a.getvalue().splitlines()]
    assert len(lines) == published + 1  # every record + 1 summary
    summary = lines[-1]
    assert summary["summary"] is True and summary["format"] == "pala-jsonl/1"
    assert summary["chain_head"] == v["chain_head"]
    assert summary["chain_ok"] is True and summary["records"] == published
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
    assert len(lines) == len(v["records"]) + 1
    assert json.loads(lines[-1])["chain_head"] == v["chain_head"]


def test_cli_export_unreadable_file_exits_three(tmp_path):
    result = runner.invoke(app, ["pala", "export", str(tmp_path / "missing.pala")])
    assert result.exit_code == 3


# ── seq-range tests ──────────────────────────────────────────────────


def test_from_seq_inclusive_lower_bound():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    count = export_jsonl(blob, out, from_seq=3)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    records = [line for line in lines if "summary" not in line]
    assert len(records) == count
    assert all(r["seq"] >= 3 for r in records)
    assert records[0]["seq"] == 3  # inclusive


def test_to_seq_inclusive_upper_bound():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    count = export_jsonl(blob, out, to_seq=4)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    records = [line for line in lines if "summary" not in line]
    assert len(records) == count
    assert all(r["seq"] <= 4 for r in records)
    assert records[-1]["seq"] == 4  # inclusive


def test_from_seq_and_to_seq_range():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    count = export_jsonl(blob, out, from_seq=2, to_seq=5)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    records = [line for line in lines if "summary" not in line]
    assert len(records) == count
    assert [r["seq"] for r in records] == [2, 3, 4, 5]


def test_range_empty_when_no_records_match():
    blob, v = _vectors_blob()
    out = io.StringIO()
    count = export_jsonl(blob, out, from_seq=1000, to_seq=2000)
    assert count == 0
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    records = [line for line in lines if "summary" not in line]
    assert records == []
    summary = lines[-1]
    assert summary["summary"] is True
    assert summary["records"] == len(v["records"])  # full chain count still reported


def test_range_summary_includes_bounds():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    export_jsonl(blob, out, from_seq=2, to_seq=5)
    summary = [json.loads(line) for line in out.getvalue().splitlines()][-1]
    assert summary["from_seq"] == 2
    assert summary["to_seq"] == 5


def test_no_range_summary_omits_bounds():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    export_jsonl(blob, out)
    summary = [json.loads(line) for line in out.getvalue().splitlines()][-1]
    assert "from_seq" not in summary
    assert "to_seq" not in summary


def test_range_still_carries_record_hash_and_header_fields():
    blob, _ = _vectors_blob()
    out = io.StringIO()
    export_jsonl(blob, out, from_seq=3, to_seq=5)
    records = [
        json.loads(line)
        for line in out.getvalue().splitlines()
        if "summary" not in json.loads(line)
    ]
    for r in records:
        assert "record_hash" in r
        assert "seq" in r
        if r.get("header_undecoded") is not True:
            assert "boot_id" in r
            assert "header_tlvs" in r


def test_cli_export_with_range_flags(tmp_path):
    blob, v = _vectors_blob()
    src = tmp_path / "chain.pala"
    src.write_bytes(blob)
    dst = tmp_path / "filtered.jsonl"
    result = runner.invoke(
        app, ["pala", "export", str(src), "-o", str(dst), "--from-seq", "2", "--to-seq", "5"]
    )
    assert result.exit_code == 0
    lines = dst.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines if "summary" not in json.loads(line)]
    assert [r["seq"] for r in records] == [2, 3, 4, 5]


# ── 0.14.1: the export declared public — what it must hold first ─────────────
#
# Asked by Auditor (its R9) to be declared; checked before it was. Four things
# were found by running it, and are held here: a container cut mid-record made
# it raise, a body altered after writing was printed without a word under
# ``chain_ok``, it kept every decoded record in memory, and a consumer had to
# read a TLV's hex to learn a tool's outcome.


def _tool_chain(path, *, pairs=2):
    from palimpsests.audit.pala_writer import OUTCOME_ERROR, OUTCOME_UNOBSERVED

    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        for outcome in (OUTCOME_UNOBSERVED, OUTCOME_ERROR)[:pairs]:
            seq, call_hash = w.tool_call("read", return_seq=True)
            w.tool_result(seq, call_hash, outcome)
        cand = w.incident_candidate(CAT_GUARD_ESCALATION, 2)
        w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
        w.guard_state_reject(detail="restore failed: frame 7")
    return path.read_bytes()


def _export(data, **kw):
    out = io.StringIO()
    count = export_jsonl(data, out, **kw)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    return count, lines[:-1], lines[-1]


def _body_altered(data: bytes) -> bytes:
    """Change bytes inside a cleartext body; its header is left as written."""
    i = data.rindex(b"restore failed")
    return data[:i] + b"RESTORE failed" + data[i + 14:]


def test_a_container_cut_mid_record_exports_what_is_whole_and_says_where_it_stopped(tmp_path):
    """A writer caught mid-write, or a crash: the commonest damage there is."""
    data = _tool_chain(tmp_path / "a.pala")
    whole, _, _ = _export(data)
    count, lines, summary = _export(data[:-20])
    assert count == whole - 1 and len(lines) == count  # every whole record, exported
    assert summary["well_formed"] is False and "cut short" in summary["malformed"]
    assert summary["bytes_parsed"] < summary["bytes_total"] == len(data) - 20
    assert summary["records"] == count and summary["consistent"] is False


def test_bytes_that_are_no_container_export_nothing_and_say_so():
    count, lines, summary = _export(b"not a pala file at all")
    assert count == 0 and lines == []
    assert summary["well_formed"] is False and summary["consistent"] is False
    assert summary["bytes_parsed"] == 0


def test_cli_export_of_a_torn_file_exits_zero_with_the_whole_records(tmp_path):
    src = tmp_path / "torn.pala"
    src.write_bytes(_tool_chain(tmp_path / "a.pala")[:-20])
    dst = tmp_path / "torn.jsonl"
    result = runner.invoke(app, ["pala", "export", str(src), "-o", str(dst)])
    assert result.exit_code == 0 and result.exception is None
    assert json.loads(dst.read_text(encoding="utf-8").splitlines()[-1])["well_formed"] is False


def test_a_body_altered_after_writing_is_shown_and_marked(tmp_path):
    """record_hash is over the header; the header binds the body by its digest.
    A body that no longer matches is exported — and its line says that what
    it shows is not what its hash covers."""
    data = _tool_chain(tmp_path / "a.pala")
    _, lines, summary = _export(_body_altered(data))
    marked = [ln for ln in lines if ln.get("body_digest_mismatch")]
    assert len(marked) == 1 and marked[0]["detail"] == "RESTORE failed: frame 7"
    assert summary["body_digest_mismatches"] == [marked[0]["seq"]]
    assert summary["chain_ok"] is True  # the header chain is intact: unchanged meaning
    assert summary["consistent"] is False
    _, clean_lines, clean = _export(data)
    assert not any("body_digest_mismatch" in ln for ln in clean_lines)
    assert clean["body_digest_mismatches"] == [] and clean["consistent"] is True


def test_the_export_and_pala_verify_agree_on_consistency(tmp_path):
    """One rule, two tools: the summary's ``consistent`` is `pala verify`'s."""
    data = _tool_chain(tmp_path / "a.pala")
    broken = bytearray(data)
    broken[40] ^= 0xFF
    cases = {"sound": data, "body altered": _body_altered(data), "torn": data[:-20],
             "chain break": bytes(broken), "empty": b""}
    for name, blob in cases.items():
        src = tmp_path / "case.pala"
        src.write_bytes(blob)
        verify = json.loads(runner.invoke(app, ["pala", "verify", str(src), "--json"]).stdout)
        assert _export(blob)[2]["consistent"] is verify["consistency"]["ok"], name


def test_a_line_carries_what_the_reader_decodes(tmp_path):
    """outcome, disposition, operator and detail on the line equal the
    reader's — a consumer never reads a TLV's hex to learn a tool's outcome."""
    from palimpsests.audit.reader import AuditReader

    for data in (_tool_chain(tmp_path / "a.pala"), _vectors_blob()[0]):
        _, lines, _ = _export(data)
        with AuditReader.from_bytes(data) as reader:
            for i, line in enumerate(lines):
                dr = reader.record_at(i)
                for key in ("kind", "kind_name"):
                    assert line[key] == getattr(dr, key), (i, key)
                for key in ("source", "source_name", "outcome", "outcome_name",
                            "disposition", "disposition_name", "detail"):
                    assert line.get(key) == getattr(dr, key), (i, key)
                    assert (key in line) is (getattr(dr, key) is not None), (i, key)
                assert line.get("operator_id") == (dr.operator_id.hex() if dr.operator_id
                                                   else None), i
    names = {ln["outcome_name"] for ln in _export(_tool_chain(tmp_path / "b.pala"))[1]
             if "outcome_name" in ln}
    assert names == {"unobserved", "error"}


def test_the_summary_carries_codes_beside_the_sentences(tmp_path):
    data = _tool_chain(tmp_path / "a.pala")
    _, _, summary = _export(data[data.index(b"PALA", 4):])  # the chain without its GENESIS
    assert summary["violations"] and len(summary["violation_codes"]) == len(summary["violations"])
    assert [0, "prefix_absent"] in summary["violation_codes"]
    assert [s for s, _ in summary["violation_codes"]] == [s for s, _ in summary["violations"]]


def test_completeness_is_never_claimed_and_an_empty_file_is_vacuous():
    _, lines, summary = _export(b"")
    assert lines == [] and summary["records"] == 0
    # nothing there to contradict (clarification C-8) — and nothing said about completeness
    assert summary["well_formed"] is True and summary["consistent"] is True
    assert summary["completeness_checked"] is False


def test_a_mapped_file_exports_as_its_bytes_do(tmp_path):
    import mmap

    path = tmp_path / "a.pala"
    data = _tool_chain(path)
    a, b = io.StringIO(), io.StringIO()
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert export_jsonl(mm, a) == export_jsonl(data, b)
    assert a.getvalue() == b.getvalue()


LINE_KEYS = {"seq", "record_hash", "record_type", "type_name", "kind", "kind_name", "body_len"}
HEADER_KEYS = {"boot_id", "span_id", "parent_span_id", "assurance_tier", "time_trust",
               "monotonic_ns", "wall_clock_ns", "key_id", "header_tlvs"}
SUMMARY_KEYS = {"summary", "format", "records", "chain_head", "chain_ok", "breaks", "gaps",
                "violations", "violation_codes", "well_formed", "malformed", "bytes_parsed",
                "bytes_total", "body_digest_mismatches", "consistent", "completeness_checked",
                "source_sha256", "tool", "note"}


def test_the_keys_of_pala_jsonl_1_are_kept(tmp_path):
    """The format is open: a release may add a key, never remove or rename one.
    These are the keys a consumer may rely on (docs/specs/export/pala-jsonl-1.md)."""
    import palimpsests.audit.export as export

    assert export.__all__ == ["FORMAT", "export_jsonl"] and export.FORMAT == "pala-jsonl/1"
    _, lines, summary = _export(_tool_chain(tmp_path / "a.pala"))
    for line in lines:
        assert LINE_KEYS | HEADER_KEYS <= set(line), line["seq"]
    assert SUMMARY_KEYS <= set(summary)
    assert set(_export(b"", from_seq=1, to_seq=2)[2]) - SUMMARY_KEYS == {"from_seq", "to_seq"}


def test_memory_does_not_grow_with_the_decoded_chain(tmp_path):
    """The export reads, writes and forgets one record at a time. Before 0.14.1
    it kept every decoded record: 1,804 B of Python heap per record against
    74 after, measured on 20,002 records. A tripwire, not a benchmark."""
    import tracemalloc
    from palimpsests.audit.pala_writer import OUTCOME_OK

    path = tmp_path / "long.pala"
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        for _ in range(2500):
            seq, call_hash = w.tool_call("read", return_seq=True)
            w.tool_result(seq, call_hash, OUTCOME_OK)
    data = path.read_bytes()

    class Sink:
        def write(self, text):
            pass

    tracemalloc.start()
    try:
        count = export_jsonl(data, Sink())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert count == 5002 and peak / count < 512, f"{peak / count:.0f} B/record"
