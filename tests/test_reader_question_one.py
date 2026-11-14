# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Question one — does this file hold together — as one answer.

The reader gave the parts (``chain.chain_ok``, ``container_check()``) and a
single ``diagnosis`` shared by all three questions, and a consumer that put
the answer together as ``chain_ok and diagnosis is None`` told its user that
a whole chain was "not whole" whenever the anchor lagged. The export, the
bundle and ``pala verify`` each had the one answer; the reader did not.
"""
from __future__ import annotations

import io
import json
import pytest
import struct
import tarfile
from hashlib import sha256
from palimpsests.audit.anchors import ManualAnchor
from palimpsests.audit.export import export_jsonl
from palimpsests.audit.pala.bundle import assemble_bundle
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy
from palimpsests.audit.reader import (
    DIAGNOSIS_QUESTIONS,
    AuditReader,
    Diagnosis,
)
from palimpsests.audit.report import build_report
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner


def _chain(tmp_path, name="w.pala"):
    p = tmp_path / name
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        early = w.head_hex
        w.model_load(b"\x11" * 32, b"\x22" * 32, role="engine.native")
        w.incident_candidate(category=1, severity=2, detail="a body to alter")
    return p, early


def _offsets(raw: bytes):
    """(header offset, header length, body length) of each record."""
    out, off = [], 0
    while off < len(raw):
        (hlen,) = struct.unpack_from("<H", raw, off + 6)
        (blen,) = struct.unpack_from("<I", raw, off + 120)
        out.append((off, hlen, blen))
        off += hlen + blen
    return out


def _cases(tmp_path):
    """name -> (path, anchor, pattern expected, consistent expected)."""
    chain, early = _chain(tmp_path)
    raw = chain.read_bytes()
    recs = _offsets(raw)

    def write(name, data):
        p = tmp_path / name
        p.write_bytes(bytes(data))
        return p

    swapped = bytearray(raw)
    off, hlen, blen = next(r for r in recs if r[2] > 4)
    swapped[off + hlen + blen - 1] ^= 1

    broken = bytearray(raw)
    broken[recs[2][0] + 24] ^= 1  # inside the third record's prev_hash

    violated = bytearray(raw)
    violated[recs[-1][0] + 11] = 9  # an undefined time-trust value

    empty = write("empty.pala", b"")
    return {
        "whole, no anchor": (chain, None, None, True),
        "whole, anchor lags": (chain, early, "unanchored_tail", True),
        "whole, anchor from elsewhere": (chain, "ab" * 32, "replaced_or_rolled_back", True),
        "body altered": (write("swapped.pala", swapped), None, None, False),
        "cut mid-record": (write("torn.pala", raw[:-7]), None, "truncated_tail", False),
        "not a container": (write("junk.pala", b"plain text, no chain"), None,
                            "not_a_container", False),
        "link broken": (write("broken.pala", broken), None, "chain_break", False),
        "a MUST violated": (write("violated.pala", violated), None, "record_violation", False),
        "starts after the beginning": (write("tail.pala", raw[recs[1][0]:]), None,
                                       "prefix_absent", False),
        "empty": (empty, None, "empty_container", True),
        "empty, an anchor says otherwise": (empty, "ab" * 32, "replaced_or_rolled_back", True),
    }


def test_question_one_is_what_it_says_for_every_kind_of_file(tmp_path):
    for name, (path, anchor, pattern, consistent) in _cases(tmp_path).items():
        with AuditReader.open(path, anchor=ManualAnchor(anchor) if anchor else None) as r:
            ver = r.verify()
            assert (ver.diagnosis.pattern if ver.diagnosis else None) == pattern, name
            assert r.is_consistent() is consistent, name


def test_a_diagnosis_about_the_anchor_is_not_a_finding_about_the_chain(tmp_path):
    """The mistake this file exists for, pinned from our side."""
    chain, early = _chain(tmp_path)
    with AuditReader.open(chain, anchor=ManualAnchor(early)) as r:
        ver = r.verify()
        assert ver.diagnosis is not None and ver.diagnosis.question == "completeness"
        assert ver.complete_to_anchor is False and ver.anchor_lag == 2
        assert r.is_consistent() is True


def test_no_diagnosis_does_not_mean_consistent(tmp_path):
    path, _anchor, _pattern, _consistent = _cases(tmp_path)["body altered"]
    with AuditReader.open(path) as r:
        assert r.verify().diagnosis is None and r.verify().chain.chain_ok is True
        assert r.is_consistent() is False


def test_the_question_of_a_pattern_agrees_with_the_facts(tmp_path):
    """Not a table to take on trust: for every case here, a pattern said to be
    about consistency sits on an inconsistent file, and one about
    completeness on a consistent file whose anchor is missed."""
    seen = set()
    for name, (path, anchor, pattern, _c) in _cases(tmp_path).items():
        if pattern is None:
            continue
        with AuditReader.open(path, anchor=ManualAnchor(anchor) if anchor else None) as r:
            diagnosis = r.verify().diagnosis
            assert diagnosis.question == DIAGNOSIS_QUESTIONS[pattern], name
            if diagnosis.question == "consistency":
                assert r.is_consistent() is False, name
            elif diagnosis.question == "completeness":
                assert r.is_consistent() is True, name
                assert r.verify().complete_to_anchor is False, name
            else:
                assert pattern == "empty_container" and r.record_count == 0
        seen.add(pattern)
    # the two continuation patterns need a rotated chain
    base = tmp_path / "rot" / "w.pala"
    base.parent.mkdir()
    w = PalaWriter(base, rotation=RotationPolicy(max_records=4, retention_s=15_552_000))
    w.genesis()
    for _ in range(9):
        w.prefix_warm(token_count=1)
    w.close()
    later = sorted(base.parent.glob("w.pala.0*"))[0]
    with AuditReader.open(later) as r:
        d = r.verify().diagnosis
        assert d.pattern == "declared_continuation" and d.question == "consistency"
        assert r.is_consistent() is False  # a file that starts mid-chain
    mf = base.parent / "w.pala.segments.json"
    doc = json.loads(mf.read_text())
    doc["segments"][0]["head"] = "ab" * 32
    mf.write_text(json.dumps(doc))
    with AuditReader.open(later) as r:
        d = r.verify().diagnosis
        assert d.pattern == "continuation_contradicts_manifest"
        assert d.question == "consistency" and r.is_consistent() is False
    seen |= {"declared_continuation", "continuation_contradicts_manifest"}
    # seq_gap is the one pattern no case here builds
    assert set(DIAGNOSIS_QUESTIONS) - seen == {"seq_gap"}


def test_a_pattern_this_build_does_not_know_has_no_question():
    assert Diagnosis("from_a_later_release", None, None, "…").question is None


def test_four_tools_give_one_answer(tmp_path):
    """The reader, ``pala verify``, the export and the bundle."""
    for name, (path, _anchor, _pattern, consistent) in _cases(tmp_path).items():
        cli = json.loads(CliRunner().invoke(
            app, ["pala", "verify", str(path), "--json"]).output)
        out = io.StringIO()
        export_jsonl(path.read_bytes(), out)
        summary = json.loads(out.getvalue().splitlines()[-1])
        assemble_bundle(path, tmp_path / "b.tar")
        with tarfile.open(tmp_path / "b.tar") as tar:
            bundle = json.loads(tar.extractfile("verification.json").read())
        with AuditReader.open(path) as r:
            answers = (r.is_consistent(), cli["consistency"]["ok"],
                       summary["consistent"], bundle["consistent"])
        assert answers == (consistent,) * 4, (name, answers)


# ── the report ──────────────────────────────────────────────────────────────


def test_the_report_says_which_question_its_diagnosis_is_about(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).resolve().parent.parent / "docs" / "specs" / "report"
         / "pala-verification-report-2.schema.json").read_text(encoding="utf-8"))
    for name, (path, anchor, pattern, _c) in _cases(tmp_path).items():
        data = build_report(
            path, anchor_source=ManualAnchor(anchor) if anchor else None).data
        jsonschema.validate(data, schema)
        if pattern is None:
            assert data["diagnosis"] is None, name
        else:
            assert data["diagnosis"]["question"] == DIAGNOSIS_QUESTIONS[pattern], name


def test_the_report_does_not_read_the_file_a_second_time(tmp_path, monkeypatch):
    """Without a reader it read the whole file into memory and then mapped it
    as well. The digest and the size now come from the one mapping."""
    chain, early = _chain(tmp_path)
    expected = (sha256(chain.read_bytes()).hexdigest(), chain.stat().st_size)

    def refuse(self, *a, **k):
        raise AssertionError(f"the report read {self.name} whole")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    for anchor in (None, ManualAnchor(early)):
        subject = build_report(chain, anchor_source=anchor).data["subject"]
        assert (subject["sha256"], subject["bytes"]) == expected
    with AuditReader.open(chain) as r:
        subject = build_report(chain, reader=r).data["subject"]
        assert (subject["sha256"], subject["bytes"]) == expected


def test_the_report_of_an_empty_file_still_names_its_bytes(tmp_path):
    p = tmp_path / "e.pala"
    p.write_bytes(b"")
    subject = build_report(p).data["subject"]
    assert subject["sha256"] == sha256(b"").hexdigest() and subject["bytes"] == 0
