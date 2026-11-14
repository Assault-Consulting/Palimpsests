# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A container with no records is diagnosed as such (U26, clarification C-8).

The verifier's answer is not changed — §7.1 holds vacuously on zero records,
and the core is frozen — but the diagnosis says what the "pass" means, and
since report format ``/2`` the report's verdict does too: ``empty``.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.reader import AuditReader
from pathlib import Path


def test_an_empty_file_is_diagnosed_and_its_verdict_is_unchanged(tmp_path):
    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    with AuditReader.open(p) as r:
        v = r.verify()
    assert v.chain.chain_ok is True and v.chain.count == 0  # unchanged: vacuous
    assert v.diagnosis.pattern == "empty_container"
    assert v.diagnosis.at_seq is None and v.diagnosis.code is None


def test_from_bytes_agrees():
    with AuditReader.from_bytes(b"") as r:
        assert r.verify().diagnosis.pattern == "empty_container"


def test_a_cut_first_record_is_still_a_truncated_tail(tmp_path):
    """Bytes that begin a record are not an empty container."""
    with AuditReader.from_bytes(b"PALA"[:3]) as r:
        assert r.verify().diagnosis.pattern == "truncated_tail"


def test_the_report_carries_it_with_its_own_verdict(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from palimpsests.audit.report import build_report

    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    data = build_report(p).data
    assert data["verdict"] == "empty"  # /2; a /1 report said "partial" here
    assert data["diagnosis"]["pattern"] == "empty_container"
    schema_path = (Path(__file__).resolve().parent.parent / "docs" / "specs" / "report"
                   / "pala-verification-report-2.schema.json")
    jsonschema.validate(data, json.loads(schema_path.read_text(encoding="utf-8")))


def test_an_anchored_empty_file_is_a_missing_log_not_a_vacuous_pass(tmp_path):
    """An anchor proves a log existed. An empty file in its place is that log
    gone: the verdict is a violation, and the diagnosis must not say the
    check passed because there was nothing to check."""
    from palimpsests.audit.anchors import ManualAnchor
    from palimpsests.audit.report import build_report

    p = tmp_path / "audit.pala"
    p.write_bytes(b"")
    with AuditReader.open(p, anchor=ManualAnchor("11" * 32)) as r:
        ver = r.verify()
        assert ver.complete_to_anchor is False
        assert ver.diagnosis.pattern == "replaced_or_rolled_back"
        assert "deleted or replaced" in ver.diagnosis.narrative
        assert "nothing to check" not in ver.diagnosis.narrative
        report = build_report(str(p), reader=r).data
    assert report["verdict"] == "violation"
    assert report["diagnosis"]["pattern"] == "replaced_or_rolled_back"
