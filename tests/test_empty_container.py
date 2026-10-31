# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A container with no records is diagnosed as such (U26, clarification C-8).

The verdict is not changed — §7.1 holds vacuously on zero records, and the
core is frozen — but the diagnosis says what the "pass" means.
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


def test_the_report_carries_it_and_still_validates_as_v1(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from palimpsests.audit.report import build_report

    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    data = build_report(p).data
    assert data["verdict"] == "partial"  # the report's verdict rule is unchanged
    assert data["diagnosis"]["pattern"] == "empty_container"
    schema_path = (Path(__file__).resolve().parent.parent / "docs" / "specs" / "report"
                   / "pala-verification-report-1.schema.json")
    jsonschema.validate(data, json.loads(schema_path.read_text(encoding="utf-8")))
