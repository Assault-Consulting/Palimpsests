# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""`pala report` — the attestation document from the CLI, both renderings.

The command is deliberately not a gate: exit 0 whenever a report was
produced, whatever it attests; the verdict lives inside. Both the JSON
and the HTML diff to a single checked-at line across two runs of the
same file.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.cli import app
from typer.testing import CliRunner

runner = CliRunner()


def _chain(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    w.prefix_warm(token_count=3)
    w.close()
    return log


def test_json_report_produced_schema_valid_and_partial_without_anchor(tmp_path):
    log = _chain(tmp_path)
    res = runner.invoke(app, ["pala", "report", str(log)])
    assert res.exit_code == 0, res.output
    report = json.loads(res.output)
    assert report["format"] == "pala-verification-report/1"
    assert report["verdict"] == "partial"  # no anchor -> honesty, not success
    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "docs" / "specs" / "report" / "pala-verification-report-1.schema.json"
    )
    jsonschema.validate(report, json.loads(schema_path.read_text()))


def test_two_json_runs_diff_only_in_checked_at(tmp_path):
    log = _chain(tmp_path)
    a = runner.invoke(app, ["pala", "report", str(log)]).output.splitlines()
    b = runner.invoke(app, ["pala", "report", str(log)]).output.splitlines()
    diff = [(x, y) for x, y in zip(a, b, strict=True) if x != y]
    assert len(a) == len(b) and len(diff) == 1, diff
    assert "wall_ns" in diff[0][0]


def test_anchor_flows_into_the_verdict_but_never_the_exit_code(tmp_path):
    log = _chain(tmp_path)
    head = json.loads(
        runner.invoke(app, ["pala", "report", str(log)]).output
    )["chain"]["head"]

    good = runner.invoke(app, ["pala", "report", str(log), "--anchor", head])
    assert good.exit_code == 0
    assert json.loads(good.output)["verdict"] == "sound"

    wrong = runner.invoke(
        app, ["pala", "report", str(log), "--anchor", "11" * 32]
    )
    assert wrong.exit_code == 0  # a report of a violation is still a report
    assert json.loads(wrong.output)["verdict"] == "violation"

    bad_hex = runner.invoke(
        app, ["pala", "report", str(log), "--anchor", "zz"]
    )
    assert bad_hex.exit_code == 3  # malformed input, not a verdict


def test_html_page_is_selfcontained_and_keeps_the_wording_discipline(tmp_path):
    log = _chain(tmp_path)
    res = runner.invoke(app, ["pala", "report", str(log), "--html"])
    assert res.exit_code == 0
    page = res.output
    assert page.startswith("<!DOCTYPE html>")
    assert "PARTIAL" in page and "pala-verification-report/1" in page
    assert "<script" not in page and "http" not in page  # self-contained
    lowered = page.lower()
    for forbidden in ("compliant", "certified", "valid log"):
        assert forbidden not in lowered
    # the chain head is on the page, escaped content everywhere
    head = json.loads(
        runner.invoke(app, ["pala", "report", str(log)]).output
    )["chain"]["head"]
    assert head in page


def test_two_html_runs_diff_only_in_the_checked_at_line(tmp_path):
    log = _chain(tmp_path)
    a = runner.invoke(app, ["pala", "report", str(log), "--html"]).output.splitlines()
    b = runner.invoke(app, ["pala", "report", str(log), "--html"]).output.splitlines()
    diff = [(x, y) for x, y in zip(a, b, strict=True) if x != y]
    # second-precision human time: two runs may land in one second (0 diffs)
    assert len(a) == len(b) and len(diff) <= 1, diff
    assert not diff or "Checked at" in diff[0][0]


def test_out_writes_the_file_and_unreadable_source_exits_3(tmp_path):
    log = _chain(tmp_path)
    dest = tmp_path / "report.html"
    res = runner.invoke(
        app, ["pala", "report", str(log), "--html", "-o", str(dest)]
    )
    assert res.exit_code == 0 and dest.exists()
    assert dest.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    missing = runner.invoke(app, ["pala", "report", str(tmp_path / "nope")])
    assert missing.exit_code == 3
