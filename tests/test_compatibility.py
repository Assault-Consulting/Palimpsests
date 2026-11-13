# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""integrations/COMPATIBILITY.md is generated from dated sources only.

The committed file must equal a fresh build; every link in it must resolve;
every annotation must sit beside a row that exists; and every surface report
in results/ must appear. A row nobody can trace is what this test refuses.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _builder():
    spec = importlib.util.spec_from_file_location(
        "build_compatibility_under_test", ROOT / "scripts" / "build_compatibility.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_the_committed_table_is_a_fresh_build():
    built = _builder().render()
    committed = (ROOT / "integrations" / "COMPATIBILITY.md").read_text(encoding="utf-8")
    assert committed == built, "run: python3 scripts/build_compatibility.py"


def test_every_link_resolves():
    text = (ROOT / "integrations" / "COMPATIBILITY.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((\.\./[^)]+)\)", text):
        assert (ROOT / "integrations" / target).resolve().is_file(), target


def test_every_report_appears_and_every_note_has_its_row():
    b = _builder()
    reports = b.reports(ROOT / "results")
    names = {name for name, *_ in reports}
    on_disk = {p.name for p in (ROOT / "results").glob("surfaces-*.md") if b.REPORT.match(p.name)}
    assert names == on_disk and names
    data = json.loads((ROOT / "integrations" / "compatibility.json").read_text(encoding="utf-8"))
    rows = {name: {r[0] for r in rws} for name, _, _, rws in reports}
    for name, meta in data["reports"].items():
        assert name in rows, name
        assert set(meta.get("notes", {})) <= rows[name], name
        if "machine_source" in meta:
            assert (ROOT / meta["machine_source"]).is_file()
    for run in data["runs"]:
        assert (ROOT / run["record"]).is_file(), run["record"]
        assert run["date"] and run["client"] and run["result"]


def test_a_report_with_a_machine_line_needs_no_annotation(tmp_path):
    b = _builder()
    (tmp_path / "results").mkdir()
    (tmp_path / "integrations").mkdir()
    (tmp_path / "integrations" / "compatibility.json").write_text('{"reports": {}, "runs": []}')
    (tmp_path / "results" / "surfaces-2026-12-01.md").write_text(
        "# Surface check — 2026-12-01\n\nMachine: Linux 6.8, Python 3.12.3, palimpsests 0.14.0\n\n"
        "| Surface | State | Version | Detail |\n|---|---|---|---|\n"
        "| mcp | 🟢 GREEN | stdio / JSON-RPC 2.0 | 1 call(s), 1 result(s), sources [1] |\n",
        encoding="utf-8")
    out = b.render(tmp_path)
    row = ("| mcp | stdio / JSON-RPC 2.0 | Linux 6.8, Python 3.12.3, palimpsests 0.14.0 "
           "| 2026-12-01 | 🟢 GREEN |")
    assert row in out


def test_the_checker_writes_the_machine_line():
    spec = importlib.util.spec_from_file_location(
        "cs_for_compat", ROOT / "scripts" / "check_surfaces.py")
    cs = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = cs
    spec.loader.exec_module(cs)
    text = cs.render([cs.Result("mcp", "GREEN", "x", "y")], "2026-12-01")
    line = next(ln for ln in text.splitlines() if ln.startswith("Machine: "))
    assert "Python" in line and "palimpsests" in line


def test_a_second_report_the_same_day_is_read_and_comes_first(tmp_path):
    b = _builder()
    (tmp_path / "results").mkdir()
    (tmp_path / "integrations").mkdir()
    (tmp_path / "integrations" / "compatibility.json").write_text('{"reports": {}, "runs": []}')
    head = "| Surface | State | Version | Detail |\n|---|---|---|---|\n"
    for name, machine, surface in (("surfaces-2026-12-01.md", "Windows 11", "opencode"),
                                   ("surfaces-2026-12-01-2.md", "Linux 6.8", "claude-code")):
        (tmp_path / "results" / name).write_text(
            f"Machine: {machine}\n\n{head}| {surface} | 🟢 GREEN | v | d |\n", encoding="utf-8")
    names = [r[0] for r in b.reports(tmp_path / "results")]
    assert names == ["surfaces-2026-12-01-2.md", "surfaces-2026-12-01.md"]
    out = b.render(tmp_path)
    assert "| claude-code | v | Linux 6.8 | 2026-12-01 |" in out


def test_rows_that_share_a_note_share_its_number(tmp_path):
    """A run of several probes carries one note about the run; the table gives
    it one number, not one per row (the 2026-11-13 report: four rows, one note)."""
    b = _builder()
    (tmp_path / "results").mkdir()
    (tmp_path / "integrations").mkdir()
    (tmp_path / "integrations" / "compatibility.json").write_text(json.dumps({
        "reports": {"surfaces-2026-12-01.md": {"notes": {
            "mcp": "about the run", "otel": "about the run", "litellm": "about this row"}}},
        "runs": []}))
    (tmp_path / "results" / "surfaces-2026-12-01.md").write_text(
        "# Surface check — 2026-12-01\n\nMachine: Linux 6.8, Python 3.12.3, palimpsests 0.14.0\n\n"
        "| Surface | State | Version | Detail |\n|---|---|---|---|\n"
        "| mcp | 🟢 GREEN | stdio | ok |\n"
        "| litellm | 🟢 GREEN | 1.0 | ok |\n"
        "| otel | 🟢 GREEN | 1.0 | ok |\n",
        encoding="utf-8")
    out = b.render(tmp_path)
    marks = re.findall(r"^\| (\w+) \|.*GREEN \[(\d)\]", out, re.M)
    assert marks == [("mcp", "1"), ("litellm", "2"), ("otel", "1")]
    assert out.count("about the run") == 1 and "\n2. about this row" in out
