#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Render integrations/COMPATIBILITY.md from dated sources only.

Two sources, nothing else: the surface checker's reports in
``results/surfaces-*.md`` (every row as the checker wrote it) and the facts
in ``integrations/compatibility.json`` that a report cannot carry — the
machine of a report written before the checker recorded it, a note naming a
known checker defect beside the row it affected, and the real-traffic run
records. Every row links to the file it came from. A row with no date and no
source is not a row.

Deterministic: a re-run on unchanged sources changes nothing, and
tests/test_compatibility.py holds the committed file to a fresh build.

Usage: python3 scripts/build_compatibility.py
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "integrations" / "COMPATIBILITY.md"
DATA = ROOT / "integrations" / "compatibility.json"
REPORT = re.compile(r"^surfaces-(\d{4}-\d{2}-\d{2})(?:-(\d+))?\.md$")
ROW = re.compile(r"^\| ([a-z0-9-]+) \| \S+ (GREEN|RED|SKIP|ERROR) \| (.*?) \| (.*) \|$")
MACHINE = re.compile(r"^Machine: (.+)$")
MARK = {"GREEN": "🟢", "RED": "🔴", "SKIP": "⚪", "ERROR": "🟠"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").strip()


def reports(results: Path) -> list[tuple[str, str, str | None, list[tuple[str, ...]]]]:
    """``(file name, date, machine line or None, rows)`` for every report, newest first."""
    out = []
    for path in results.iterdir():
        m = REPORT.match(path.name)
        if not m:
            continue
        machine, rows = None, []
        for line in path.read_text(encoding="utf-8").splitlines():
            mm = MACHINE.match(line)
            if mm:
                machine = mm.group(1).strip()
            r = ROW.match(line)
            if r:
                rows.append(r.groups())
        out.append((path.name, m.group(1), machine, rows, int(m.group(2) or 1)))
    # newest first: by date, then by the day's run number (surfaces-DATE-2 after DATE)
    out.sort(key=lambda r: (r[1], r[4]), reverse=True)
    return [r[:4] for r in out]


def render(root: Path = ROOT) -> str:
    data = json.loads((root / "integrations" / "compatibility.json").read_text(encoding="utf-8"))
    annotated = data.get("reports", {})
    lines = [
        "<!-- SPDX-FileCopyrightText: Assault Consulting -->",
        "<!-- SPDX-License-Identifier: Apache-2.0 -->",
        "",
        "# Compatibility",
        "",
        "Which client versions were checked against which integration, on what",
        "machine, when, and with what result. **Generated** by",
        "`scripts/build_compatibility.py` from the surface checker's dated reports",
        "in `results/` and the real-traffic run records; do not edit by hand.",
        "",
        "Read it as evidence, not as a promise. A row says what one check on one",
        "machine showed on one date. ⚪ SKIP means the surface was not checked, and",
        "🟠 ERROR means the checker failed; neither is a pass. How the checker",
        "works and what its states mean: [`docs/SURFACE-CHECKER.md`](../docs/SURFACE-CHECKER.md).",
        "",
        "## Surface checks",
        "",
        "One probe per client, against a stand-in model: does the client's surface",
        "still deliver a call and its result with the expected mark.",
        "",
        "| Integration | Client version | Machine | Date | State | Checker's detail | Report |",
        "|---|---|---|---|---|---|---|",
    ]
    footnotes: list[str] = []
    for name, date, machine, rows in reports(root / "results"):
        meta = annotated.get(name, {})
        where = machine or meta.get("machine") or "not recorded"
        for surface, state, version, detail in rows:
            note = meta.get("notes", {}).get(surface)
            mark = f"{MARK[state]} {state}"
            if note:
                footnotes.append(note)
                mark += f" [{len(footnotes)}]"
            lines.append(
                f"| {surface} | {_cell(version)} | {_cell(where)} | {date} | {mark} "
                f"| {_cell(detail)} | [{name}](../results/{name}) |"
            )
    if footnotes:
        lines += ["", "Notes on rows above, from the run's own notes file:", ""]
        lines += [f"{i}. {n}" for i, n in enumerate(footnotes, 1)]
    lines += [
        "",
        "## Real traffic",
        "",
        "A real client and a real model, on one machine, with what reached the",
        "chain and what did not. Each record states its own limits.",
        "",
        "| Integration | Client | Machine | Date | Palimpsests | What reached the chain | Record |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in data.get("runs", []):
        rec = r["record"]
        folder = rec.split("/")[-2]
        lines.append(
            f"| {r['integration']} | {_cell(r['client'])} | {_cell(r['machine'])} | {r['date']} "
            f"| {_cell(r['palimpsests'])} | {_cell(r['result'])} | [{folder}](../{rec}) |"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
