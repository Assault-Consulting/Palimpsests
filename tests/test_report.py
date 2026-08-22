# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U6: one schema owner; deterministic modulo checked_at; §20.4 round-trip."""
from __future__ import annotations

import json
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.report import REPORT_FORMAT, build_report


def _chain(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()  # seq 0
    span = w.session_start("s1")  # seq 1
    h1 = w.incident_candidate(1, 2, detail="state reject burst")  # seq 2
    w.incident_candidate(1, 2, detail="second, never acked")  # seq 3
    w.oversight_ack(2, h1, 1, b"\x07" * 16)  # seq 4
    w.session_end(span)  # seq 5
    w.close()
    return log


def test_section15_shape_and_safety_accounting(tmp_path):
    report = build_report(_chain(tmp_path)).data
    assert report["format"] == REPORT_FORMAT
    # every §15 top-level key, no extras
    assert sorted(report) == sorted(
        [
            "format", "subject", "verifier", "checked_at", "chain",
            "anchor", "completeness", "existence", "diagnosis",
            "advisory", "safety", "time_basis",
        ]
    )
    assert report["chain"]["chain_ok"] is True
    assert report["subject"]["records"] == 6
    # two candidates, one acked → one unacknowledged (the Art. 73 trigger)
    assert report["safety"]["unacknowledged_candidates"] == 1
    assert report["advisory"]["note"] == "advisory items do not affect the verdict"
    # not-checked is never rendered as passed (L7)
    assert report["completeness"]["complete_to_anchor"] is None
    assert report["anchor"] is None
    assert report["time_basis"]["axis"] == "proved-order"


def test_deterministic_modulo_checked_at(tmp_path):
    log = _chain(tmp_path)
    a = build_report(log).data
    b = build_report(log).data
    a["checked_at"] = b["checked_at"] = None
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_shell_names_itself_but_package_stays(tmp_path):
    report = build_report(_chain(tmp_path), tool="palimpsests-auditor 0.1").data
    assert report["verifier"]["tool"] == "palimpsests-auditor 0.1"
    assert report["verifier"]["package"].startswith("palimpsests ")
