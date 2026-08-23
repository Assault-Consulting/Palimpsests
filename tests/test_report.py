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
            "container", "anchor", "completeness", "existence",
            "diagnosis", "advisory", "safety", "time_basis", "verdict",
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
    # K1: the verdict is IN the model, produced by the exported rule
    assert report["verdict"] == "partial"  # sound so far, no anchor supplied
    assert report["container"]["well_formed"] is True
    assert report["container"]["bytes_parsed"] == report["container"]["bytes_total"]


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


def test_truncated_container_is_attested_and_a_violation(tmp_path):
    # K2: the CLI knew this fact; now the report does too.
    log = _chain(tmp_path)
    raw = log.read_bytes()
    cut = tmp_path / "cut.pala"
    cut.write_bytes(raw[: len(raw) - 40])
    report = build_report(cut).data
    assert report["container"]["well_formed"] is False
    assert report["container"]["bytes_parsed"] < report["container"]["bytes_total"]
    assert report["verdict"] == "violation"


def test_body_swap_is_a_violation_even_with_an_intact_header_chain(tmp_path):
    # K5: a header-only chain check cannot see a body swap; the report must.
    from palimpsests.audit.pala import iter_records

    log = _chain(tmp_path)
    raw = bytearray(log.read_bytes())
    # locate the ack record's body (seq 4, the largest body) and flip one
    # byte INSIDE it — headers stay untouched, so the chain still holds
    offset = 0
    target = None
    for hb, body in iter_records(bytes(raw)):
        if len(body) == 80:
            target = offset + len(hb) + 10  # a byte well inside the body
        offset += len(hb) + len(body)
    assert target is not None
    raw[target] ^= 0xFF
    swapped = tmp_path / "swapped.pala"
    swapped.write_bytes(bytes(raw))
    report = build_report(swapped).data
    assert report["chain"]["chain_ok"] is True  # headers still chain
    assert report["container"]["body_digest_mismatches"] != []
    assert report["verdict"] == "violation"


def test_report_validates_against_the_shipped_schema(tmp_path):
    jsonschema = __import__("pytest").importorskip("jsonschema")
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parents[1]
        / "docs" / "specs" / "report" / "pala-verification-report-1.schema.json"
    )
    schema = json.loads(schema_path.read_text())
    report = build_report(_chain(tmp_path)).data
    jsonschema.validate(report, schema)  # raises on any shape drift
