# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The report's ``health`` section: advisory, optional, of fixed size.

A report left the desk without the record's own account of its clocks and
its anchoring — the part a reader judges a wall-clock claim by. A consumer
that shows the package's report as it comes could add it only by writing a
second document of its own. ``build_report(health=True)`` carries a summary
of the health channel; without it the key is ``None`` and nothing is
computed. No figure is a threshold, and none reaches the verdict.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.bootstats import boot_statistics
from palimpsests.audit.pala.codec import (
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    TIME_UNSYNCED,
    ZERO32,
    Header,
    record_hash,
)
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.report import build_report, derive_verdict, health_summary
from palimpsests.audit.report_html import render_html
from palimpsests.audit.timehealth import STEP_THRESHOLD_NS, drift_series, step_catalog
from pathlib import Path

A, B = b"\x0a" * 16, b"\x0b" * 16
MS, S = 1_000_000, 1_000_000_000
SCHEMA = Path(__file__).resolve().parent.parent / "docs" / "specs" / "report" / \
    "pala-verification-report-2.schema.json"


def _write(tmp_path, rows):
    """rows: (record_type, boot_id, mono, wall). seq is positional."""
    data, prev = b"", ZERO32
    for seq, (rtype, boot, mono, wall) in enumerate(rows):
        hb = Header(
            record_type=rtype, seq=seq, boot_id=boot, prev_hash=prev,
            time_trust=TIME_UNSYNCED, monotonic_ns=mono, wall_clock_ns=wall,
        ).encode()
        data += hb
        prev = record_hash(hb)
    path = tmp_path / "t.pala"
    path.write_bytes(data)
    return path


@pytest.fixture
def two_boots(tmp_path):
    w0 = 1_700_000_000 * S
    return _write(tmp_path, [
        # boot A: anchors at 10 s and 40 s of a 100 s boot; one 2 s step
        (RT_GENESIS, A, 0, w0),
        (RT_BOOT, A, 1 * S, w0 + 1 * S),
        (RT_ANCHOR, A, 10 * S, w0 + 10 * S),
        (RT_EVENT, A, 20 * S, w0 + 22 * S),          # the wall clock stepped +2 s
        (RT_ANCHOR, A, 40 * S, w0 + 42 * S),
        (RT_EVENT, A, 100 * S, w0 + 102 * S),
        # boot B: no anchor; the wall clock goes backwards once
        (RT_BOOT, B, 0, w0 + 200 * S),
        (RT_EVENT, B, 5 * S, w0 + 205 * S),
        (RT_EVENT, B, 6 * S, w0 + 204 * S),          # regression, -1 s
    ])


def test_without_the_flag_the_key_is_there_and_nothing_is_said(two_boots):
    data = build_report(two_boots).data
    assert "health" in data and data["health"] is None


def test_the_summary_is_what_the_health_channel_computes(two_boots):
    health = build_report(two_boots, health=True).data["health"]
    with AuditReader.open(two_boots) as reader:
        boots, steps = boot_statistics(reader), step_catalog(reader)
        slopes = [d.slope_ppm for d in drift_series(reader) if d.slope_ppm is not None]
        assert health == health_summary(reader)

    assert health["boots"] == {
        "basis": "proved order", "count": 2,
        "resumed_after_truncated_tail": 0, "with_time_trust_change": 0}
    # boot A's gaps: 0→10, 10→40, 40→100 s. The edge to the boot's end is the widest.
    assert health["anchors"] == {
        "basis": "the monotonic clock, within one boot",
        "count": 2, "boots_without_anchor": 1,
        "widest_gap_ns": 60 * S, "widest_gap_boot_first_seq": 0}
    assert health["anchors"]["widest_gap_ns"] == max(
        b.anchors.widest_anchor_gap_ns for b in boots if b.anchors.count)
    wall = health["wall_clock"]
    assert (wall["steps"], wall["regressions"], wall["slews"]) == (1, 1, 0)
    assert (wall["largest_delta_ns"], wall["largest_at_seq"]) == (2 * S, 3)
    assert wall["step_threshold_ns"] == STEP_THRESHOLD_NS
    assert len(steps) == 2 and wall["drift_boots_measured"] == len(slopes) == 2
    assert wall["drift_slope_ppm_min"] == round(min(slopes), 3)
    assert wall["drift_slope_ppm_max"] == round(max(slopes), 3)
    assert health["spans"] == {"basis": "proved order", "closed": 0, "open": 0}


def test_every_group_names_the_clock_it_is_measured_on(two_boots):
    health = build_report(two_boots, health=True).data["health"]
    groups = {k: v for k, v in health.items() if k != "note"}
    assert set(groups) == {"boots", "anchors", "wall_clock", "spans"}
    assert all(isinstance(g["basis"], str) and g["basis"] for g in groups.values())
    assert "wall clock" in groups["wall_clock"]["basis"]
    assert "advisory" in health["note"] and "verdict" in health["note"]


def test_health_never_reaches_the_verdict(two_boots):
    """The same file, with and without: every other key is identical, and a
    summary rewritten to look alarming changes nothing the rule reads."""
    plain = build_report(two_boots).data
    with_health = build_report(two_boots, health=True).data
    skip = {"health", "checked_at"}
    assert {k: v for k, v in plain.items() if k not in skip} == {
        k: v for k, v in with_health.items() if k not in skip}
    alarming = json.loads(json.dumps(with_health))
    alarming["health"]["wall_clock"]["regressions"] = 10**6
    alarming["health"]["anchors"]["count"] = 0
    assert derive_verdict(alarming) == derive_verdict(plain) == plain["verdict"]


def test_the_summary_does_not_grow_with_the_chain(tmp_path):
    def size(n):
        folder = tmp_path / str(n)
        folder.mkdir()
        rows = [(RT_GENESIS, A, 0, S)] + [
            (RT_ANCHOR if i % 7 == 0 else RT_EVENT, A, i * S, S + i * S + (i % 3) * 200 * MS)
            for i in range(1, n)]
        health = build_report(_write(folder, rows), health=True).data["health"]
        return len(json.dumps(health)), set(_leaves(health))

    (small, keys_small), (large, keys_large) = size(20), size(2000)
    assert keys_small == keys_large
    assert large - small < 40  # the digits of larger numbers, nothing else


def _leaves(node, prefix=""):
    for key, value in node.items():
        if isinstance(value, dict):
            yield from _leaves(value, prefix + key + ".")
        else:
            assert not isinstance(value, list), "a list would grow with the chain"
            yield prefix + key


def test_a_chain_with_nothing_to_measure_says_so_with_nulls(tmp_path):
    for name, data in (("empty", b""), ("junk", b"not a container at all")):
        path = tmp_path / f"{name}.pala"
        path.write_bytes(data)
        health = build_report(path, health=True).data["health"]
        assert health["boots"]["count"] == 0 and health["anchors"]["count"] == 0
        assert health["anchors"]["widest_gap_ns"] is None
        assert health["wall_clock"]["largest_delta_ns"] is None
        assert health["wall_clock"]["drift_slope_ppm_min"] is None


def test_both_shapes_validate_and_the_schema_names_every_key(two_boots):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    for flag in (False, True):
        jsonschema.validate(build_report(two_boots, health=flag).data, schema)
    declared = schema["properties"]["health"]["oneOf"][1]["properties"]
    health = build_report(two_boots, health=True).data["health"]
    for group, body in health.items():
        if group == "note":
            continue
        assert set(body) == set(declared[group]["properties"]) == set(declared[group]["required"])
    broken = build_report(two_boots, health=True).data
    del broken["health"]["anchors"]["basis"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, schema)


def test_a_shared_reader_gives_the_same_section(two_boots):
    with AuditReader.open(two_boots) as reader:
        shared = build_report(two_boots, reader=reader, health=True).data["health"]
    assert shared == build_report(two_boots, health=True).data["health"]


def test_the_page_shows_the_section_only_when_it_is_there(two_boots):
    plain = render_html(build_report(two_boots).data)
    page = render_html(build_report(two_boots, health=True).data)
    assert "Record health" not in plain
    assert "Record health — advisory" in page
    assert "60,000,000,000 ns" in page and "the writer&#x27;s wall clock" in page


def test_a_real_writer_chain_and_the_command(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        span = w.session_start("s")
        w.prefix_warm(token_count=5)
        w.anchor()
        w.session_end(span)
        w.session_start("left open")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(app, ["pala", "report", str(log), "--health", "-o", str(out)])
    assert result.exit_code == 0, result.output
    health = json.loads(out.read_text(encoding="utf-8"))["health"]
    assert health["boots"]["count"] == 1 and health["anchors"]["count"] == 1
    assert health["spans"] == {"basis": "proved order", "closed": 1, "open": 1}
    plain = CliRunner().invoke(app, ["pala", "report", str(log)])
    assert json.loads(plain.output)["health"] is None
