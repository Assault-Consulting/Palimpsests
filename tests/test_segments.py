# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""WS-R: the cut keeps the proof — alone, across the seam, after deletion."""
from __future__ import annotations

import json
from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.segments import segment_chain
from palimpsests.audit.pala_writer import PalaWriter


def _chain(tmp_path, n_events=9):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    for i in range(n_events):
        # bodies included: the cut must carry record bytes, not headers only
        w.incident_candidate(1, 2, detail=f"e{i}")
    w.close()
    return log


def test_segments_verify_alone_seeded_from_the_manifest(tmp_path):
    log = _chain(tmp_path)  # 10 records
    res = segment_chain(log, tmp_path / "segs", records_per_segment=4)
    assert [s.records for s in res.segments] == [4, 4, 2]

    manifest = json.loads(res.manifest_path.read_text())
    for i, seg in enumerate(manifest["segments"]):
        seg_bytes = (tmp_path / "segs" / seg["file"]).read_bytes()
        headers = [hb for hb, _ in iter_records(seg_bytes)]
        start_prev = (
            None if i == 0 else bytes.fromhex(seg["prev_head"])
        )
        r = verify_headers(headers, start_prev=start_prev)
        assert r.chain_ok is True, (i, r.violations, r.breaks)
        assert r.head.hex() == seg["head"]
        # the seam is a checked link, not a convention
        if i > 0:
            assert seg["prev_head"] == manifest["segments"][i - 1]["head"]


def test_concatenation_reproduces_the_source_byte_for_byte(tmp_path):
    log = _chain(tmp_path)
    res = segment_chain(log, tmp_path / "segs", records_per_segment=3)
    joined = b"".join(
        (tmp_path / "segs" / s.file).read_bytes() for s in res.segments
    )
    assert joined == log.read_bytes()


def test_retention_deletion_keeps_the_tail_verifiable(tmp_path):
    log = _chain(tmp_path)
    res = segment_chain(log, tmp_path / "segs", records_per_segment=4)
    manifest = json.loads(res.manifest_path.read_text())
    # the six-month knife falls: the first segment's bytes are deleted
    (tmp_path / "segs" / manifest["segments"][0]["file"]).unlink()
    # the survivors still prove they continue a specific, named history
    for seg in manifest["segments"][1:]:
        seg_bytes = (tmp_path / "segs" / seg["file"]).read_bytes()
        headers = [hb for hb, _ in iter_records(seg_bytes)]
        r = verify_headers(headers, start_prev=bytes.fromhex(seg["prev_head"]))
        assert r.chain_ok is True


def test_deterministic_and_forgery_breaks_the_seam(tmp_path):
    log = _chain(tmp_path)
    a = segment_chain(log, tmp_path / "a", records_per_segment=4)
    b = segment_chain(log, tmp_path / "b", records_per_segment=4)
    assert a.manifest_path.read_bytes() == b.manifest_path.read_bytes()
    for s in a.segments:
        assert (tmp_path / "a" / s.file).read_bytes() == (
            tmp_path / "b" / s.file
        ).read_bytes()

    # a wrong seed (forged predecessor) is a detected break at the seam
    seg1 = json.loads(a.manifest_path.read_text())["segments"][1]
    seg_bytes = (tmp_path / "a" / seg1["file"]).read_bytes()
    headers = [hb for hb, _ in iter_records(seg_bytes)]
    r = verify_headers(headers, start_prev=b"\x99" * 32)
    assert r.chain_ok is False and r.breaks != []


def test_default_verifier_behaviour_is_unchanged(tmp_path):
    log = _chain(tmp_path)
    res = segment_chain(log, tmp_path / "segs", records_per_segment=4)
    seg1 = res.segments[1]
    seg_bytes = (tmp_path / "segs" / seg1.file).read_bytes()
    headers = [hb for hb, _ in iter_records(seg_bytes)]
    r = verify_headers(headers)  # no start_prev: the GENESIS MUST stands
    assert r.chain_ok is False
    assert any("GENESIS" in v[1] for v in r.violations)


def test_cli_segment_command(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    log = _chain(tmp_path)
    out = tmp_path / "cli-segs"
    result = CliRunner().invoke(
        app, ["pala", "segment", str(log), "-o", str(out), "-n", "4"]
    )
    assert result.exit_code == 0, result.output
    assert "3 file(s)" in result.output
    assert (out / "segments.json").exists()
