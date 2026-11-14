# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A segmented chain, verified as a set (U18).

Both shapes of ``pala-segments/1`` manifest: the one ``pala segment``
writes (every segment listed) and the one a rotating writer keeps (closed
segments only — the live one is found by its link). Deletion under
retention makes a set incomplete, never inconsistent; tampering makes it
inconsistent.
"""
from __future__ import annotations

import json
import os
import pytest
from palimpsests.audit.pala.segments import segment_chain
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy
from palimpsests.audit.segment_set import verify_segment_set


def _segmented(tmp_path):
    src = tmp_path / "c.pala"
    with PalaWriter(src) as w:
        w.genesis()
        w.boot()
        for i in range(10):
            w.prefix_warm(token_count=i)
    return segment_chain(src, tmp_path / "segs", records_per_segment=4)


def _rotated(tmp_path):
    folder = tmp_path / "rot"
    folder.mkdir()
    with PalaWriter(folder / "w.pala", rotation=RotationPolicy(max_records=4)) as w:
        w.genesis()
        w.boot()
        for i in range(9):
            w.prefix_warm(token_count=i)
        head = w.head
    return folder / "w.pala.segments.json", head


def test_a_whole_set_is_consistent_and_complete(tmp_path):
    res = _segmented(tmp_path)
    v = verify_segment_set(res.manifest_path)
    assert v.consistent and v.complete and not v.absent
    assert v.head.hex() == res.source_head
    assert all(c.listed and c.verified and c.head_matches and c.seam_ok for c in v.segments)


def test_a_deleted_segment_leaves_it_consistent_not_complete(tmp_path):
    res = _segmented(tmp_path)
    first = res.segments[0].file
    os.remove(res.manifest_path.parent / first)
    v = verify_segment_set(res.manifest_path)
    assert v.consistent and not v.complete
    assert v.absent == [first]
    assert v.segments[0].present is False and v.segments[0].verified is None


def test_a_tampered_segment_makes_it_inconsistent(tmp_path):
    res = _segmented(tmp_path)
    mid = res.manifest_path.parent / res.segments[1].file
    data = bytearray(mid.read_bytes())
    data[60] ^= 0x01  # inside the first record's prev_hash: the link into the segment
    mid.write_bytes(bytes(data))
    v = verify_segment_set(res.manifest_path)
    assert not v.consistent and not v.complete
    assert v.segments[1].verified is False and v.segments[1].detail


def test_a_manifest_that_disagrees_with_the_file_is_caught(tmp_path):
    res = _segmented(tmp_path)
    mf = json.loads(res.manifest_path.read_text())
    mf["segments"][1]["head"] = "00" * 32
    res.manifest_path.write_text(json.dumps(mf))
    v = verify_segment_set(res.manifest_path)
    assert not v.consistent
    assert v.segments[1].head_matches is False
    assert v.segments[2].seam_ok is False  # its prev_head no longer names the entry before it


def test_the_manifest_is_named_by_the_bytes_read(tmp_path):
    import hashlib

    res = _segmented(tmp_path)
    v = verify_segment_set(res.manifest_path)
    assert v.manifest_sha256 == hashlib.sha256(res.manifest_path.read_bytes()).digest()


def test_a_rotating_writer_set_includes_its_live_segment(tmp_path):
    manifest, head = _rotated(tmp_path)
    v = verify_segment_set(manifest)
    assert v.consistent and v.complete and v.head == head
    tail = v.segments[-1]
    assert tail.listed is False and tail.verified  # found by its link, not by the manifest


def test_retention_on_a_rotating_writer(tmp_path):
    manifest, head = _rotated(tmp_path)
    os.remove(manifest.parent / "w.pala")  # the GENESIS segment, expired
    v = verify_segment_set(manifest)
    assert v.consistent and not v.complete and v.absent == ["w.pala"]
    assert v.head == head  # the survivors still verify to the live head


def test_not_a_manifest_is_refused(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"format": "something-else"}')
    with pytest.raises(ValueError, match="pala-segments/1"):
        verify_segment_set(p)


# ── damage is an answer, not an exception ───────────────────────────────────


def test_a_segment_cut_mid_record_is_an_answer_about_that_segment(tmp_path):
    """It raised ``MalformedRecord`` out of ``verify_segment_set``, whose own
    contract is that everything but "not a manifest" is an answer."""
    res = _segmented(tmp_path)
    victim = res.manifest_path.parent / res.segments[1].file
    victim.write_bytes(victim.read_bytes()[:-5])
    v = verify_segment_set(res.manifest_path)
    assert v.consistent is False and v.complete is False
    check = v.segments[1]
    assert check.present and check.verified is False
    assert "malformed" in check.detail and "cut short" in check.detail
    assert v.segments[0].verified is True  # the others are still judged on their own
    assert v.segments[2].verified is True


def test_a_segment_that_is_not_a_container_is_an_answer_too(tmp_path):
    res = _segmented(tmp_path)
    (res.manifest_path.parent / res.segments[0].file).write_bytes(b"not a container")
    v = verify_segment_set(res.manifest_path)
    assert v.consistent is False and v.segments[0].verified is False


def test_an_entry_that_names_a_path_is_not_followed(tmp_path):
    """The set is the files beside the manifest. An entry naming a file
    somewhere else — here a real, sound segment one directory up — is not
    read, and the set is not called consistent on the strength of it."""
    res = _segmented(tmp_path)
    folder = res.manifest_path.parent
    first = res.segments[0].file
    os.replace(folder / first, tmp_path / first)  # the real file, moved out
    for elsewhere in (f"../{first}", str(tmp_path / first)):
        mf = json.loads(res.manifest_path.read_text())
        mf["segments"][0]["file"] = elsewhere
        res.manifest_path.write_text(json.dumps(mf))
        v = verify_segment_set(res.manifest_path)
        assert v.segments[0].present is False and v.segments[0].verified is False, elsewhere
        assert "not read" in v.segments[0].detail
        assert v.consistent is False and v.complete is False, elsewhere


# ── the knife looks before it cuts ──────────────────────────────────────────


def _source(tmp_path):
    src = tmp_path / "c.pala"
    with PalaWriter(src) as w:
        w.genesis()
        w.boot()
        for i in range(10):
            w.prefix_warm(token_count=i)
    return src


def test_a_source_cut_mid_record_is_refused_and_nothing_is_written(tmp_path):
    """It raised ``MalformedRecord`` after writing the segments before the
    cut — files on disk, no manifest to say what they were."""
    src = _source(tmp_path)
    torn = tmp_path / "torn.pala"
    torn.write_bytes(src.read_bytes()[:-9])
    out = tmp_path / "segs"
    with pytest.raises(ValueError, match="not a well-formed container"):
        segment_chain(torn, out, records_per_segment=4)
    assert not out.exists()


def test_the_cli_refuses_a_torn_source_without_a_traceback(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    src = _source(tmp_path)
    torn = tmp_path / "torn.pala"
    torn.write_bytes(src.read_bytes()[:-9])
    res = CliRunner().invoke(app, ["pala", "segment", str(torn), "-o", str(tmp_path / "s")])
    assert res.exit_code == 3 and "nothing was written" in res.output
    assert not (tmp_path / "s").exists()


def test_the_cli_says_the_segments_verify_only_when_they_do(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    src = _source(tmp_path)
    ok = CliRunner().invoke(
        app, ["pala", "segment", str(src), "-o", str(tmp_path / "a"), "-n", "4"])
    assert ok.exit_code == 0 and "every segment verifies alone" in ok.output

    raw = bytearray(src.read_bytes())
    raw[200] ^= 1  # one bit: the container still walks, and no longer verifies
    bad = tmp_path / "bad.pala"
    bad.write_bytes(bytes(raw))
    res = CliRunner().invoke(
        app, ["pala", "segment", str(bad), "-o", str(tmp_path / "b"), "-n", "4"])
    assert res.exit_code == 0  # the cut is faithful: it was made
    assert "do NOT verify" in res.output
    assert "every segment verifies alone" not in res.output
    # and faithful means byte for byte, damage included
    segs = sorted((tmp_path / "b").glob("segment-*.pala"))
    assert b"".join(p.read_bytes() for p in segs) == bad.read_bytes()


def test_the_keys_of_pala_segments_1_are_kept(tmp_path):
    """Both writers, the keys a reader relies on. The format is open: a
    writer may add keys — the rotating writer already adds two per entry."""
    knife = json.loads(_segmented(tmp_path).manifest_path.read_text())
    base = tmp_path / "rot" / "w.pala"
    base.parent.mkdir()
    with PalaWriter(base, rotation=RotationPolicy(max_records=4)) as w:
        w.genesis()
        for i in range(9):
            w.prefix_warm(token_count=i)
    rotating = json.loads((base.parent / "w.pala.segments.json").read_text())
    for mf in (knife, rotating):
        assert mf["format"] == "pala-segments/1"
        assert {"format", "tool", "source_head", "segments"} <= mf.keys()
        for entry in mf["segments"]:
            assert {"file", "first_seq", "last_seq", "records", "head", "prev_head"} \
                <= entry.keys()
        assert mf["source_head"] == mf["segments"][-1]["head"]
    assert "records_per_segment" in knife and "rotation" in rotating
    assert {"root", "frontier"} <= rotating["segments"][0].keys()
