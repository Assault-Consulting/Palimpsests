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
