# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U17 — ``Verification.manifest``: the second file a segment's verdict rests on.

A segment whose first record declares a continuation is diagnosed against
the ``<stem>.segments.json`` manifest beside it. Before this, a consumer
learned that only from the diagnosis's sentence: it could not name the
file, hash it, or notice it change. Each case here pins what the reading
says — path, status, the digest of the bytes judged, and why — and that a
verdict which consulted no manifest says so with ``None``.
"""
from __future__ import annotations

import json
import os
import shutil
from hashlib import sha256
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy
from palimpsests.audit.reader import (
    AuditReader,
    ManifestReading,
    Verification,
    decode_continuation,
)
from pathlib import Path


def _survivor(tmp_path: Path) -> Path:
    """The last segment of a rotated chain, with every earlier one removed
    and the manifest left beside it (Case B)."""
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=4, retention_s=15_552_000))
    w.genesis()
    for _ in range(13):
        w.prefix_warm(token_count=1)
    w.close()
    segs = [base] + sorted(tmp_path.glob("w.pala.0*"))
    for old in segs[:-1]:
        os.remove(old)
    return segs[-1]


def _manifest(tmp_path: Path) -> Path:
    return tmp_path / "w.pala.segments.json"


def _reading(path: Path) -> ManifestReading | None:
    with AuditReader.open(path) as r:
        return r.verify().manifest


# --- the three statuses --------------------------------------------------------


def test_a_matching_manifest_is_named_and_hashed(tmp_path):
    seg = _survivor(tmp_path)
    m = _reading(seg)
    assert m == ManifestReading(
        str(_manifest(tmp_path)), "matches", sha256(_manifest(tmp_path).read_bytes()).digest(), None
    )


def test_a_contradicting_manifest_is_named_and_hashed_as_it_was_judged(tmp_path):
    seg = _survivor(tmp_path)
    mf = json.loads(_manifest(tmp_path).read_text())
    mf["segments"][-1]["head"] = "ab" * 32
    _manifest(tmp_path).write_text(json.dumps(mf))
    with AuditReader.open(seg) as r:
        v = r.verify()
    assert v.diagnosis.pattern == "continuation_contradicts_manifest"
    assert v.manifest.status == "contradicts"
    assert v.manifest.sha256 == sha256(_manifest(tmp_path).read_bytes()).digest()


def test_a_manifest_with_no_entry_for_the_predecessor_contradicts(tmp_path):
    """The semantics the diagnosis already had: a manifest that does not list
    the segment the declaration names disagrees with it. Now it says which."""
    seg = _survivor(tmp_path)
    _manifest(tmp_path).write_text(json.dumps({"format": "pala-segments/1", "segments": []}))
    with AuditReader.open(seg) as r:
        v = r.verify()
    assert v.diagnosis.pattern == "continuation_contradicts_manifest"
    assert v.manifest.status == "contradicts"
    assert "lists no segment" in v.manifest.detail


def test_a_missing_manifest_names_where_it_was_looked_for(tmp_path):
    seg = _survivor(tmp_path)
    _manifest(tmp_path).unlink()
    m = _reading(seg)
    assert m.path == str(_manifest(tmp_path))
    assert m.status == "declared_only"
    assert m.sha256 is None
    assert "no manifest" in m.detail


# --- a manifest that cannot be judged is set aside, and says so ------------------


def test_a_manifest_that_is_not_json_is_hashed_and_set_aside(tmp_path):
    seg = _survivor(tmp_path)
    _manifest(tmp_path).write_text("{")
    m = _reading(seg)
    assert m.status == "declared_only"
    assert m.sha256 == sha256(b"{").digest()
    assert "not JSON" in m.detail


def test_a_manifest_that_is_a_list_no_longer_crashes_verify(tmp_path):
    """On main before this PR, a top-level JSON array raised AttributeError
    out of verify(). A malformed manifest confirms nothing and contradicts
    nothing; it is set aside and the reason given."""
    seg = _survivor(tmp_path)
    _manifest(tmp_path).write_text("[]")
    with AuditReader.open(seg) as r:
        v = r.verify()
    assert v.diagnosis.pattern == "declared_continuation"
    assert v.manifest.status == "declared_only"
    assert "not pala-segments/1" in v.manifest.detail


def test_a_manifest_path_that_cannot_be_read_says_why(tmp_path):
    """Present but unreadable (here a directory) is not "no manifest"."""
    seg = _survivor(tmp_path)
    _manifest(tmp_path).unlink()
    _manifest(tmp_path).mkdir()
    m = _reading(seg)
    assert m.status == "declared_only"
    assert m.sha256 is None
    assert "could not be read" in m.detail


def test_segments_that_are_not_a_list_are_set_aside(tmp_path):
    seg = _survivor(tmp_path)
    _manifest(tmp_path).write_text(json.dumps({"format": "pala-segments/1", "segments": {}}))
    m = _reading(seg)
    assert m.status == "declared_only"
    assert "not a list" in m.detail


def test_an_entry_that_is_not_an_object_is_set_aside(tmp_path):
    seg = _survivor(tmp_path)
    with AuditReader.open(seg) as r:
        k = decode_continuation(r.record_at(0)).segment_index - 1
    mf = json.loads(_manifest(tmp_path).read_text())
    mf["segments"][k] = 7
    _manifest(tmp_path).write_text(json.dumps(mf))
    m = _reading(seg)
    assert m.status == "declared_only"
    assert "not an object" in m.detail


# --- when there is nothing to name ----------------------------------------------


def test_a_reader_without_a_path_cannot_name_a_manifest(tmp_path):
    seg = _survivor(tmp_path)
    with AuditReader.from_bytes(seg.read_bytes()) as r:
        m = r.verify().manifest
    assert m.path is None
    assert m.status == "declared_only"
    assert "not opened from a path" in m.detail


def test_a_segment_renamed_away_from_its_pattern_cannot_name_one(tmp_path):
    seg = _survivor(tmp_path)
    renamed = tmp_path / "copy.pala"
    shutil.copy(seg, renamed)
    m = _reading(renamed)
    assert m.path is None
    assert "not a segment's" in m.detail


def test_a_verdict_that_consulted_no_manifest_says_none(tmp_path):
    """The whole chain from GENESIS: no continuation at position 0, so no
    second file was involved in the verdict."""
    base = tmp_path / "whole.pala"
    w = PalaWriter(base)
    w.genesis()
    w.boot()
    w.close()
    assert _reading(base) is None


# --- one read: the digest is of the bytes judged ---------------------------------


def test_the_digest_describes_the_manifest_as_judged_not_as_it_is_later(tmp_path):
    seg = _survivor(tmp_path)
    before = sha256(_manifest(tmp_path).read_bytes()).digest()
    with AuditReader.open(seg) as r:
        first = r.verify().manifest
        _manifest(tmp_path).write_text("{}")
        assert r.verify().manifest == first  # the verdict is cached; so is what it rested on
    assert first.sha256 == before
    assert _reading(seg).sha256 == sha256(b"{}").digest()  # a new reader reads anew


def test_verification_without_a_manifest_still_constructs_positionally():
    """Additive: the field has a default, so the seven-field construction
    any caller already wrote keeps working."""
    v = Verification(None, None, [], None, None, None, None)
    assert v.manifest is None
