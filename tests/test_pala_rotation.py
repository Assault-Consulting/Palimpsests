# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Writer-side rotation: a segment boundary is invisible to the chain.

Core §2.4 is explicit — records are concatenated back-to-back with no
file header, so the byte concatenation of rotated segments IS a valid
container. These tests pin the writer's side of that promise: same
boot, continuous sequence, one verifiable chain across the cut, and
the two refusals (open span, non-empty target).
"""
from __future__ import annotations

import pytest
from palimpsests.audit import pala
from palimpsests.audit.pala_writer import PalaWriter


def _headers(data: bytes) -> list[bytes]:
    return [h for h, _ in pala.iter_records(data)]


def test_concatenated_segments_verify_as_one_chain(tmp_path):
    p1, p2 = tmp_path / "seg.0001.pala", tmp_path / "seg.0002.pala"
    w = PalaWriter(p1)
    w.genesis()
    span = w.session_start("session-r1")
    w.prefix_warm(token_count=64)
    w.session_end(span)

    head_at_cut = w.rotate(p2)

    span2 = w.session_start("session-r2")
    w.prefix_warm(token_count=8)
    w.session_end(span2)
    final_head = w.head
    w.close()

    combined = p1.read_bytes() + p2.read_bytes()
    result = pala.verify_headers(_headers(combined), expected_head=final_head)
    assert result.chain_ok and not result.breaks and not result.gaps, result
    assert head_at_cut == _last_head(p1.read_bytes())
    # the cut fell between records: both segments are themselves well-formed
    assert p2.stat().st_size > 0
    seqs = [pala.Header.decode(h).seq for h in _headers(combined)]
    assert seqs == list(range(len(seqs)))


def _last_head(data: bytes) -> bytes:
    last = b""
    for h, _ in pala.iter_records(data):
        last = pala.record_hash(h)
    return last


def test_rotation_emits_no_boot_and_keeps_the_boot_id(tmp_path):
    w = PalaWriter(tmp_path / "a.pala")
    w.genesis()
    w.rotate(tmp_path / "b.pala")
    w.prefix_warm(token_count=1)
    w.close()
    combined = (tmp_path / "a.pala").read_bytes() + (tmp_path / "b.pala").read_bytes()
    headers = [pala.Header.decode(h) for h in _headers(combined)]
    boots = {h.boot_id for h in headers}
    assert len(boots) == 1
    types = [h.record_type for h in headers]
    assert types.count(0x0002) == 0  # RT_BOOT never appears: same boot


def test_rotation_is_refused_while_a_span_is_open(tmp_path):
    w = PalaWriter(tmp_path / "a.pala")
    w.genesis()
    span = w.session_start("open-session")
    with pytest.raises(ValueError, match="rotation blocked"):
        w.rotate(tmp_path / "b.pala")
    w.session_end(span)
    w.rotate(tmp_path / "b.pala")  # now fine
    w.close()


def test_rotation_refuses_a_non_empty_target(tmp_path):
    other = tmp_path / "busy.pala"
    other.write_bytes(b"not empty")
    w = PalaWriter(tmp_path / "a.pala")
    w.genesis()
    with pytest.raises(ValueError, match="already holds bytes"):
        w.rotate(other)
    w.close()


def test_rotation_before_genesis_is_refused(tmp_path):
    w = PalaWriter(tmp_path / "a.pala")
    with pytest.raises(ValueError, match="no records yet"):
        w.rotate(tmp_path / "b.pala")
    w.close()


def test_resume_after_rotation_continues_the_chain(tmp_path):
    p1, p2 = tmp_path / "a.pala", tmp_path / "b.pala"
    w = PalaWriter(p1)
    w.genesis()
    w.rotate(p2)
    w.prefix_warm(token_count=2)
    w.close()

    resumed = PalaWriter.open_existing(p2)
    resumed.boot()
    resumed.prefix_warm(token_count=3)
    final = resumed.head
    resumed.close()

    combined = p1.read_bytes() + p2.read_bytes()
    result = pala.verify_headers(_headers(combined), expected_head=final)
    assert result.chain_ok and not result.breaks and not result.gaps, result


# ─── rotation policy (WS-ROT triggers) ──────────────────────────────────────


def _seg_headers(path):
    return _headers(path.read_bytes())


def _opens_with_continuation(path) -> bool:
    """The segment's first record is a SEGMENT_CONTINUATION (r6, kind 11)."""
    import struct

    hb, body = next(iter(pala.iter_records(path.read_bytes())))
    if pala.Header.decode(hb).record_type != 0x0012 or len(body) < 6:
        return False
    return struct.unpack_from("<HHH", body, 0) == (0x0001, 2, 11)


def test_policy_refuses_empty_and_nonpositive():
    from palimpsests.audit.pala_writer import RotationPolicy

    with pytest.raises(ValueError, match="rotates on nothing"):
        RotationPolicy()
    with pytest.raises(ValueError, match="must be positive"):
        RotationPolicy(max_records=0)
    with pytest.raises(ValueError, match="must be positive"):
        RotationPolicy(max_bytes=-1)


def test_max_records_cuts_and_the_manifest_stitches(tmp_path):
    import json
    from palimpsests.audit.pala_writer import RotationPolicy

    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=3))
    w.genesis()
    for _ in range(6):
        w.prefix_warm(token_count=1)
    final = w.head
    w.close()

    # GENESIS + 6 records, 3 per segment: every segment after the first
    # opens with its continuation record, which counts toward the 3 — so
    # [G,w,w] [c,w,w] [c,w,w] and an open fourth segment holding only its
    # continuation, written at the cut after the last record.
    s1, s2, s3 = (tmp_path / f"w.pala.0000{i}" for i in (1, 2, 3))
    assert s1.exists() and s2.exists() and s3.exists()
    assert all(_opens_with_continuation(f) for f in (s1, s2, s3))
    assert not _opens_with_continuation(base)
    manifest = json.loads((tmp_path / "w.pala.segments.json").read_text())
    assert manifest["format"] == "pala-segments/1"
    assert manifest["rotation"] == {"max_records": 3}
    entries = manifest["segments"]
    # closed segments only: the open one is never listed
    assert [e["file"] for e in entries] == ["w.pala", "w.pala.00001", "w.pala.00002"]
    assert [e["records"] for e in entries] == [3, 3, 3]
    assert entries[0]["prev_head"] == "00" * 32
    assert entries[1]["prev_head"] == entries[0]["head"]
    assert entries[2]["prev_head"] == entries[1]["head"]
    assert manifest["source_head"] == entries[2]["head"]

    # every closed segment verifies ALONE, seeded from the manifest
    for path, entry in ((base, entries[0]), (s1, entries[1]), (s2, entries[2])):
        r = pala.verify_headers(
            _seg_headers(path), start_prev=bytes.fromhex(entry["prev_head"])
        )
        assert r.chain_ok and r.head.hex() == entry["head"], (path, r)

    # and the byte concatenation is still one monolithic chain
    combined = base.read_bytes() + s1.read_bytes() + s2.read_bytes() + s3.read_bytes()
    r = pala.verify_headers(_headers(combined), expected_head=final)
    assert r.chain_ok and not r.breaks and not r.gaps, r


def test_due_cut_defers_to_the_span_boundary(tmp_path):
    from palimpsests.audit.pala_writer import RotationPolicy

    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=1))
    w.genesis()  # cut immediately after: segment 1 = [GENESIS]
    span = w.session_start("span-across")  # due at once, but the span is open
    w.prefix_warm(token_count=1)
    w.session_end(span)  # span closed -> the deferred cut happens here
    w.prefix_warm(token_count=1)
    w.close()

    # the span's three records share one file, after that file's
    # continuation record: the cut never severed the span
    span_file = tmp_path / "w.pala.00001"
    assert _opens_with_continuation(span_file)
    types = [pala.Header.decode(h).record_type for h in _seg_headers(span_file)]
    assert types[1:] == [0x0010, 0x0012, 0x0011]  # SPAN_START, EVENT, SPAN_END
    assert len(_seg_headers(base)) == 1  # GENESIS alone
    # the post-span record, after its own segment's continuation
    after = tmp_path / "w.pala.00002"
    assert _opens_with_continuation(after) and len(_seg_headers(after)) == 2


def test_max_bytes_cuts_between_records_never_inside(tmp_path):
    from palimpsests.audit.pala_writer import RotationPolicy

    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_bytes=1))
    w.genesis()  # one record already exceeds 1 byte -> cut after it, whole
    w.prefix_warm(token_count=1)
    w.close()
    assert len(_seg_headers(base)) == 1
    # the continuation record never triggers a cut of its own, or a byte
    # threshold below one record would loop forever: it is followed by
    # the record that then does
    s1, s2 = tmp_path / "w.pala.00001", tmp_path / "w.pala.00002"
    assert _opens_with_continuation(s1) and len(_seg_headers(s1)) == 2
    assert _opens_with_continuation(s2) and len(_seg_headers(s2)) == 1
    combined = base.read_bytes() + s1.read_bytes() + s2.read_bytes()
    assert pala.verify_headers(_headers(combined)).chain_ok


def test_max_age_measures_the_segment_on_the_monotonic_clock(tmp_path, monkeypatch):
    from palimpsests.audit import pala_writer as pw

    ticks = iter([0.0, 0.0] + [100.0] * 12)
    monkeypatch.setattr(pw, "_monotonic", lambda: next(ticks))
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=pw.RotationPolicy(max_age_s=60))
    w.genesis()  # age 0 -> no cut
    w.prefix_warm(token_count=1)  # age 100 >= 60 -> cut after this record
    w.prefix_warm(token_count=1)
    w.close()
    assert len(_seg_headers(base)) == 2
    s1 = tmp_path / "w.pala.00001"
    assert _opens_with_continuation(s1) and len(_seg_headers(s1)) == 2


def test_resume_extends_a_manifest_whose_link_checks_out(tmp_path):
    import json
    from palimpsests.audit.pala_writer import RotationPolicy

    policy = RotationPolicy(max_records=2)
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=policy)
    w.genesis()
    w.prefix_warm(token_count=1)  # 2 records -> cut; .00001 opens with its continuation
    w.prefix_warm(token_count=1)  # .00001 = [c, w] -> cut; .00002 = [c]
    w.close()

    # the closed segment is refused, and the refusal names where to go
    with pytest.raises(ValueError, match=r"closed segment.*w\.pala\.00002"):
        PalaWriter.open_existing(tmp_path / "w.pala.00001", rotation=policy)

    resumed = PalaWriter.open_existing(tmp_path / "w.pala.00002", rotation=policy)
    resumed.boot()  # .00002 = [c, BOOT] -> 2 records -> cut
    resumed.prefix_warm(token_count=1)  # .00003 = [c, w] -> cut; .00004 = [c]
    resumed.close()

    manifest = json.loads((tmp_path / "w.pala.segments.json").read_text())
    entries = manifest["segments"]
    assert [e["file"] for e in entries] == [
        "w.pala", "w.pala.00001", "w.pala.00002", "w.pala.00003",
    ]
    assert entries[2]["prev_head"] == entries[1]["head"]
    assert entries[3]["prev_head"] == entries[2]["head"]
    assert entries[2]["records"] == 2  # the resume scan counted the adopted continuation
    nxt = tmp_path / "w.pala.00004"
    assert nxt.exists() and _opens_with_continuation(nxt)


def test_a_foreign_manifest_at_the_base_is_refused(tmp_path):
    from palimpsests.audit.pala_writer import RotationPolicy

    base = tmp_path / "w.pala"
    (tmp_path / "w.pala.segments.json").write_text('{"format": "not-ours/9"}')
    with pytest.raises(ValueError, match="refusing to extend"):
        PalaWriter(base, rotation=RotationPolicy(max_records=3))
