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
