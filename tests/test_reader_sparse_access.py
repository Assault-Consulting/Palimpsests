# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U16 — public sparse access: ``record_count``, ``record_at``,
``record_by_seq``, ``header_at``.

Three invariants, the same three the U14 header path keeps:

1. **Same answers.** Each record or header read sparsely equals the one
   the full decode produces for the same position.
2. **No materialisation.** On a cold reader none of the four fills the
   full decode cache; ``record_at`` decodes exactly the record asked for.
3. **One meaning per argument.** An index is a file position — never a
   seq, never counted from the end — and a seq the file does not hold is
   ``None``, not an error.
"""
from __future__ import annotations

import pytest
import threading
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from pathlib import Path


def _chain(tmp_path: Path) -> Path:
    log = tmp_path / "sparse.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    s1 = w.session_start("s1")
    w.model_load(b"\x11" * 32, b"\x22" * 32, role="engine.native")
    call = w.tool_call("web.search", args_digest=b"\x01" * 32)
    w.tool_result(w.seq - 1, call, 0, result_digest=b"\x02" * 32)
    w.incident_candidate(1, 2, detail="guard refusals exceeded")
    w.session_end(s1)
    w.anchor()
    w.close()
    return log


def _record_offsets(data: bytes) -> list[int]:
    """Where each record starts, by the container magic. Test-only: the
    fixtures below need to damage or repeat a specific record."""
    offs, at = [], 0
    while (at := data.find(b"PALA", at)) != -1:
        offs.append(at)
        at += 4
    return offs


# --- 1. same answers ----------------------------------------------------------


def test_every_position_agrees_with_the_full_decode(tmp_path):
    path = _chain(tmp_path)
    with AuditReader.open(path) as sparse, AuditReader.open(path) as full:
        everything = list(full.records())
        assert sparse.record_count == len(everything)
        for i, expected in enumerate(everything):
            assert sparse.record_at(i) == expected
            assert sparse.header_at(i) == expected.header
            assert sparse.record_by_seq(expected.seq) == expected


def test_after_a_full_decode_the_same_objects_are_returned(tmp_path):
    """One cache, not two: once records() has materialised the chain,
    record_at hands back those objects rather than decoding again."""
    with AuditReader.open(_chain(tmp_path)) as r:
        everything = list(r.records())
        assert all(r.record_at(i) is everything[i] for i in range(r.record_count))


def test_from_bytes_answers_the_same(tmp_path):
    path = _chain(tmp_path)
    with AuditReader.open(path) as a, AuditReader.from_bytes(path.read_bytes()) as b:
        assert a.record_count == b.record_count
        assert a.record_at(3) == b.record_at(3)


# --- 2. no materialisation -----------------------------------------------------


def test_a_cold_reader_never_fills_the_full_cache(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        n = r.record_count
        r.record_at(n // 2)
        r.record_by_seq(r.record_at(1).seq)
        r.header_at(n - 1)
        assert r._decoded is None


def test_record_at_decodes_only_what_it_is_asked_for(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        r.record_at(4)
        assert set(r._partial) == {4}
        r.record_at(4)
        assert set(r._partial) == {4}


def test_header_at_and_record_count_decode_nothing(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        r.header_at(2)
        assert r.record_count > 0
        assert r._partial == {}


def test_the_seq_index_is_built_once_under_concurrency(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        seen: list[int] = []

        def ask() -> None:
            r.record_by_seq(3)
            seen.append(id(r._first_pos_by_seq))

        threads = [threading.Thread(target=ask) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(seen)) == 1


# --- 3. one meaning per argument -----------------------------------------------


@pytest.mark.parametrize("bad", [-1, 10_000])
def test_an_index_outside_the_file_is_refused(tmp_path, bad):
    with AuditReader.open(_chain(tmp_path)) as r:
        with pytest.raises(IndexError):
            r.record_at(bad)
        with pytest.raises(IndexError):
            r.header_at(bad)


def test_the_last_valid_index_is_record_count_minus_one(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        assert r.record_at(r.record_count - 1).index == r.record_count - 1
        with pytest.raises(IndexError):
            r.record_at(r.record_count)


@pytest.mark.parametrize("bad", ["1", 1.0, True])
def test_an_index_that_is_not_an_int_is_refused(tmp_path, bad):
    """True is an int to Python and would silently mean position 1."""
    with AuditReader.open(_chain(tmp_path)) as r:
        with pytest.raises(TypeError):
            r.record_at(bad)
        with pytest.raises(TypeError):
            r.header_at(bad)


def test_a_seq_this_file_does_not_hold_is_none(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        assert r.record_by_seq(10_000) is None


def test_index_and_seq_part_across_a_gap(tmp_path):
    """Drop the record at position 1: every later record keeps its seq,
    and positions stay contiguous — so seq 1 is absent while position 1
    is the record carrying seq 2."""
    path = _chain(tmp_path)
    data = path.read_bytes()
    offs = _record_offsets(data)
    path.write_bytes(data[: offs[1]] + data[offs[2] :])
    with AuditReader.open(path) as r:
        assert r.record_by_seq(1) is None
        assert r.record_at(1).seq == 2
        assert r.record_by_seq(2).index == 1


def test_a_repeated_seq_answers_with_the_first_in_file_order(tmp_path):
    path = _chain(tmp_path)
    data = path.read_bytes()
    offs = _record_offsets(data)
    second = data[offs[1] : offs[2]]
    path.write_bytes(data[: offs[2]] + second + data[offs[2] :])
    with AuditReader.open(path) as r:
        assert r.record_at(1).seq == r.record_at(2).seq
        assert r.record_by_seq(r.record_at(1).seq).index == 1


def test_an_undecodable_header_reads_as_none_not_an_error(tmp_path):
    """An unknown format_version: reported, never rejected (§7.6). The
    sparse reads say the same thing DecodedRecord already says."""
    path = _chain(tmp_path)
    data = bytearray(path.read_bytes())
    at = _record_offsets(bytes(data))[3]
    data[at + 4 : at + 6] = (2).to_bytes(2, "little")  # format_version
    path.write_bytes(bytes(data))
    with AuditReader.open(path) as r:
        assert r.header_at(3) is None
        assert r.record_at(3).header is None
        assert r.header_at(2) is not None
