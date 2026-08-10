# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for the anchor boundary (Track C, C1+C2).

Covers the design sketch §12 "Anchors" row: manual hex validation;
FileAnchor round-trip with FileAnchorStore including atomic replace;
missing→None vs garbage→error; Chained order, raising-link survival, and
the last_attempts trace.
"""

from __future__ import annotations

import pytest
from palimpsests.audit.anchors import (
    AnchorReading,
    AnchorSource,
    AnchorSourceError,
    ChainedAnchorSource,
    FileAnchor,
    FileAnchorStore,
    ManualAnchor,
)

HEAD = bytes(range(32))
HEAD_HEX = HEAD.hex()
OTHER = bytes(range(32, 64))


# --------------------------------------------------------------------------- #
# AnchorReading
# --------------------------------------------------------------------------- #


def test_reading_rejects_wrong_length_head():
    with pytest.raises(ValueError):
        AnchorReading(
            head=b"\x00" * 31, source_kind="manual", source_detail="", observed_at_ns=None
        )


# --------------------------------------------------------------------------- #
# ManualAnchor — validates at construction
# --------------------------------------------------------------------------- #


def test_manual_valid_reads_back():
    src = ManualAnchor(HEAD_HEX)
    reading = src.current_head()
    assert reading is not None
    assert reading.head == HEAD
    assert reading.source_kind == "manual"
    assert reading.observed_at_ns is not None


def test_manual_rejects_bad_hex_at_construction():
    with pytest.raises(ValueError):
        ManualAnchor("nothex" * 10)


def test_manual_rejects_wrong_length_at_construction():
    with pytest.raises(ValueError):
        ManualAnchor("00" * 31)  # 31 bytes


def test_manual_tolerates_whitespace():
    assert ManualAnchor(f"  {HEAD_HEX}\n").current_head().head == HEAD


def test_manual_satisfies_protocol():
    assert isinstance(ManualAnchor(HEAD_HEX), AnchorSource)


# --------------------------------------------------------------------------- #
# FileAnchor + FileAnchorStore — round-trip, absence, garbage, atomicity
# --------------------------------------------------------------------------- #


def test_file_roundtrip_through_store(tmp_path):
    p = tmp_path / "anchor.head"
    FileAnchorStore(p).store_head(HEAD)
    reading = FileAnchor(p).current_head()
    assert reading is not None
    assert reading.head == HEAD
    assert reading.source_kind == "file"
    assert reading.source_detail == str(p)


def test_file_missing_is_absent_not_error(tmp_path):
    assert FileAnchor(tmp_path / "nope.head").current_head() is None


def test_file_garbage_is_error_not_absent(tmp_path):
    p = tmp_path / "bad.head"
    p.write_text("not a hex head at all\n")
    with pytest.raises(AnchorSourceError):
        FileAnchor(p).current_head()


def test_file_multiple_content_lines_is_error(tmp_path):
    p = tmp_path / "two.head"
    p.write_text(f"{HEAD_HEX}\n{OTHER.hex()}\n")
    with pytest.raises(AnchorSourceError):
        FileAnchor(p).current_head()


def test_file_comments_and_trailing_newline_tolerated(tmp_path):
    p = tmp_path / "c.head"
    p.write_text(f"# written by palimpsests\n# boot: abc\n{HEAD_HEX}\n\n")
    assert FileAnchor(p).current_head().head == HEAD


def test_store_meta_roundtrips_as_comments(tmp_path):
    p = tmp_path / "m.head"
    FileAnchorStore(p).store_head(HEAD, meta={"boot": "deadbeef", "count": "42"})
    body = p.read_text()
    assert "# boot: deadbeef" in body
    assert "# count: 42" in body
    assert FileAnchor(p).current_head().head == HEAD  # comments ignored on read


def test_store_overwrite_leaves_no_tmp(tmp_path):
    p = tmp_path / "a.head"
    store = FileAnchorStore(p)
    store.store_head(HEAD)
    store.store_head(OTHER)
    assert FileAnchor(p).current_head().head == OTHER
    assert not (tmp_path / "a.head.tmp").exists()


def test_store_rejects_wrong_length(tmp_path):
    with pytest.raises(ValueError):
        FileAnchorStore(tmp_path / "x.head").store_head(b"\x00" * 31)


# --------------------------------------------------------------------------- #
# ChainedAnchorSource — order, survival, trace
# --------------------------------------------------------------------------- #


class _Absent:
    source_kind = "absent-src"
    source_detail = "d0"

    def current_head(self) -> AnchorReading | None:
        return None


class _Raising:
    source_kind = "raising-src"
    source_detail = "d1"

    def current_head(self) -> AnchorReading | None:
        raise AnchorSourceError(
            "boom", source_kind=self.source_kind, source_detail=self.source_detail
        )


def test_chain_first_answer_wins():
    chain = ChainedAnchorSource([ManualAnchor(HEAD_HEX), ManualAnchor(OTHER.hex())])
    reading = chain.current_head()
    assert reading.head == HEAD
    assert reading.source_kind == "manual"


def test_chain_survives_raising_link_and_continues():
    chain = ChainedAnchorSource([_Raising(), ManualAnchor(HEAD_HEX)])
    reading = chain.current_head()
    assert reading.head == HEAD  # the manual answered despite the raising first link


def test_chain_records_full_trace():
    chain = ChainedAnchorSource([_Absent(), _Raising(), ManualAnchor(HEAD_HEX)])
    chain.current_head()
    outcomes = [(a.source_kind, a.outcome) for a in chain.last_attempts]
    assert outcomes == [
        ("absent-src", "absent"),
        ("raising-src", "error"),
        ("manual", "answered"),
    ]
    assert chain.last_attempts[1].error == "boom"


def test_chain_all_absent_returns_none():
    chain = ChainedAnchorSource([_Absent(), _Absent()])
    assert chain.current_head() is None
    assert [a.outcome for a in chain.last_attempts] == ["absent", "absent"]


def test_chain_stops_at_first_answer_no_later_attempts():
    chain = ChainedAnchorSource([ManualAnchor(HEAD_HEX), _Raising()])
    chain.current_head()
    # the raising link must never be reached once an answer is found
    assert [a.outcome for a in chain.last_attempts] == ["answered"]
