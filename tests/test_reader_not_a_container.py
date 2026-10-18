# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U22 — a file that is not a PALA-1 container is diagnosed as one.

Before this, any file whose byte 0 was not the record magic — an image, a
JSON export, a text file — got ``truncated_tail``: "the container ends in
the middle of a record; consistent with a writer interrupted mid-write".
That blames a writer that never existed. Now it is ``not_a_container``.

The line is drawn at byte 0 and nowhere else. A file that opens with the
magic (or as much of it as the file holds) is a PALA-1 file that was cut,
and stays ``truncated_tail``; bytes that stop being records *after* valid
ones stay ``truncated_tail`` too, since a torn write can leave exactly
that. The verdict never changes — only the explanation does.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.pala.codec import MAGIC
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.report import build_report
from pathlib import Path

SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "docs/specs/report/pala-verification-report-1.schema.json"
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200


def _pattern(data: bytes) -> str | None:
    with AuditReader.from_bytes(data) as r:
        d = r.verify().diagnosis
    return d.pattern if d else None


def _chain(tmp_path: Path) -> bytes:
    log = tmp_path / "c.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.prefix_warm(token_count=1)
    w.close()
    return log.read_bytes()


# --- not a container -------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [PNG, b'{"records": []}', b"plain text, long enough to hold a header" * 4, b"XY"],
    ids=["png", "json", "text", "two-bytes"],
)
def test_bytes_that_do_not_open_with_the_magic_are_not_a_container(data):
    assert _pattern(data) == "not_a_container"


def test_the_diagnosis_never_blames_a_writer(tmp_path):
    with AuditReader.from_bytes(PNG) as r:
        d = r.verify().diagnosis
    assert d.at_seq is None
    assert "not a PALA-1 container" in d.narrative
    assert "interrupted mid-write" not in d.narrative


def test_the_verdict_is_unchanged_only_the_explanation(tmp_path):
    path = tmp_path / "x.png"
    path.write_bytes(PNG)
    rep = build_report(path)
    assert rep.data["verdict"] == "violation"
    assert rep.data["container"]["malformed"] == "bad magic at offset 0"
    assert rep.data["diagnosis"]["pattern"] == "not_a_container"
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(rep.data, json.loads(SCHEMA.read_text()))


# --- still truncated_tail: a PALA-1 file that was cut ----------------------------


def test_a_file_cut_inside_its_first_record_is_truncated(tmp_path):
    first = _chain(tmp_path)[:40]  # opens with the magic, cut in the header
    assert first.startswith(MAGIC)
    assert _pattern(first) == "truncated_tail"


@pytest.mark.parametrize("n", [1, 2, 3])
def test_a_file_cut_inside_the_magic_itself_is_truncated(n):
    """As much of the magic as the file holds is still the magic."""
    assert _pattern(MAGIC[:n]) == "truncated_tail"


def test_garbage_after_valid_records_stays_truncated(tmp_path):
    """Past byte 0 the line does not move: a torn write can leave this."""
    assert _pattern(_chain(tmp_path) + b"Z" * 200) == "truncated_tail"


def test_a_chain_cut_mid_record_stays_truncated(tmp_path):
    data = _chain(tmp_path)
    assert _pattern(data[:-5]) == "truncated_tail"


# --- unchanged on purpose ---------------------------------------------------------


def test_an_empty_file_is_left_as_it_was():
    """An empty file has no byte 0 to judge and is not truncated: no
    diagnosis, as before. Whether an empty file is a chain at all is a
    question for the core specification (§4.2 speaks of a first record),
    not for this diagnosis — see the PR."""
    assert _pattern(b"") is None


def test_a_whole_chain_has_no_diagnosis(tmp_path):
    assert _pattern(_chain(tmp_path)) is None
