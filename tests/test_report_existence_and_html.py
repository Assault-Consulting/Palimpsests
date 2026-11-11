# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Two requests from Auditor before 0.14 (its UPSTREAM-REQUESTS-0.14, R5, R6).

R6: the report's existence note said "tier A: none available" — a limit of a
tier the report never reads. It now says what was checked: the WITNESS
records in this chain, and that receipts held outside it are not consulted.

R5: ``render_html`` joins channel 2 as the HTML rendering of a report's data.
"""
from __future__ import annotations

from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.report import build_report


def _chain(tmp_path):
    p = tmp_path / "a.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.kv_save(b"\x01" * 32)
    return p


def test_the_existence_note_says_what_was_checked_not_what_a_tier_allows(tmp_path):
    data = build_report(_chain(tmp_path)).data
    note = data["existence"]["note"]
    assert data["existence"]["external_pins"] == []
    assert "tier" not in note.lower()
    assert "no WITNESS record in this chain" in note
    assert "not consulted" in note


def test_render_html_is_declared_and_renders_a_report(tmp_path):
    import palimpsests.audit.report_html as rh

    assert rh.__all__ == ["render_html"]
    data = build_report(_chain(tmp_path)).data
    page = rh.render_html(data)
    assert isinstance(page, str) and page.lstrip().lower().startswith("<!doctype html")
    assert "no WITNESS record in this chain" in page  # the note travels into the page
    assert data["verdict"] in page


def test_an_empty_container_is_not_called_sound_as_far_as_checked(tmp_path):
    """The verdict word is the report's (``partial`` in format /1); the
    sentence beside it must not say an empty file is sound as far as checked."""
    import palimpsests.audit.report_html as rh

    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    data = build_report(p).data
    assert data["verdict"] == "partial" and data["diagnosis"]["pattern"] == "empty_container"
    page = rh.render_html(data)
    assert "PARTIAL" in page
    assert "sound as far as checked" not in page
    assert "holds no records" in page and "nothing was found intact" in page


def test_an_ordinary_partial_keeps_its_gloss(tmp_path):
    import palimpsests.audit.report_html as rh

    page = rh.render_html(build_report(_chain(tmp_path)).data)
    assert "sound as far as checked" in page
