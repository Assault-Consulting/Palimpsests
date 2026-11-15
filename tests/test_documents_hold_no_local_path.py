# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A report and a bundle are made to be sent; neither holds a path of the
machine that made it.

Report ``/2`` settled this for the segments manifest, which it names by file
name. The anchor file was left out of that rule: read against a
``FileAnchor``, the report's ``anchor.source_detail`` and the bundle's
``verification.json`` carried the anchor file's full path — a directory
layout and, in a home directory, a user name.
"""
from __future__ import annotations

import json
import pytest
import tarfile
from palimpsests.audit import anchors
from palimpsests.audit.anchors import ChainedAnchorSource, FileAnchor, ManualAnchor
from palimpsests.audit.pala.bundle import assemble_bundle
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.report import build_report
from palimpsests.audit.report_html import render_html

SECRET_DIR = "home-of-a-named-user"


@pytest.fixture
def chain(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    for _ in range(4):
        w.prefix_warm(token_count=5)
    w.close()
    with AuditReader.open(log) as r:
        head = r.verify().chain.head
    private = tmp_path / SECRET_DIR
    private.mkdir()
    good = private / "head.anchor"
    good.write_text(head.hex() + "\n", encoding="utf-8")
    broken = private / "broken.anchor"
    broken.write_text("not hex\nand two lines\n", encoding="utf-8")
    unreadable = private / "a-directory.anchor"
    unreadable.mkdir()  # reading it is an OSError whose text quotes the path
    return log, head, good, broken, unreadable


def _verification(tar_path) -> dict:
    with tarfile.open(tar_path) as tar:
        return json.loads(tar.extractfile("verification.json").read())


def test_the_report_names_the_anchor_file_and_not_its_directory(chain):
    log, _head, good, _b, _u = chain
    report = build_report(log, anchor_source=FileAnchor(good))
    assert report.data["verdict"] == "sound"
    assert report.data["anchor"]["source_detail"] == "head.anchor"
    assert SECRET_DIR not in json.dumps(report.data)
    assert SECRET_DIR not in render_html(report.data)


def test_the_bundle_names_the_anchor_file_and_not_its_directory(chain, tmp_path):
    log, _head, good, _b, _u = chain
    out = tmp_path / "b.tar"
    assemble_bundle(log, out, anchor_source=FileAnchor(good))
    ver = _verification(out)
    assert ver["anchor"]["source_detail"] == "head.anchor"
    assert [a["source_detail"] for a in ver["anchor_attempts"]] == ["head.anchor"]
    assert SECRET_DIR.encode() not in out.read_bytes()


def test_an_attempt_that_failed_does_not_carry_the_path_in_its_error(chain, tmp_path):
    """The operating system's message quotes the path it could not read."""
    log, head, good, broken, unreadable = chain
    source = lambda: ChainedAnchorSource(  # noqa: E731
        [FileAnchor(unreadable), FileAnchor(broken), FileAnchor(good)])
    # the premise: the reader's own attempts do carry the path, locally
    with AuditReader.open(log, anchor=source()) as r:
        local = r.verify().anchor_attempts
    assert [a.outcome for a in local] == ["error", "error", "answered"]
    assert all(SECRET_DIR in a.source_detail for a in local)
    assert SECRET_DIR in local[0].error

    report = build_report(log, anchor_source=source())
    assert [a["outcome"] for a in report.data["anchor"]["attempts"]] == [
        "error", "error", "answered"]
    assert "a-directory.anchor" in report.data["anchor"]["attempts"][0]["error"]
    assert SECRET_DIR not in json.dumps(report.data)

    out = tmp_path / "b.tar"
    assemble_bundle(log, out, anchor_source=source())
    ver = _verification(out)
    assert [a["source_detail"] for a in ver["anchor_attempts"]] == [
        "a-directory.anchor", "broken.anchor", "head.anchor"]
    assert SECRET_DIR.encode() not in out.read_bytes()


def test_a_bundle_is_the_same_bytes_wherever_the_anchor_file_lay(chain, tmp_path):
    """Same source, same range, same anchor answer: the same archive. With
    the path inside, two machines made two archives."""
    log, head, good, _b, _u = chain
    elsewhere = tmp_path / "another" / "place"
    elsewhere.mkdir(parents=True)
    (elsewhere / "head.anchor").write_text(head.hex() + "\n", encoding="utf-8")
    a, b = tmp_path / "a.tar", tmp_path / "b.tar"
    assemble_bundle(log, a, anchor_source=FileAnchor(good))
    assemble_bundle(log, b, anchor_source=FileAnchor(elsewhere / "head.anchor"))
    assert a.read_bytes() == b.read_bytes()


def test_a_detail_that_is_not_a_path_is_left_alone(chain):
    log, head, _g, _b, _u = chain
    report = build_report(log, anchor_source=ManualAnchor(head.hex(), detail="ticket/4521"))
    assert report.data["anchor"]["source_detail"] == "ticket/4521"


@pytest.mark.parametrize(("path", "name"), [
    ("/home/user/keys/head.anchor", "head.anchor"),
    (r"C:\Users\user\keys\head.anchor", "head.anchor"),
    (r"\\server\share\head.anchor", "head.anchor"),
    ("head.anchor", "head.anchor"),
    ("relative/dir/head.anchor", "head.anchor"),
])
def test_paths_of_either_convention_reduce_to_the_file_name(path, name):
    assert anchors._portable_detail("file", path) == name
    assert anchors._portable_detail("manual", path) == path
    error = f"anchor file could not be read: [Errno 13] Permission denied: {path!r}"
    reduced = anchors._portable_error("file", path, error)
    assert reduced.endswith(f"'{name}'") and "user" not in reduced
    assert anchors._portable_error("file", path, None) is None
