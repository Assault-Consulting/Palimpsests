# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Edge and error paths of the audit reading layer.

These exercise the branches that the happy-path suites in
``test_audit_reader.py`` / ``test_tailing.py`` do not reach: empty and
malformed containers, the mmap lifecycle, an unreadable anchor source, an
undecodable (unknown-version) record, and the origin ``detail`` field. They
are ordinary reachable paths — no hardware, no native build.
"""

from __future__ import annotations

import struct
from palimpsests.audit.anchors import FileAnchor
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala.codec import FIXED_HEADER_LEN, MAGIC
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.tailing import TailingReader


def _chain(log):
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    span = w.session_start("s")
    w.model_load(
        model_digest=bytes(range(32)),
        config_digest=bytes(range(1, 33)),
        detail="qwen2.5-1.5b",
        span_id=span,
    )
    w.session_end(span)
    head = w.anchor()
    w.close()
    return log, head


# --------------------------------------------------------------------------- #
# AuditReader construction / lifecycle
# --------------------------------------------------------------------------- #


def test_open_empty_file(tmp_path):
    empty = tmp_path / "empty.pala"
    empty.touch()
    with AuditReader.open(empty) as r:
        v = r.verify()
    assert v.chain.count == 0


def test_open_context_manager_closes_mmap(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    r = AuditReader.open(log)
    with r:
        assert r.verify().chain.chain_ok is True
    # exiting the context closed the mmap+file; a second close is a no-op.
    r.close()


# --------------------------------------------------------------------------- #
# _walk truncation / garbage branches
# --------------------------------------------------------------------------- #


def test_walk_fixed_header_cut(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    data = log.read_bytes()
    # A complete chain plus a few trailing bytes < a fixed header.
    r = AuditReader.from_bytes(data + b"PA")
    assert r.verify().diagnosis.pattern == "truncated_tail"


def test_walk_bad_magic_midstream(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    recs = list(iter_records(log.read_bytes()))
    good = recs[0][0] + recs[0][1]
    # A full-header-sized block that is not a PALA record → bad magic branch.
    r = AuditReader.from_bytes(good + b"Z" * (FIXED_HEADER_LEN + 4))
    v = r.verify()
    assert v.diagnosis.pattern == "truncated_tail"
    assert "bad magic" in r._truncated_detail


def test_walk_header_len_below_fixed(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    recs = list(iter_records(log.read_bytes()))
    good = recs[0][0] + recs[0][1]
    # A second "record": valid magic, but header_len field below the fixed size.
    bad = bytearray(MAGIC + b"\x00" * (FIXED_HEADER_LEN + 4))
    struct.pack_into("<H", bad, 6, 10)  # header_len = 10 < 156
    r = AuditReader.from_bytes(good + bytes(bad))
    assert r.verify().diagnosis.pattern == "truncated_tail"
    assert "below fixed size" in r._truncated_detail


# --------------------------------------------------------------------------- #
# Anchor source that raises → recorded as an error attempt
# --------------------------------------------------------------------------- #


def test_anchor_source_error_is_recorded(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    garbage = tmp_path / "bad.head"
    garbage.write_text("not hex at all\n")
    r = AuditReader.open(log, anchor=FileAnchor(garbage))
    v = r.verify()
    assert v.anchor_attempts[0].outcome == "error"
    assert v.complete_to_anchor is None  # unreadable anchor → not checked
    r.close()


# --------------------------------------------------------------------------- #
# Undecodable (unknown-version) record → minimal DecodedRecord
# --------------------------------------------------------------------------- #


def test_unknown_version_record_decodes_minimally(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    recs = list(iter_records(log.read_bytes()))
    hb = bytearray(recs[0][0])
    struct.pack_into("<H", hb, 4, 2)  # format_version = 2 (unknown)
    data = bytes(hb) + recs[0][1]
    r = AuditReader.from_bytes(data)
    dr = next(iter(r.records()))
    assert dr.header is None  # did not decode
    assert dr.type_name is None
    assert dr.kind is None


# --------------------------------------------------------------------------- #
# origin_at detail field
# --------------------------------------------------------------------------- #


def test_origin_detail_is_extracted(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    r = AuditReader.open(log)
    load_seq = next(d.seq for d in r.records() if d.kind_name == "MODEL_LOAD")
    origin = r.origin_at(load_seq)
    assert origin.detail == "qwen2.5-1.5b"
    r.close()


# --------------------------------------------------------------------------- #
# TailingReader: missing file, and a second drain after a rollback diagnosis
# --------------------------------------------------------------------------- #


def test_tailing_missing_file_is_empty(tmp_path):
    tr = TailingReader(tmp_path / "does-not-exist.pala")
    assert tr._drain() == []
    tr.close()


def test_tailing_rollback_diagnosed_once(tmp_path):
    log, _ = _chain(tmp_path / "c.pala")
    tr = TailingReader(log, torn_grace=99)
    tr._drain()  # verify the whole chain
    data = log.read_bytes()
    log.write_bytes(data[: len(data) // 2])  # shrink below the verified head

    first = tr._drain()
    assert any(e.kind == "diagnosis" for e in first)
    # Already diagnosed: a further drain does not re-emit the same alarm.
    assert all(e.kind != "diagnosis" for e in tr._drain())
    tr.close()
