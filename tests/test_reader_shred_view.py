# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``decode_shred``: a KEY_SHRED's erasure note as fields (profile §8).

The published vectors describe that body in full — reason, targets, detail
— and the reader returned none of it as a field. The note is what the
writer declared; resolution against the chain stays where it was.
"""
from __future__ import annotations

import json
import struct
from palimpsests.audit.pala.codec import encode_tlvs
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.profiles.inference import (
    REASON_LEGAL_ERASURE,
    REASON_POLICY,
    REASON_RETENTION_EXPIRY,
    REASON_UNSPECIFIED,
    SHRED_DETAIL,
    SHRED_REASON,
    SHRED_TARGET_SEQS,
)
from palimpsests.audit.reader import (
    RT_KEY_SHRED,
    AuditReader,
    ShredView,
    decode_shred,
)
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs" / "specs" / "pala-1" / "profiles" / "inference-vectors.json"
)


def _vector_reader():
    v = json.loads(VECTORS.read_text(encoding="utf-8"))
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    return AuditReader.from_bytes(blob), v


def test_every_key_shred_in_the_vectors_decodes_to_its_published_semantics():
    reader, v = _vector_reader()
    expected = {
        int(seq): s for seq, s in v["semantics"].items()
        if isinstance(s, dict) and s.get("record_type") == "KEY_SHRED"
    }
    assert expected, "the vectors must describe at least one KEY_SHRED"
    with reader as r:
        seen = {}
        for dr in r.records():
            view = decode_shred(dr)
            if dr.record_type == RT_KEY_SHRED:
                assert view is not None
                seen[dr.seq] = view
            else:
                assert view is None  # nothing but a KEY_SHRED is one
    assert seen.keys() == expected.keys()
    for seq, sem in expected.items():
        view = seen[seq]
        assert view.seq == seq
        assert view.reason == sem["reason"]
        assert list(view.target_seqs) == sem["target_seqs"]
        assert view.detail == sem["detail"]


def _shreds(tmp_path, **kw):
    p = tmp_path / "s.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.key_shred(7, **kw)
    with AuditReader.open(p) as r:
        dr = r.record_at(r.record_count - 1)
        return dr, decode_shred(dr)


def test_what_the_writer_wrote_is_what_is_read(tmp_path):
    dr, view = _shreds(
        tmp_path, reason=REASON_RETENTION_EXPIRY, target_seqs=[1, 0], detail="policy P-4 §2"
    )
    assert view == ShredView(
        seq=dr.seq, key_id=7, reason=2, reason_name="retention_expiry",
        target_seqs=(1, 0), detail="policy P-4 §2",
    )  # targets as written: order kept, nothing resolved


def test_the_optional_parts_absent_are_empty_and_none(tmp_path):
    _dr, view = _shreds(tmp_path)
    assert view.reason == REASON_UNSPECIFIED and view.reason_name == "unspecified"
    assert view.target_seqs == () and view.detail is None


def test_every_reason_of_the_profile_has_its_name(tmp_path):
    import palimpsests.audit.reader as r

    assert r._SHRED_REASON_NAMES == {
        REASON_UNSPECIFIED: "unspecified",
        REASON_LEGAL_ERASURE: "legal_erasure",
        REASON_RETENTION_EXPIRY: "retention_expiry",
        REASON_POLICY: "policy",
    }


def test_a_reason_this_build_does_not_know_keeps_its_number(tmp_path):
    _dr, view = _shreds(tmp_path, reason=77)
    assert view.reason == 77 and view.reason_name is None


def test_the_record_s_own_detail_is_not_widened(tmp_path):
    """``DecodedRecord.detail`` is EVT_DETAIL on an EVENT or SAFETY body. A
    KEY_SHRED's reference is another tag in another namespace."""
    dr, view = _shreds(tmp_path, detail="erasure request E-17")
    assert dr.detail is None and dr.kind is None
    assert view.detail == "erasure request E-17"


def _key_shred_with_body(tmp_path, body: bytes):
    """A KEY_SHRED whose body is ``body``, written through the writer's own
    record path so the header binds it."""
    p = tmp_path / "raw.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w._emit(RT_KEY_SHRED, tlvs=[], body=body)
    with AuditReader.open(p) as r:
        assert r.verify().chain.chain_ok
        return r.record_at(r.record_count - 1)


def test_a_body_that_is_not_the_profile_s_note_is_not_usable(tmp_path):
    cases = {
        "no body": b"",
        "no reason": encode_tlvs([(SHRED_DETAIL, b"only a detail")]),
        "reason of the wrong width": encode_tlvs([(SHRED_REASON, b"\x01")]),
        "targets cut mid-number": encode_tlvs(
            [(SHRED_REASON, struct.pack("<H", 1)), (SHRED_TARGET_SEQS, b"\x00" * 12)]
        ),
    }
    for name, body in cases.items():
        sub = tmp_path / name.replace(" ", "-")
        sub.mkdir()
        assert decode_shred(_key_shred_with_body(sub, body)) is None, name


def test_a_note_without_a_declared_key_still_decodes(tmp_path):
    body = encode_tlvs([(SHRED_REASON, struct.pack("<H", REASON_POLICY))])
    view = decode_shred(_key_shred_with_body(tmp_path, body))
    assert view is not None and view.key_id is None and view.reason_name == "policy"


def test_the_note_and_the_resolution_are_two_answers(tmp_path):
    """A target that does not exist is in the note — it was declared — and
    not in ``shredded_targets()``, which holds only what resolved."""
    p = tmp_path / "t.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.key_shred(7, REASON_LEGAL_ERASURE, target_seqs=[999])
    with AuditReader.open(p) as r:
        view = decode_shred(r.record_at(r.record_count - 1))
        assert view.target_seqs == (999,)
        assert 999 not in r.shredded_targets()
        assert "shred_target_unresolved" in [i.code for i in r.verify().advisory.items]
