# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Every chain violation carries a code (U24).

Each of the ten codes is produced here from a real chain with exactly one
header field damaged, so the vocabulary is not a list someone typed but
the set the verifier actually emits. ``violations`` keeps its sentences,
unchanged; ``violation_codes`` runs parallel to it.
"""
from __future__ import annotations

import struct
from palimpsests.audit.pala import KNOWN_RECORD_TYPES
from palimpsests.audit.pala.incremental import VIOLATION_CODES, IncrementalVerifier
from palimpsests.audit.pala.verify import verify_headers
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader


def _headers(tmp_path):
    """GENESIS, BOOT (no body), MODEL_LOAD (a body, header TLVs)."""
    p = tmp_path / "c.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.model_load(b"\x01" * 32, b"\x02" * 32, detail="m")
    with AuditReader.open(p) as r:
        return [bytes(h) for h in r._headers]


def _put(hb: bytes, off: int, fmt: str, value) -> bytes:
    b = bytearray(hb)
    struct.pack_into(fmt, b, off, value)
    return bytes(b)


def _codes(headers) -> list[str]:
    res = verify_headers(headers)
    assert len(res.violation_codes) == len(res.violations)  # parallel, always
    assert [s for s, _ in res.violation_codes] == [s for s, _ in res.violations]
    return [c for _, c in res.violation_codes]


def test_each_code_is_emitted_for_its_violation(tmp_path):
    g, boot, load = _headers(tmp_path)
    seen: set[str] = set()

    def expect(code, headers):
        codes = _codes(headers)
        assert code in codes, (code, codes)
        seen.add(code)

    expect("prefix_absent", [boot, load])
    expect("genesis_prev_hash_nonzero", [_put(g, 36, "32s", b"\x09" * 32), boot, load])
    expect("genesis_not_first", [g, g, boot])
    expect("time_unknown_with_wall_clock", [g, _put(boot, 11, "B", 0), load])
    expect("time_trust_undefined", [g, _put(boot, 11, "B", 9), load])
    expect("empty_body_digest_nonzero", [g, _put(boot, 124, "32s", b"\x07" * 32), load])
    expect("nonempty_body_digest_zero", [g, boot, _put(load, 124, "32s", b"\x00" * 32)])
    short = _put(_put(load, 116, "<I", 3), 120, "<I", 5)  # key_id 3, body_len 5
    expect("encrypted_body_too_short", [g, boot, short])
    bad_tlv = boot + b"\x01\x00\xff\x00"  # a TLV claiming 255 bytes it does not have
    expect("malformed_tlv", [g, _put(bad_tlv, 6, "<H", len(bad_tlv)), load])

    v = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
    v.step(g)
    v.step(boot + b"\x00")  # header_len says one thing, the bytes another
    assert ("header_len_mismatch" in [c for _, c in v.result().violation_codes])
    seen.add("header_len_mismatch")

    assert seen == VIOLATION_CODES


def test_a_sound_chain_has_no_codes(tmp_path):
    assert _codes(_headers(tmp_path)) == []


def _bodiless(tmp_path):
    """GENESIS, BOOT, BOOT — no bodies, so the headers are the container."""
    p = tmp_path / "b.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.boot()
    with AuditReader.open(p) as r:
        return [bytes(h) for h in r._headers]


def test_the_diagnosis_carries_the_code(tmp_path):
    g, boot, boot2 = _bodiless(tmp_path)
    # the last record: damaging an earlier one would break the next link,
    # and a break is diagnosed before a violation
    data = g + boot + _put(boot2, 11, "B", 9)
    with AuditReader.from_bytes(data) as r:
        d = r.verify().diagnosis
    assert d.pattern == "record_violation" and d.code == "time_trust_undefined"
    assert "not a defined value" in d.expected  # the sentence is still there


def test_prefix_absent_is_decided_by_its_code(tmp_path):
    _g, boot, boot2 = _bodiless(tmp_path)
    with AuditReader.from_bytes(boot + boot2) as r:
        d = r.verify().diagnosis
    assert d.pattern == "prefix_absent" and d.code is None
