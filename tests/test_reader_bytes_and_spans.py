# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U30 and U31 — Auditor's requests for 0.14 (its UPSTREAM-REQUESTS-0_14.md).

U30: ``RecordFields.detail``, read in place, for a search over ``detail``.
U31: a record's bytes as stored, and where each TLV sits, for a hex view.

Every value is compared with what full decoding gives, on every record,
including records the decoder rejects — which is where the bytes matter
most, because there is nothing to re-encode.
"""
from __future__ import annotations

import pytest
import struct
from palimpsests.audit.pala import vectors
from palimpsests.audit.pala.codec import RT_AGGREGATE, RT_EVENT, Header, encode_tlvs
from palimpsests.audit.pala_writer import OUTCOME_OK, PalaWriter
from palimpsests.audit.profiles.inference import EVT_DETAIL, EVT_KIND, KIND_KV_SAVE
from palimpsests.audit.reader import AuditReader, RecordFields


def _detail_chain(path):
    """The detail edges: decode_record's rule has no minimum length."""
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        seq, h = w.tool_call("read", detail="a tool", return_seq=True)
        w.tool_result(seq, h, OUTCOME_OK)
        role = w._origin("engine.native")
        kind = (EVT_KIND, struct.pack("<H", KIND_KV_SAVE))
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs(
            [kind, (EVT_DETAIL, b"first"), (EVT_DETAIL, b"second")]))   # two: first wins
        bad_utf8 = (EVT_DETAIL, b"\xff\xfeok")
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([kind, bad_utf8]))
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([kind, (EVT_DETAIL, b"")]))   # empty: ""
        w._emit(RT_EVENT, tlvs=role, body=encode_tlvs([kind, (EVT_DETAIL, b"x")]))  # one byte
        w._emit(RT_AGGREGATE, body=encode_tlvs([(EVT_DETAIL, b"not a detail here")]))  # wrong type
    return path


def _damaged(tmp_path, source):
    """Three records the decoder handles differently, made by flipping bytes
    of a written chain: an encrypted body, an unknown format version, and
    header TLVs that overrun the header."""
    data = bytearray(source.read_bytes())
    with AuditReader.open(source) as r:
        offs = [r._headers._off[i] for i in range(r.record_count)]
        with_tlvs = [i for i in range(r.record_count) if r.header_at(i).tlvs]
        with_body = [i for i in range(r.record_count) if r.record_at(i).body_tlvs]
    overrun = with_tlvs[-1]
    version = next(i for i in with_tlvs if i != overrun)
    encrypted = next(i for i in with_body if i not in (overrun, version))
    assert len({overrun, version, encrypted}) == 3  # three different records, three cases
    struct.pack_into("<I", data, offs[encrypted] + 116, 7)          # key_id 7: ciphertext
    struct.pack_into("<H", data, offs[version] + 4, 2)              # format_version 2
    struct.pack_into("<H", data, offs[overrun] + 156 + 2, 0xFFF0)   # a TLV overrunning the header
    p = tmp_path / "damaged.pala"
    p.write_bytes(bytes(data))
    return p


def _chains(tmp_path):
    loops = tmp_path / "loops.pala"
    with PalaWriter(loops) as w:
        w.genesis()
        w.boot()
        for _ in range(20):
            seq, h = w.tool_call("read", args_digest=b"\x01" * 32, return_seq=True)
            w.tool_result(seq, h, OUTCOME_OK, result_digest=b"\x02" * 32)
    detail = _detail_chain(tmp_path / "detail.pala")
    out = [loops, detail, _damaged(tmp_path, detail)]
    for name in ("core", "inference"):
        p = tmp_path / f"{name}.pala"
        p.write_bytes(b"".join(
            bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex") or "")
            for r in vectors.load(name)["records"]))
        out.append(p)
    return out


def test_detail_equals_the_decoded_record_everywhere(tmp_path):
    for chain in _chains(tmp_path):
        with AuditReader.open(chain) as r:
            got = [r.record_fields_at(i) for i in range(r.record_count)]
            assert r._partial == {}
            for i, f in enumerate(got):
                d = r.record_at(i)
                assert f == RecordFields(d.kind, d.kind_name, d.source, d.source_name,
                                         d.outcome, d.outcome_name, d.detail), (chain.name, i)
    with AuditReader.open(tmp_path / "detail.pala") as r:
        details = [r.record_fields_at(i).detail for i in range(r.record_count)]
    assert details[-5:] == ["first", "\ufffd\ufffdok", "", "x", None]


def test_record_bytes_are_the_file(tmp_path):
    for chain in _chains(tmp_path):
        data = chain.read_bytes()
        with AuditReader.open(chain) as r:
            joined = b""
            for i in range(r.record_count):
                rb = r.record_bytes_at(i)
                assert data[rb.offset : rb.offset + len(rb.header) + len(rb.body)] == (
                    rb.header + rb.body)
                joined += rb.header + rb.body
                hdr = r.header_at(i)
                if hdr is not None:
                    # the decoder keeps every field and TLV: no accepted header
                    # re-encodes differently — the property, held on every record
                    assert Header.decode(rb.header) == hdr
                    assert rb.header == hdr.encode()
                    assert len(rb.body) == hdr.body_len
            assert joined == data
            assert r._partial == {}


def test_bytes_are_the_only_view_of_a_rejected_header(tmp_path):
    damaged = _damaged(tmp_path, _detail_chain(tmp_path / "d.pala"))
    with AuditReader.open(damaged) as r:
        rejected = [i for i in range(r.record_count) if r.header_at(i) is None]
        assert len(rejected) == 2  # the unknown version and the overrun
        sealed = [i for i in range(r.record_count)
                  if r.header_at(i) is not None and r.header_at(i).key_id]
        assert len(sealed) == 1 and r.body_tlv_spans_at(sealed[0]) is None
        assert r.record_bytes_at(sealed[0]).body  # the ciphertext, as stored
        for i in rejected:
            rb = r.record_bytes_at(i)
            assert rb.header and r.header_tlv_spans_at(i) is None


def test_tlv_maps_reproduce_what_the_decoder_lists(tmp_path):
    for chain in _chains(tmp_path):
        with AuditReader.open(chain) as r:
            for i in range(r.record_count):
                rb = r.record_bytes_at(i)
                whole = rb.header + rb.body
                hdr, d = r.header_at(i), r.record_at(i)
                hs = r.header_tlv_spans_at(i)
                assert (hs is None) == (hdr is None), (chain.name, i)
                if hs is not None:
                    assert [(t, whole[o:o + n]) for t, o, n in hs] == hdr.tlvs
                bs = r.body_tlv_spans_at(i)
                assert (bs is None) == (d.body_tlvs is None), (chain.name, i)
                if bs is not None:
                    assert [(t, whole[o:o + n]) for t, o, n in bs] == d.body_tlvs
                    assert all(o >= len(rb.header) for _, o, _ in bs)


def test_index_rules(tmp_path):
    with AuditReader.open(_detail_chain(tmp_path / "d.pala")) as r:
        for method in (r.record_bytes_at, r.header_tlv_spans_at, r.body_tlv_spans_at):
            with pytest.raises(IndexError):
                method(r.record_count)
            with pytest.raises(IndexError):
                method(-1)
            with pytest.raises(TypeError):
                method(True)
