# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U14 PR-8 — the ``_walk()`` floor.

``_walk()`` used to copy every header out of the container into its own
``bytes`` object and keep all of them for the reader's lifetime; that
per-record object was the memory floor under everything else. The
headers are now a sequence over three offset/length arrays, sliced on
access. Pinned here:

1. ``_headers`` behaves as the list it replaces — same length, same
   ``bytes`` per index (negative indices and slices included), same
   iteration — on a busy chain, on the companion vectors, and on a chain
   whose last record is torn.
2. The in-place field view (``fields_at``) gives exactly what the
   bytes-based view gave, record by record, including ``None`` for a
   header that does not decode (unknown format version) and for
   malformed TLVs.
3. ``structure()`` (one pass) returns what ``boots()`` and ``spans()``
   returned as two passes, and the report is still one report.
"""
from __future__ import annotations

import json
import struct
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader, _header_fields
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _busy(tmp_path: Path) -> Path:
    log = tmp_path / "busy.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    s1 = w.session_start("s1")
    w.model_load(b"\x11" * 32, b"\x22" * 32, role="engine.native")
    for _ in range(50):
        w.kv_save(b"\x33" * 32)
    call = w.tool_call("web.search", args_digest=b"\x01" * 32)
    w.tool_result(w.seq - 1, call, 0, result_digest=b"\x02" * 32)
    w.session_end(s1)
    w.session_start("s2")
    w.close()
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)  # torn tail
    w2 = PalaWriter.open_existing(log)
    w2.boot()
    w2.recovery_truncated_tail()
    w2.incident_candidate(1, 2)
    w2.close()
    return log


def _vectors(tmp_path: Path) -> Path:
    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    p = tmp_path / "vectors.pala"
    p.write_bytes(blob)
    return p


def _torn(tmp_path: Path) -> Path:
    src = _vectors(tmp_path).read_bytes()
    p = tmp_path / "torn.pala"
    p.write_bytes(src[: len(src) - 40])  # last record cut mid-way
    return p


def _reference_headers(data: bytes) -> list[bytes]:
    """The old ``_walk()``: copy each header out, stop at a torn record."""
    out, off, n = [], 0, len(data)
    while off < n:
        if off + 156 > n or data[off : off + 4] != b"PALA":
            break
        (hlen,) = struct.unpack_from("<H", data, off + 6)
        (blen,) = struct.unpack_from("<I", data, off + 120)
        if hlen < 156 or off + hlen + blen > n:
            break
        out.append(bytes(data[off : off + hlen]))
        off += hlen + blen
    return out


def test_header_sequence_is_the_list_it_replaces(tmp_path):
    for path in (_busy(tmp_path), _vectors(tmp_path), _torn(tmp_path)):
        ref = _reference_headers(path.read_bytes())
        for r in (AuditReader.open(path), AuditReader.from_bytes(path.read_bytes())):
            hs = r._headers
            assert len(hs) == len(ref)
            assert list(hs) == ref
            assert [hs[i] for i in range(len(ref))] == ref
            assert hs[-1] == ref[-1] and hs[0] == ref[0]
            assert hs[2:5] == ref[2:5] and hs[-3:] == ref[-3:]
            for i, hb in enumerate(ref):
                assert hs.seq_at(i) == struct.unpack_from("<Q", hb, 12)[0]
                assert hs.record_type_at(i) == struct.unpack_from("<H", hb, 8)[0]
                assert hs.key_id_at(i) == struct.unpack_from("<I", hb, 116)[0]
            r.close()


def test_in_place_fields_equal_the_bytes_view_including_rejects(tmp_path):
    path = _busy(tmp_path)
    data = bytearray(path.read_bytes())
    # corrupt one record's format_version and another's TLV length so the
    # accept/reject rule is exercised on both sides
    hs = AuditReader.from_bytes(bytes(data))._headers
    off_v = hs._off[3]
    data[off_v + 4 : off_v + 6] = struct.pack("<H", 9)  # unknown version
    off_t = hs._off[5]
    hlen_t = hs._hlen[5]
    if hlen_t > 156:
        data[off_t + 158 : off_t + 160] = struct.pack("<H", 60000)  # TLV overruns
    r = AuditReader.from_bytes(bytes(data))
    for i, hb in enumerate(r._headers):
        a = _header_fields(hb)
        b = r._headers.fields_at(i)
        if a is None:
            assert b is None, i
        else:
            assert b is not None
            assert (a.record_type, a.time_trust, a.seq, a.boot_id, a.span_id, a.parent_span_id) == (
                b.record_type,
                b.time_trust,
                b.seq,
                b.boot_id,
                b.span_id,
                b.parent_span_id,
            )
    assert r._headers.fields_at(3) is None
    if hlen_t > 156:
        assert r._headers.fields_at(5) is None and _header_fields(r._headers[5]) is None


def test_one_pass_structure_equals_the_two_views(tmp_path):
    for path in (_busy(tmp_path), _vectors(tmp_path)):
        cold = AuditReader.open(path)
        boots, spans = cold.structure()
        assert boots == cold.boots() and spans == cold.spans()
        warm = AuditReader.open(path)
        list(warm.records())
        assert (boots, spans) == warm.structure()
        assert cold._decoded is None
        assert len(boots) == (2 if path.name == "busy.pala" else 1)
        cold.close()
        warm.close()
