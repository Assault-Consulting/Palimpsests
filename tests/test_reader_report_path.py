# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U14 PR-6 — the report path reads headers, not the whole chain.

Three invariants, each pinned on chains that exercise the edges the
views care about — several boots, a resume with a
``RECOVERY_TRUNCATED_TAIL``, open and closed spans, an oversight
candidate/ack pair, and the published companion vectors (encrypted body,
KEY_SHRED, tool loop, reported pair):

1. **Same answers.** ``boots()``, ``spans()`` and the safety section on
   a cold reader (no ``verify()``, no ``records()``) equal those on a
   reader whose decode cache is warm. The header-only path and the
   decoded path are two readings of the same bytes and must not drift.
2. **No materialisation.** On a cold reader the views leave the decode
   cache untouched — the whole point of the change.
3. **The report is one report.** ``build_report`` with ``reader=`` and
   without it produce identical JSON apart from the clock, and the
   ``sha256`` over the reader's own buffer equals the file's.
"""
from __future__ import annotations

import json
import struct
from hashlib import sha256
from palimpsests.audit.pala_writer import EVT_KIND, KIND_INCIDENT_CANDIDATE, PalaWriter
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.report import _safety_section, build_report
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _busy_chain(tmp_path: Path) -> Path:
    log = tmp_path / "busy.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    s1 = w.session_start("s1")
    w.model_load(b"\x11" * 32, b"\x22" * 32, role="engine.native")
    call = w.tool_call("web.search", args_digest=b"\x01" * 32)
    w.tool_result(w.seq - 1, call, 0, result_digest=b"\x02" * 32)
    w.session_end(s1)
    w.session_start("s2")  # left open on purpose: visibly unclosed
    w.close()
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 20)  # torn tail
    w2 = PalaWriter.open_existing(log)
    w2.boot()
    w2.recovery_truncated_tail()
    s3 = w2.session_start("s3")
    cand = w2.incident_candidate(1, 2, recoverable=True, detail="guard refusals exceeded")
    w2.oversight_ack(w2.seq - 1, cand, 0, b"\x0e" * 16)
    w2.incident_candidate(1, 1, recoverable=True, detail="a second, unacknowledged one")
    w2.session_end(s3)
    w2.close()
    return log


def _vectors_chain(tmp_path: Path) -> Path:
    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    p = tmp_path / "vectors.pala"
    p.write_bytes(blob)
    return p


def _cold_and_warm(path: Path) -> tuple[AuditReader, AuditReader]:
    cold = AuditReader.open(path)
    warm = AuditReader.open(path)
    list(warm.records())  # materialise the whole chain
    return cold, warm


def test_views_agree_cold_and_warm_and_do_not_materialise(tmp_path):
    for path in (_busy_chain(tmp_path), _vectors_chain(tmp_path)):
        cold, warm = _cold_and_warm(path)
        assert cold.boots() == warm.boots()
        assert cold.spans() == warm.spans()
        assert _safety_section(cold) == _safety_section(warm)
        assert cold.acknowledged_candidates() == warm.acknowledged_candidates()
        assert cold._decoded is None, "the views must not decode the chain"
        # and once verify() has warmed the cache, the same objects come back
        cold.verify()
        assert cold.boots() == warm.boots() and cold.spans() == warm.spans()
        cold.close()
        warm.close()


def test_busy_chain_edges_are_seen_by_the_header_path(tmp_path):
    r = AuditReader.open(_busy_chain(tmp_path))
    boots = r.boots()
    assert len(boots) == 2
    assert boots[0].recovery_seq is None
    assert boots[1].recovery_seq is not None  # found by the in-place kind probe
    spans = r.spans()
    assert [s.end_seq is None for s in spans] == [False, True, False]
    safety = _safety_section(r)
    assert safety["count"] == 3
    assert safety["unacknowledged_candidates"] == 1
    assert r._decoded is None
    r.close()


def test_kind_probe_matches_full_decode_on_every_record(tmp_path):
    for path in (_busy_chain(tmp_path), _vectors_chain(tmp_path)):
        r = AuditReader.open(path)
        probed = [r._kind_probe(i, hb) for i, hb in enumerate(r._headers)]
        assert r._decoded is None
        decoded = [dr.kind for dr in r.records()]
        assert probed == decoded
        r.close()


def test_kind_probe_falls_back_when_evt_kind_is_not_first(tmp_path):
    # A well-formed but unusually ordered body: EVT_DETAIL before EVT_KIND.
    # The profile says EVT_KIND comes first; the probe must still answer
    # what a full decode answers rather than guess from the wrong TLV.
    from palimpsests.audit.pala.codec import encode_tlvs

    log = tmp_path / "odd.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    body = encode_tlvs(
        [(0x0004, b"detail first"), (EVT_KIND, struct.pack("<H", KIND_INCIDENT_CANDIDATE))]
    )
    w._emit(0x0040, body=body)  # SAFETY, via the writer's own emit path
    w.close()
    r = AuditReader.open(log)
    probed = [r._kind_probe(i, hb) for i, hb in enumerate(r._headers)]
    assert probed == [dr.kind for dr in r.records()]
    assert probed[-1] == KIND_INCIDENT_CANDIDATE
    r.close()


def test_report_is_identical_with_and_without_a_reader(tmp_path):
    path = _busy_chain(tmp_path)
    with AuditReader.open(path) as r:
        with_reader = json.loads(build_report(path, reader=r).to_json_bytes())
    without = json.loads(build_report(path).to_json_bytes())
    for d in (with_reader, without):
        d["checked_at"]["wall_ns"] = 0
    assert with_reader == without
    assert with_reader["subject"]["sha256"] == sha256(path.read_bytes()).hexdigest()
    assert with_reader["subject"]["first_seq"] == 0
    assert with_reader["subject"]["last_seq"] == with_reader["subject"]["records"] - 1
    assert with_reader["safety"]["count"] == 3
