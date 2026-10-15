# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The reader's side of SEGMENT_CONTINUATION (profile r6 §3.2, design §3–§4).

Case A — the whole chain present: continuation records are ordinary
events, checked by the §4 advisories. Case B — the prefix gone: the
diagnosis names the declared continuation and whether the segments
manifest agrees; the core verdict never changes.
"""
from __future__ import annotations

import json
import os
import pytest
import struct
from palimpsests.audit.pala.codec import RT_EVENT, encode_tlvs
from palimpsests.audit.pala_writer import (
    EVT_KIND,
    KIND_SEGMENT_CONTINUATION,
    OUTCOME_OK,
    OUTCOME_UNOBSERVED,
    SEG_INDEX,
    SEG_PREDECESSOR_HEAD,
    SEG_PRIOR_ROOT,
    SEG_RETENTION_S,
    PalaWriter,
    RotationPolicy,
)
from palimpsests.audit.reader import AuditReader, decode_continuation
from palimpsests.audit.report import build_report
from pathlib import Path

SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "docs/specs/report/pala-verification-report-1.schema.json"
)


def _rotated(tmp_path, records=14):
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=4, retention_s=15_552_000))
    w.genesis()
    for _ in range(records - 1):
        w.prefix_warm(token_count=1)
    w.close()
    return base, [base] + sorted(tmp_path.glob("w.pala.0*"))


def _codes(reader):
    return [i.code for i in reader.verify().advisory.items]


def _valid(report):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(report.data, json.loads(SCHEMA.read_text()))


# ── Case A: the whole chain ────────────────────────────────────────────────


def test_a_whole_rotated_chain_reads_clean(tmp_path):
    _, segs = _rotated(tmp_path)
    data = b"".join(s.read_bytes() for s in segs)
    with AuditReader.from_bytes(data) as r:
        ver = r.verify()
        assert ver.chain.chain_ok and ver.diagnosis is None
        assert not [c for c in _codes(r) if c.startswith("continuation_")]
        views = [
            decode_continuation(d) for d in r.records() if d.kind_name == "SEGMENT_CONTINUATION"
        ]
        assert [v.segment_index for v in views] == list(range(1, len(segs)))
        assert all(v.retention_s == 15_552_000 for v in views)


def _forged(tmp_path, bodies):
    """GENESIS, one event, then hand-made kind-11 records."""
    p = tmp_path / "forged.pala"
    w = PalaWriter(p)
    w.genesis()
    w.prefix_warm(token_count=1)
    for make in bodies:
        w._emit(RT_EVENT, tlvs=w._origin("engine.native"), body=encode_tlvs(make(w)))
    w.close()
    return p


def _body(pred, index, root, retention=0):
    return [
        (EVT_KIND, struct.pack("<H", KIND_SEGMENT_CONTINUATION)),
        (SEG_PREDECESSOR_HEAD, pred),
        (SEG_INDEX, struct.pack("<I", index)),
        (SEG_RETENTION_S, struct.pack("<Q", retention)),
        (SEG_PRIOR_ROOT, root),
    ]


def test_each_section_4_check_names_what_is_wrong(tmp_path):
    p = _forged(tmp_path, [
        lambda w: _body(w.head, 1, w._frontier.root()),  # sound
        lambda w: _body(b"\x00" * 32, 2, w._frontier.root()),  # predecessor != prev_hash
        lambda w: _body(w.head, 4, w._frontier.root()),  # 2 -> 4: a gap, whole chain here
        lambda w: _body(w.head, 4, b"\x11" * 32),  # not increasing; root wrong
        lambda w: _body(w.head, 9, w._frontier.root())[:3],  # malformed: tags missing
    ])
    with AuditReader.open(p) as r:
        codes = _codes(r)
        assert r.verify().chain.chain_ok  # the chain itself is sound throughout
    assert codes.count("continuation_predecessor_mismatch") == 1
    assert codes.count("continuation_index_gap") == 1
    assert codes.count("continuation_index_not_increasing") == 1
    assert codes.count("continuation_prior_root_mismatch") == 1
    assert codes.count("continuation_malformed") == 1


def test_the_prior_root_is_checked_against_the_records_not_itself(tmp_path):
    # the writer's own continuations, re-verified from the bytes
    _, segs = _rotated(tmp_path)
    data = b"".join(s.read_bytes() for s in segs)
    with AuditReader.from_bytes(data) as r:
        assert "continuation_prior_root_mismatch" not in _codes(r)
    # and a continuation whose root covers one record fewer than it should:
    # internally plausible, wrong against the records themselves
    p = _forged(tmp_path, [lambda w: _body(w.head, 1, _root_of_first(w, 1))])
    with AuditReader.open(p) as r:
        assert "continuation_prior_root_mismatch" in _codes(r)


def _root_of_first(w, n):
    from palimpsests.audit.pala.frontier import MerkleFrontier

    with open(w.path, "rb") as fh:
        data = fh.read()
    from palimpsests.audit import pala

    return MerkleFrontier.from_record_hashes(
        pala.record_hash(h) for h, _ in list(pala.iter_records(data))[:n]
    ).root()


def test_a_chain_without_continuations_pays_nothing_for_them(tmp_path, monkeypatch):
    import palimpsests.audit.pala.frontier as fr

    p = tmp_path / "plain.pala"
    with PalaWriter(p) as w:
        w.genesis()
        for _ in range(50):
            w.prefix_warm(token_count=1)

    class _Boom:
        def __init__(self, *a, **k):
            raise AssertionError("a frontier was built for a chain with no continuations")

    monkeypatch.setattr(fr, "MerkleFrontier", _Boom)
    with AuditReader.open(p) as r:
        assert r.verify().chain.chain_ok


# ── Case B: the prefix is gone ─────────────────────────────────────────────


def _survivor(tmp_path):
    base, segs = _rotated(tmp_path)
    for old in segs[:-1]:
        os.remove(old)
    return segs[-1]


def test_case_b_names_the_declared_continuation_and_the_manifest_agrees(tmp_path):
    last = _survivor(tmp_path)
    rep = build_report(last)
    d = rep.data["diagnosis"]
    assert rep.data["verdict"] == "violation"  # the core verdict is unchanged (D1)
    assert d["pattern"] == "declared_continuation"
    assert "names the same predecessor" in d["narrative"]
    assert "not verified here" in d["narrative"]
    _valid(rep)


def test_case_b_without_a_manifest_is_declared_only(tmp_path):
    last = _survivor(tmp_path)
    (tmp_path / "w.pala.segments.json").unlink()
    d = build_report(last).data["diagnosis"]
    assert d["pattern"] == "declared_continuation"
    assert "unconfirmed" in d["narrative"]


def test_case_b_against_a_manifest_that_disagrees_is_a_finding(tmp_path):
    last = _survivor(tmp_path)
    mf_path = tmp_path / "w.pala.segments.json"
    mf = json.loads(mf_path.read_text())
    mf["segments"][-1]["head"] = "ab" * 32
    mf_path.write_text(json.dumps(mf))
    rep = build_report(last)
    assert rep.data["diagnosis"]["pattern"] == "continuation_contradicts_manifest"
    assert rep.data["verdict"] == "violation"
    _valid(rep)


def test_a_segment_that_declares_nothing_keeps_the_plain_diagnosis(tmp_path):
    # a knife-made segment: cut after the fact, so its first record is an
    # ordinary event and the absence stays unexplained
    from palimpsests.audit.pala.segments import segment_chain

    p = tmp_path / "plain.pala"
    with PalaWriter(p) as w:
        w.genesis()
        for _ in range(9):
            w.prefix_warm(token_count=1)
    out = tmp_path / "knife"
    res = segment_chain(p, out, records_per_segment=4)
    d = build_report(out / res.segments[-1].file).data["diagnosis"]
    assert d["pattern"] == "prefix_absent"


# ── outcome names ──────────────────────────────────────────────────────────


def test_outcomes_are_named_and_only_on_results(tmp_path):
    p = tmp_path / "o.pala"
    with PalaWriter(p) as w:
        w.genesis()
        c1 = w.tool_call("shell.exec")
        w.tool_result(1, c1, OUTCOME_UNOBSERVED)
        c2 = w.tool_call("fs.read")
        w.tool_result(3, c2, OUTCOME_OK)
    with AuditReader.open(p) as r:
        recs = list(r.records())
    by_kind = [(d.kind_name, d.outcome, d.outcome_name) for d in recs if d.kind_name]
    assert ("TOOL_RESULT", 4, "unobserved") in by_kind
    assert ("TOOL_RESULT", 0, "ok") in by_kind
    assert all(o is None for k, o, _ in by_kind if k == "TOOL_CALL")
