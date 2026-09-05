# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U14 PR-7 — ``verify()`` no longer materialises the chain.

Two changes, each pinned by contract, not by timing:

* **One header pass (D1).** ``verify_headers_with_advisory`` returns the
  §7.1 verdict and the ``IncrementalVerifier`` advisory from a single
  stepping of the headers; the reader used to step a second verifier
  over the same headers to read the advisory the first had thrown away.
  Pinned: equal to ``verify_headers`` plus a separately stepped verifier
  on the companion vectors and on a chain that halts mid-way.

* **A bounded referential pass.** Only records that carry a reference,
  and the records they name, are decoded. Pinned: the advisory on a
  cold reader equals the advisory on a reader that materialised the
  whole chain first, for every referential code the reader knows how to
  emit; a cold ``verify()`` leaves the full decode cache empty; and the
  number of records decoded on a chain that mixes one reference into
  many bystanders is the number of records the reference involves.
"""
from __future__ import annotations

import json
from palimpsests.audit.pala import verify_headers
from palimpsests.audit.pala.codec import KNOWN_RECORD_TYPES
from palimpsests.audit.pala.incremental import IncrementalVerifier
from palimpsests.audit.pala.verify import verify_headers_with_advisory
from palimpsests.audit.pala_writer import (
    DISP_ACKNOWLEDGED,
    REASON_LEGAL_ERASURE,
    PalaWriter,
)
from palimpsests.audit.reader import AuditReader
from pathlib import Path

OPERATOR = b"\x0e" * 16
VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _vector_headers() -> list[bytes]:
    v = json.loads(VECTORS.read_text())
    return [bytes.fromhex(r["header_hex"]) for r in v["records"]]


def _items(ver):
    return [(i.code, i.at_seq, i.boot_id, i.detail) for i in ver.advisory.items]


# ── D1: one pass, same two answers ──────────────────────────────────────


def _two_pass(headers):
    result = verify_headers(headers)
    v = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
    for hb in headers:
        v.step(hb)
    return result, v.advisory()


def test_single_pass_equals_the_old_two_passes_on_the_vectors():
    headers = _vector_headers()
    r1, a1 = verify_headers_with_advisory(headers)
    r2, a2 = _two_pass(headers)
    assert r1 == r2
    assert a1.items == a2.items


def test_single_pass_equals_two_passes_when_the_chain_halts():
    headers = _vector_headers()
    headers.insert(5, b"NOTPALA" + b"\x00" * 200)  # unparseable: the verifier halts
    headers.append(_vector_headers()[3])  # never reached by either
    r1, a1 = verify_headers_with_advisory(headers)
    r2, a2 = _two_pass(headers)
    assert r1 == r2 and not r1.chain_ok
    assert a1.items == a2.items


# ── bounded referential pass: cold == warm for every referential code ───


def _chains(tmp_path: Path) -> list[Path]:
    out = []

    log = tmp_path / "dangling.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.oversight_ack(999, b"\xab" * 32, DISP_ACKNOWLEDGED, OPERATOR)
    out.append(log)

    log = tmp_path / "mismatch.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.incident_candidate(1, 2)
        w.oversight_ack(w.seq - 1, b"\xcd" * 32, DISP_ACKNOWLEDGED, OPERATOR)
    out.append(log)

    log = tmp_path / "not-a-candidate.pala"
    with PalaWriter(log) as w:
        w.genesis()
        boot_hash = w.boot()
        w.oversight_ack(w.seq - 1, boot_hash, DISP_ACKNOWLEDGED, OPERATOR)
    out.append(log)

    log = tmp_path / "shred.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.kv_save(b"\x11" * 32)
        clear_seq = w.seq - 1
        w.key_shred(9, REASON_LEGAL_ERASURE, target_seqs=[clear_seq, 4242], detail="E-99")
    out.append(log)

    log = tmp_path / "tool-target.pala"
    with PalaWriter(log) as w:
        w.genesis()
        boot_hash = w.boot()
        # a TOOL_RESULT bound (hash-correct) to a record that is not a call
        w.tool_result(w.seq - 1, boot_hash, 0, result_digest=b"\x02" * 32)
        call = w.tool_call("web.search", args_digest=b"\x01" * 32)
        w.tool_result(w.seq - 1, call, 0, result_digest=b"\x03" * 32)
        w.guard_tool_loop_limit(8, call_seq=w.seq - 2, call_hash=call)
    out.append(log)

    log = tmp_path / "clean-loop.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(1, 2, ref_seq=1, ref_hash=w.head)
        w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
    out.append(log)

    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    log = tmp_path / "vectors.pala"
    log.write_bytes(blob)
    out.append(log)
    return out


def test_cold_verify_equals_warm_verify_and_does_not_materialise(tmp_path):
    seen_codes = set()
    for path in _chains(tmp_path):
        cold = AuditReader.open(path)
        warm = AuditReader.open(path)
        list(warm.records())
        cv, wv = cold.verify(), warm.verify()
        assert _items(cv) == _items(wv), path.name
        assert cv.chain == wv.chain
        assert cold._decoded is None, "verify() must not decode the chain"
        seen_codes.update(i.code for i in cv.advisory.items)
        cold.close()
        warm.close()
    assert seen_codes >= {
        "reference_unresolved",
        "reference_hash_mismatch",
        "ack_target_not_a_candidate",
        "shred_target_unresolved",
        "shred_target_key_mismatch",
        "tool_target_not_a_call",
    }


def test_decode_count_scales_with_references_not_chain_length(tmp_path):
    log = tmp_path / "bystanders.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        for _ in range(300):
            w.kv_save(b"\x11" * 32)  # bystanders: EVENT bodies, never referenced
        cand = w.incident_candidate(1, 2)
        cand_seq = w.seq - 1
        for _ in range(300):
            w.kv_save(b"\x22" * 32)
        w.oversight_ack(cand_seq, cand, DISP_ACKNOWLEDGED, OPERATOR)
    r = AuditReader.open(log)
    ver = r.verify()
    assert ver.chain.chain_ok
    assert [i.code for i in ver.advisory.items] == ["anchor_never_written"]  # header-level only
    # the candidate (referencer and ack target) and the ack itself —
    # nothing among the 600 bystanders
    assert set(r._partial) == {cand_seq, cand_seq + 301}
    assert r._decoded is None
    # and the report path reuses what verify() decoded rather than decoding again
    from palimpsests.audit.report import _safety_section

    before = dict(r._partial)
    section = _safety_section(r)
    assert section["count"] == 2 and section["unacknowledged_candidates"] == 0
    assert r._partial == before
    r.close()
