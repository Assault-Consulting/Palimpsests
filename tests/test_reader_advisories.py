# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Referential-integrity advisories (WS3) and r2 kind recognition.

Every check here is an advisory, never a violation — the design line
the profile draws is pinned by the tests themselves: chains with
dangling or mismatched references stay ``chain_ok`` throughout, and the
observation lands in ``Verification.advisory``. The golden no-advisory
fixture is the published r2 companion-vectors chain (an encrypted body
whose key_id matches its shred's target — a state the metadata-only
writer cannot itself produce).
"""
from __future__ import annotations

import json
from palimpsests.audit.pala_writer import (
    CAT_GUARD_ESCALATION,
    DISP_ACKNOWLEDGED,
    REASON_LEGAL_ERASURE,
    PalaWriter,
)
from palimpsests.audit.reader import AuditReader
from pathlib import Path

OPERATOR = bytes.fromhex("0e5a70120e5a70120e5a70120e5a7012")
VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _referential(verification):
    codes = {
        "reference_unresolved",
        "reference_hash_mismatch",
        "ack_target_not_a_candidate",
        "shred_target_unresolved",
        "shred_target_key_mismatch",
    }
    return [i for i in verification.advisory.items if i.code in codes]


def test_companion_vectors_chain_is_referentially_clean():
    """The published r2 chain resolves every reference — including the
    shred whose target actually carries the destroyed key_id."""
    v = json.loads(VECTORS.read_text())
    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    reader = AuditReader.from_bytes(blob)
    ver = reader.verify()
    assert ver.chain.chain_ok
    assert _referential(ver) == []
    # and the r2 kinds resolve by name now
    names = {dr.seq: dr.kind_name for dr in reader.records()}
    assert names[4] == "INCIDENT_CANDIDATE"
    assert names[5] == "OVERSIGHT_ACK"


def test_writer_loop_with_correct_references_is_clean(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(CAT_GUARD_ESCALATION, 2)
        w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, OPERATOR)
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok and _referential(ver) == []


def test_dangling_ack_is_an_advisory_not_a_violation(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.oversight_ack(999, b"\xab" * 32, DISP_ACKNOWLEDGED, OPERATOR)
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok  # the chain is sound — the semantics are not
    items = _referential(ver)
    assert [i.code for i in items] == ["reference_unresolved"]
    assert items[0].at_seq == 2 and "999" in items[0].detail


def test_ack_hash_mismatch_is_the_stronger_signal(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.incident_candidate(CAT_GUARD_ESCALATION, 2)
        cand_seq = w.seq - 1
        w.oversight_ack(cand_seq, b"\xcd" * 32, DISP_ACKNOWLEDGED, OPERATOR)
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok
    assert [i.code for i in _referential(ver)] == ["reference_hash_mismatch"]


def test_ack_to_a_non_candidate_is_flagged(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        boot_hash = w.boot()
        boot_seq = w.seq - 1
        # hash-correct reference to a record that is not a candidate
        w.oversight_ack(boot_seq, boot_hash, DISP_ACKNOWLEDGED, OPERATOR)
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok
    assert [i.code for i in _referential(ver)] == ["ack_target_not_a_candidate"]


def test_shred_targets_unresolved_and_key_mismatch(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.kv_save(b"\x11" * 32)  # cleartext record: key_id 0
        clear_seq = w.seq - 1
        w.key_shred(
            9,
            REASON_LEGAL_ERASURE,
            target_seqs=[clear_seq, 4242],
            detail="ticket E-99",
        )
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok
    codes = sorted(i.code for i in _referential(ver))
    assert codes == ["shred_target_key_mismatch", "shred_target_unresolved"]


def test_candidate_source_reference_is_checked_too(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.incident_candidate(
            CAT_GUARD_ESCALATION, 2, ref_seq=777, ref_hash=b"\x01" * 32
        )
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert [i.code for i in _referential(ver)] == ["reference_unresolved"]


def test_oversight_loop_across_a_resume_resolves_cleanly(tmp_path):
    """Candidate in boot N, ack in boot N+1 — the r2 loop closes across
    the boundary and the reader resolves it with zero advisories."""
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(CAT_GUARD_ESCALATION, 3)
        cand_seq = w.seq - 1
    with PalaWriter.open_existing(log) as w2:
        w2.boot()
        w2.oversight_ack(cand_seq, cand, DISP_ACKNOWLEDGED, OPERATOR)
    with AuditReader.open(log) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok
    assert _referential(ver) == []
    # boot-scoped advisories from the header pass stay silent as well:
    # a mono reset across BOOT is normal, never a regression (Track C rule).
    assert all(i.code != "mono_regression_in_boot" for i in ver.advisory.items)
