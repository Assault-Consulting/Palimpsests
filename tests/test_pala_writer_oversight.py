# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r2 emit paths: oversight kinds 102/103 and documented erasure.

Every record these methods write must decode to exactly the profile-r2
semantics the companion vectors publish, the whole chain must stay
green under the production verifier, and two properties the design
insists on are pinned as tests rather than prose: the writer is *dumb*
(format validation only — referential integrity is the reader's), and
the oversight loop crosses boot boundaries (a candidate in boot N is
answerable in boot N+1, hash-bound through the resume).
"""
from __future__ import annotations

import pytest
import struct
from palimpsests.audit.pala import decode_tlvs, iter_records, verify_headers
from palimpsests.audit.pala_writer import (
    CAT_GUARD_ESCALATION,
    DISP_ACKNOWLEDGED,
    DISP_ESCALATED,
    EVT_CATEGORY,
    EVT_DISPOSITION,
    EVT_KIND,
    EVT_OPERATOR_ID,
    EVT_RECOVERABLE,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    EVT_SEVERITY,
    KIND_INCIDENT_CANDIDATE,
    KIND_OVERSIGHT_ACK,
    REASON_LEGAL_ERASURE,
    SHRED_DETAIL,
    SHRED_REASON,
    SHRED_TARGET_SEQS,
    PalaWriter,
)

OPERATOR = bytes.fromhex("0e5a70120e5a70120e5a70120e5a7012")


def _verify(path):
    blob = path.read_bytes()
    headers = [hb for hb, _ in iter_records(blob)]
    return verify_headers(headers), blob


def _last_body(blob: bytes) -> dict[int, bytes]:
    *_, last = iter_records(blob)
    return dict(decode_tlvs(last[1]))


def test_incident_candidate_decodes_per_r2(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        guard = w.guard_prefix_release(5, 2)
        guard_seq = w.seq - 1
        w.incident_candidate(
            CAT_GUARD_ESCALATION,
            2,
            recoverable=True,
            ref_seq=guard_seq,
            ref_hash=guard,
            detail="guard refusals exceeded threshold in window",
        )
    res, blob = _verify(log)
    assert res.chain_ok
    body = _last_body(blob)
    assert struct.unpack("<H", body[EVT_KIND])[0] == KIND_INCIDENT_CANDIDATE
    assert struct.unpack("<H", body[EVT_CATEGORY])[0] == CAT_GUARD_ESCALATION
    assert struct.unpack("<H", body[EVT_SEVERITY])[0] == 2
    assert body[EVT_RECOVERABLE] == b"\x01"
    assert struct.unpack("<Q", body[EVT_REF_SEQ])[0] == guard_seq
    assert body[EVT_REF_HASH] == guard


def test_candidate_reference_must_come_as_a_pair(tmp_path):
    with PalaWriter(tmp_path / "a.pala") as w:
        w.genesis()
        w.boot()
        with pytest.raises(ValueError, match="together"):
            w.incident_candidate(CAT_GUARD_ESCALATION, 1, ref_seq=2)
        with pytest.raises(ValueError, match="together"):
            w.incident_candidate(CAT_GUARD_ESCALATION, 1, ref_hash=b"\x00" * 32)
        with pytest.raises(ValueError, match="32 bytes"):
            w.incident_candidate(CAT_GUARD_ESCALATION, 1, ref_seq=2, ref_hash=b"\x00" * 8)


def test_oversight_ack_decodes_and_binds_by_hash(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(CAT_GUARD_ESCALATION, 2)
        cand_seq = w.seq - 1
        w.oversight_ack(cand_seq, cand, DISP_ACKNOWLEDGED, OPERATOR)
    res, blob = _verify(log)
    assert res.chain_ok
    body = _last_body(blob)
    assert struct.unpack("<H", body[EVT_KIND])[0] == KIND_OVERSIGHT_ACK
    assert struct.unpack("<Q", body[EVT_REF_SEQ])[0] == cand_seq
    assert body[EVT_REF_HASH] == cand
    assert struct.unpack("<H", body[EVT_DISPOSITION])[0] == DISP_ACKNOWLEDGED
    assert body[EVT_OPERATOR_ID] == OPERATOR


def test_ack_validates_format_only_never_existence(tmp_path):
    """The dumb-writer contract, pinned.

    Formats are enforced; existence is not — an ack naming a candidate
    that was never written is *accepted* by the writer, because
    referential integrity is the reader's advisory (profile r2), and a
    writer that walked its own file to check would block the hot path.
    """
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        with pytest.raises(ValueError, match="32 bytes"):
            w.oversight_ack(1, b"\x00" * 4, DISP_ACKNOWLEDGED, OPERATOR)
        with pytest.raises(ValueError, match="16 bytes"):
            w.oversight_ack(1, b"\x00" * 32, DISP_ACKNOWLEDGED, b"\x00" * 4)
        with pytest.raises(ValueError, match="0, 1 or 2"):
            w.oversight_ack(1, b"\x00" * 32, 7, OPERATOR)
        # a dangling reference is the writer's to accept, the reader's to flag
        w.oversight_ack(999, b"\xab" * 32, DISP_ESCALATED, OPERATOR)
    res, _ = _verify(log)
    assert res.chain_ok


def test_key_shred_documents_the_erasure_in_one_record(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.key_shred(
            9,
            REASON_LEGAL_ERASURE,
            target_seqs=[3, 11],
            detail="erasure request E-17",
        )
    res, blob = _verify(log)
    assert res.chain_ok
    body = _last_body(blob)
    assert struct.unpack("<H", body[SHRED_REASON])[0] == REASON_LEGAL_ERASURE
    raw = body[SHRED_TARGET_SEQS]
    targets = [struct.unpack_from("<Q", raw, i)[0] for i in range(0, len(raw), 8)]
    assert targets == [3, 11]
    assert body[SHRED_DETAIL] == b"erasure request E-17"
    # cleartext by MUST: the record's own header carries key_id 0
    *_, (header_bytes, _) = iter_records(blob)
    key_id = struct.unpack_from("<I", header_bytes, 116)[0]
    assert key_id == 0


def test_oversight_loop_crosses_the_boot_boundary(tmp_path):
    """Candidate in boot N, ack in boot N+1 — the interaction WS2 exists for.

    The reference crosses a resume: same file, new boot, hash-bound
    through ``open_existing``. The chain must verify as one chain, and
    the ack's reference must still name the boot-N candidate byte-exactly.
    """
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        cand = w.incident_candidate(
            CAT_GUARD_ESCALATION, 3, recoverable=False, detail="pre-crash candidate"
        )
        cand_seq = w.seq - 1
        boot_n = w.boot_id

    with PalaWriter.open_existing(log) as w2:
        w2.boot()  # MUST: the first record after a resume
        assert w2.boot_id != boot_n
        w2.oversight_ack(cand_seq, cand, DISP_ACKNOWLEDGED, OPERATOR)

    res, blob = _verify(log)
    assert res.chain_ok and res.count == 5
    assert res.breaks == [] and res.gaps == [] and res.violations == []
    body = _last_body(blob)
    assert struct.unpack("<Q", body[EVT_REF_SEQ])[0] == cand_seq
    assert body[EVT_REF_HASH] == cand
