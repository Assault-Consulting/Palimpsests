# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r2 inference-profile companion vectors verify and decode.

Two layers, deliberately separate: the envelope answers must hold under
any core verifier (the production one here; CI regenerates the file
byte-for-byte from the reference-based generator as a separate gate),
and the r2 body semantics must decode to exactly the published
``semantics`` block — the check a profile-aware reader implements.

``test-vectors.json`` (the core's, frozen) is deliberately not touched
by anything r2: the last test pins that.
"""
from __future__ import annotations

import hashlib
import json
import pytest
import struct
from palimpsests.audit.pala import decode_tlvs, iter_records, verify_headers
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parent.parent / "docs" / "specs" / "pala-1"
VECTORS = SPEC_DIR / "profiles" / "inference-vectors.json"

# Frozen with the core at v1.0; four independent verification runs pin it.
CORE_VECTORS_SHA256 = "476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193"

EVT_KIND = 0x0001
EVT_CATEGORY = 0x0005
EVT_SEVERITY = 0x0006
EVT_RECOVERABLE = 0x0007
EVT_REF_SEQ = 0x0008
EVT_REF_HASH = 0x0009
EVT_OPERATOR_ID = 0x000A
EVT_DISPOSITION = 0x000B
SHRED_REASON = 0x0001
SHRED_TARGET_SEQS = 0x0002
SHRED_DETAIL = 0x0003


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS.read_text())


@pytest.fixture(scope="module")
def container(vectors) -> bytes:
    return b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in vectors["records"]
    )


def _body(vectors, seq: int) -> dict[int, bytes]:
    rec = next(r for r in vectors["records"] if r["seq"] == seq)
    return dict(decode_tlvs(bytes.fromhex(rec["body_hex"])))


def test_envelope_verifies_with_the_production_verifier(vectors, container):
    headers = [hb for hb, _ in iter_records(container)]
    res = verify_headers(headers)
    assert res.chain_ok is True
    assert res.count == len(vectors["records"])  # self-describing fixture
    assert res.breaks == [] and res.gaps == [] and res.violations == []
    assert res.head.hex() == vectors["chain_head"] == vectors["anchor_head"]


def test_incident_candidate_decodes_to_the_published_semantics(vectors):
    want = vectors["semantics"]["4"]
    body = _body(vectors, 4)
    assert struct.unpack("<H", body[EVT_KIND])[0] == want["kind"] == 102
    assert struct.unpack("<H", body[EVT_CATEGORY])[0] == want["category"]
    assert struct.unpack("<H", body[EVT_SEVERITY])[0] == want["severity"]
    assert body[EVT_RECOVERABLE] == bytes([want["recoverable"]])
    assert struct.unpack("<Q", body[EVT_REF_SEQ])[0] == want["ref_seq"]
    assert body[EVT_REF_HASH].hex() == want["ref_hash"]
    # the hash-bound reference names the actual guard record
    guard = next(r for r in vectors["records"] if r["seq"] == want["ref_seq"])
    assert body[EVT_REF_HASH].hex() == guard["record_hash"]


def test_oversight_ack_binds_to_the_candidate_by_seq_and_hash(vectors):
    want = vectors["semantics"]["5"]
    body = _body(vectors, 5)
    assert struct.unpack("<H", body[EVT_KIND])[0] == want["kind"] == 103
    assert struct.unpack("<Q", body[EVT_REF_SEQ])[0] == want["ref_seq"] == 4
    candidate = next(r for r in vectors["records"] if r["seq"] == 4)
    assert body[EVT_REF_HASH].hex() == candidate["record_hash"] == want["ref_hash"]
    assert struct.unpack("<H", body[EVT_DISPOSITION])[0] == want["disposition"]
    assert body[EVT_OPERATOR_ID] == bytes.fromhex(want["operator_id"])
    assert len(body[EVT_OPERATOR_ID]) == 16  # pseudonymous, fixed width, no PII


def test_key_shred_body_documents_the_erasure(vectors):
    want = vectors["semantics"]["6"]
    body = _body(vectors, 6)
    assert struct.unpack("<H", body[SHRED_REASON])[0] == want["reason"]
    raw = body[SHRED_TARGET_SEQS]
    assert len(raw) % 8 == 0
    targets = [struct.unpack_from("<Q", raw, i)[0] for i in range(0, len(raw), 8)]
    assert targets == want["target_seqs"] == [3]
    assert body[SHRED_DETAIL].decode() == want["detail"]


def test_encrypted_content_body_round_trips_under_the_spec_derivations(vectors):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    enc = vectors["encryption"]
    rec = next(r for r in vectors["records"] if r["seq"] == 3)
    body = bytes.fromhex(rec["body_hex"])
    nonce, ct = body[:12], body[12:]
    assert nonce == b"\x00\x00\x00\x00" + struct.pack("<Q", 3)  # core §4.4 rule
    aad = struct.pack("<Q", 3) + bytes.fromhex(vectors["boot_id"]) + struct.pack("<H", 0x0012)
    out = crypto.AESGCM(bytes.fromhex(enc["key_hex"])).decrypt(nonce, ct, aad)
    assert out.decode() == enc["seq3_plaintext"]


def test_the_frozen_core_vectors_are_untouched():
    data = (SPEC_DIR / "test-vectors.json").read_bytes()
    assert hashlib.sha256(data).hexdigest() == CORE_VECTORS_SHA256
