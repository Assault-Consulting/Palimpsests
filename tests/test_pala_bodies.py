# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for PALA-1 body sealing/opening — need the [pala] extra."""
from __future__ import annotations

import json
import pytest
from palimpsests.audit.pala import Header, body_digest_of, open_body, seal_body
from palimpsests.audit.pala.codec import RT_EVENT
from pathlib import Path

pytest.importorskip("cryptography", reason="body crypto needs the [pala] extra")
from cryptography.exceptions import InvalidTag  # noqa: E402

SPEC_DIR = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"
VECTORS = json.loads((SPEC_DIR / "test-vectors.json").read_text())


def _vec3():
    r = next(r for r in VECTORS["records"] if r["seq"] == 3)
    hdr = Header.decode(bytes.fromhex(r["header_hex"]))
    return r, hdr, bytes.fromhex(VECTORS["aes_key_hex"])


def test_open_body_reproduces_the_vector_plaintext() -> None:
    r, hdr, key = _vec3()
    pt = open_body(
        key,
        seq=hdr.seq,
        boot_id=hdr.boot_id,
        record_type=hdr.record_type,
        body=bytes.fromhex(r["body_hex"]),
        body_digest=hdr.body_digest,
    )
    assert pt.decode() == VECTORS["plaintext_utf8"]


def test_seal_body_reproduces_the_vector_bytes() -> None:
    """Deterministic nonce ⇒ the vector body is reproducible exactly."""
    r, hdr, key = _vec3()
    body, digest = seal_body(
        key,
        seq=hdr.seq,
        boot_id=hdr.boot_id,
        record_type=hdr.record_type,
        plaintext=VECTORS["plaintext_utf8"].encode(),
    )
    assert body.hex() == r["body_hex"]
    assert digest == hdr.body_digest
    assert len(body) == hdr.body_len  # §2.3: body_len counts nonce+ct+tag


def test_digest_mismatch_and_wrong_key_are_distinct_failures() -> None:
    """§7.5: tampered body vs destroyed key must never be conflated."""
    r, hdr, key = _vec3()
    body = bytearray(bytes.fromhex(r["body_hex"]))
    body[-1] ^= 0x01
    with pytest.raises(ValueError, match="body_digest"):
        open_body(
            key,
            seq=hdr.seq,
            boot_id=hdr.boot_id,
            record_type=hdr.record_type,
            body=bytes(body),
            body_digest=hdr.body_digest,
        )
    # right body, wrong (shredded) key: digest passes, decryption fails
    with pytest.raises(InvalidTag):
        open_body(
            b"\x00" * 32,
            seq=hdr.seq,
            boot_id=hdr.boot_id,
            record_type=hdr.record_type,
            body=bytes.fromhex(r["body_hex"]),
            body_digest=hdr.body_digest,
        )


def test_aad_binds_body_to_its_chain_slot() -> None:
    """A body moved to another seq must not decrypt, even with the key."""
    r, hdr, key = _vec3()
    with pytest.raises(InvalidTag):
        open_body(
            key,
            seq=hdr.seq + 1,  # swapped one slot over
            boot_id=hdr.boot_id,
            record_type=hdr.record_type,
            body=bytes.fromhex(r["body_hex"]),
            body_digest=hdr.body_digest,
        )


def test_roundtrip_arbitrary_plaintext() -> None:
    key = bytes(range(32))
    body, digest = seal_body(
        key, seq=99, boot_id=b"\x07" * 16, record_type=RT_EVENT, plaintext=b"x" * 1000
    )
    assert body_digest_of(body) == digest
    out = open_body(
        key, seq=99, boot_id=b"\x07" * 16, record_type=RT_EVENT,
        body=body, body_digest=digest,
    )
    assert out == b"x" * 1000
