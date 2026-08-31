# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The published SCITT-statement vector stays true to the code.

The vector file is the contract an external verifier works against
(docs/interop/), so this test pins it three ways: the statement
regenerates byte-for-byte from the stated inputs (Ed25519 is
deterministic), it verifies against the stated public key and head,
and the file's own digest fields agree with its bytes.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from palimpsests.audit.pala import scitt, vectors

VECTOR = pathlib.Path(__file__).parent.parent / "docs" / "interop" / "scitt-statement-vector.json"


@pytest.fixture(scope="module")
def doc() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_the_statement_regenerates_byte_for_byte(doc):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(doc["key"]["private_seed_hex"])
    )
    head = bytes.fromhex(doc["subject_chain"]["chain_head_hex"])
    stmt = scitt.build_signed_statement(
        head,
        first_seq=doc["subject_chain"]["first_seq"],
        last_seq=doc["subject_chain"]["last_seq"],
        key=key,
        issuer=doc["statement_inputs"]["issuer"],
        subject=doc["statement_inputs"]["subject"],
        alg=scitt.ALG_EDDSA,
    )
    assert stmt.hex() == doc["expected"]["statement_hex"]
    assert len(stmt) == doc["expected"]["statement_length_bytes"]
    assert hashlib.sha256(stmt).hexdigest() == doc["expected"]["statement_sha256"]


def test_the_vector_head_is_the_published_core_head(doc):
    assert doc["subject_chain"]["chain_head_hex"] == vectors.load("core")["chain_head"]


def test_the_stated_public_key_matches_the_seed_and_verifies(doc):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(doc["key"]["private_seed_hex"])
    )
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert pub_raw.hex() == doc["key"]["public_key_hex"]
    decoded = scitt.check_statement_against_head(
        bytes.fromhex(doc["expected"]["statement_hex"]),
        key.public_key(),
        bytes.fromhex(doc["subject_chain"]["chain_head_hex"]),
    )
    assert (decoded[2], decoded[3]) == (
        doc["subject_chain"]["first_seq"],
        doc["subject_chain"]["last_seq"],
    )


def test_the_tamper_expectations_hold(doc):
    key = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(doc["key"]["private_seed_hex"])
    )
    stmt = bytes.fromhex(doc["expected"]["statement_hex"])
    head = bytes.fromhex(doc["subject_chain"]["chain_head_hex"])

    other = bytearray(head)
    other[0] ^= 0x01
    with pytest.raises(ValueError):
        scitt.check_statement_against_head(stmt, key.public_key(), bytes(other))

    broken = bytearray(stmt)
    broken[-1] ^= 0x01
    with pytest.raises(ValueError):
        scitt.check_statement_against_head(bytes(broken), key.public_key(), head)


def test_s_plus_l_malleated_signature_is_rejected():
    """B2 finding F-2, pinned: our verify path enforces RFC 8032 §5.1.7.

    Adding the group order L to the scalar S yields a second, distinct
    64-byte signature over the identical Sig_structure. A stack without
    the range check accepts it; ours must not. The malleated scalar is
    cross-checked against the value published in bridge run B2.
    """
    import cbor2

    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    stmt = bytes.fromhex(v["expected"]["statement_hex"])
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(v["key"]["public_key_hex"])
    )
    head = bytes.fromhex(v["subject_chain"]["chain_head_hex"])

    L = 2**252 + 27742317777372353535851937790883648493
    tag = cbor2.loads(stmt)
    protected, unprotected, payload, sig = tag.value
    s_int = int.from_bytes(sig[32:], "little")
    malleated = sig[:32] + (s_int + L).to_bytes(32, "little")
    assert malleated[32:].hex() == (
        "cb2ef1d5ef03b37e377359b5bba5ebfeb07bb5808ea4edb3bb13ad8c04d5a713"
    )  # the exact value bridge run B2 published

    stmt2 = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, malleated]))
    with pytest.raises(ValueError):
        scitt.check_statement_against_head(stmt2, pub, head)
