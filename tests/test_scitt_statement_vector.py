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
