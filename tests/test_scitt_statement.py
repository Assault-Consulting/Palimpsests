# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""B.1 — the chain head as a SCITT Signed Statement, tested against the
published vectors: the statement commits to the *published* heads, the
tampered variants are rejected, and both admitted algorithms round-trip.
"""
from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from palimpsests.audit.pala import scitt, vectors


@pytest.fixture(scope="module")
def es_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ed_key():
    return ed25519.Ed25519PrivateKey.generate()


def _published_head(name: str) -> tuple[bytes, int]:
    v = vectors.load(name)
    return bytes.fromhex(v["chain_head"]), len(v["records"])


@pytest.mark.parametrize("vector_set", ["core", "inference"])
def test_statement_commits_to_the_published_head(vector_set, es_key):
    head, n = _published_head(vector_set)
    msg = scitt.build_signed_statement(
        head,
        first_seq=0,
        last_seq=n - 1,
        key=es_key,
        issuer="urn:example:issuer",
        subject=f"pala-1:chain:{head[:8].hex()}",
    )
    decoded = scitt.check_statement_against_head(msg, es_key.public_key(), head)
    assert decoded[1] == head
    assert (decoded[2], decoded[3]) == (0, n - 1)
    assert decoded[4] == scitt.FORMAT_ID


def test_eddsa_round_trips(ed_key):
    head, n = _published_head("core")
    msg = scitt.build_signed_statement(
        head,
        first_seq=0,
        last_seq=n - 1,
        key=ed_key,
        issuer="urn:example:issuer",
        subject="pala-1:chain:test",
        alg=scitt.ALG_EDDSA,
    )
    assert scitt.check_statement_against_head(msg, ed_key.public_key(), head)[1] == head


def test_a_different_head_is_rejected(es_key):
    head, n = _published_head("core")
    msg = scitt.build_signed_statement(
        head, first_seq=0, last_seq=n - 1, key=es_key, issuer="i", subject="s"
    )
    other = bytearray(head)
    other[0] ^= 0x01
    with pytest.raises(ValueError, match="expected chain head"):
        scitt.check_statement_against_head(msg, es_key.public_key(), bytes(other))


def test_a_tampered_signature_is_rejected(es_key):
    head, n = _published_head("core")
    msg = bytearray(
        scitt.build_signed_statement(
            head, first_seq=0, last_seq=n - 1, key=es_key, issuer="i", subject="s"
        )
    )
    msg[-1] ^= 0x01
    with pytest.raises(ValueError, match="verification failed"):
        scitt.check_statement_against_head(bytes(msg), es_key.public_key(), head)


def test_a_tampered_payload_is_rejected(es_key):
    """Flipping a payload byte breaks the signature, not just the commitment."""
    head, n = _published_head("core")
    msg = scitt.build_signed_statement(
        head, first_seq=0, last_seq=n - 1, key=es_key, issuer="i", subject="s"
    )
    tag = cbor2.loads(msg)
    protected, unprotected, payload, sig = tag.value
    payload = bytearray(payload)
    payload[-1] ^= 0x01
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, bytes(payload), sig]))
    with pytest.raises(ValueError):
        scitt.check_statement_against_head(forged, es_key.public_key(), head)


def test_the_claims_ride_in_the_protected_header(es_key):
    head, n = _published_head("core")
    msg = scitt.build_signed_statement(
        head, first_seq=0, last_seq=n - 1, key=es_key, issuer="urn:i", subject="urn:s"
    )
    protected = cbor2.loads(cbor2.loads(msg).value[0])
    assert protected[15] == {1: "urn:i", 2: "urn:s"}
    assert protected[1] == scitt.ALG_ES256


def test_bad_inputs_are_refused(es_key):
    head, _ = _published_head("core")
    with pytest.raises(ValueError, match="32 bytes"):
        scitt.head_payload(b"short", 0, 1)
    with pytest.raises(ValueError, match="sequence range"):
        scitt.head_payload(head, 5, 4)
    with pytest.raises(ValueError, match="unsupported COSE alg"):
        scitt.build_signed_statement(
            head, first_seq=0, last_seq=1, key=es_key, issuer="i", subject="s", alg=-99
        )


def test_not_a_cose_sign1_is_refused(es_key):
    head, _ = _published_head("core")
    with pytest.raises(ValueError, match="not a COSE_Sign1"):
        scitt.check_statement_against_head(cbor2.dumps({"x": 1}), es_key.public_key(), head)


def test_a_non_map_payload_is_refused(es_key):
    head, _ = _published_head("core")
    msg = scitt._cose_sign1(cbor2.dumps([1, 2]), es_key, alg=scitt.ALG_ES256)
    with pytest.raises(ValueError, match="not a CBOR map"):
        scitt.check_statement_against_head(msg, es_key.public_key(), head)
