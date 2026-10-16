# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Statement construction v3: the derived root in the payload.

Pinned four ways: the published v3 vector regenerates byte-for-byte and
its roots match the package's own frontier; both statements verify, and
the consistency proof between their roots verifies with no chain at
hand; every tamper expectation the vector lists holds; and a writer's
``chain_root()`` makes a statement a reader then verifies as
``recomputed``.
"""
from __future__ import annotations

import json
import pytest
import shutil
import subprocess
import sys
from pathlib import Path

pytest.importorskip("cbor2")
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from palimpsests.audit.pala import scitt  # noqa: E402
from palimpsests.audit.pala.frontier import MerkleFrontier  # noqa: E402
from palimpsests.audit.pala.merkle import verify_consistency  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
VECTOR = REPO / "docs" / "interop" / "scitt-statement-vector-v3.json"


@pytest.fixture(scope="module")
def doc() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def _key(doc):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(doc["key"]["private_seed_hex"])
    )


class _Chain:
    """What ``chain_root`` reads from a reader: the headers, in order. The
    published vectors give record hashes, not containers, so the reader is
    stood in by an object that hashes to them."""

    def __init__(self, record_hashes: list[bytes]) -> None:
        self._headers = record_hashes


@pytest.fixture
def chain(doc, monkeypatch):
    import palimpsests.audit.pala.proofs as proofs

    hashes = [bytes.fromhex(h) for h in doc["subject_chain"]["record_hashes_hex"]]
    monkeypatch.setattr(proofs, "_record_hash", lambda h: h)  # headers ARE the hashes here
    return _Chain(hashes)


# ── the vector ─────────────────────────────────────────────────────────────


def test_the_vector_regenerates_byte_for_byte(tmp_path):
    for rel in (
        "docs/interop/gen_scitt_statement_vector_v3.py",
        "docs/interop/scitt-statement-vector.json",
        "docs/specs/pala-1/palaudit_ref.py",
        "docs/specs/pala-1/test-vectors.json",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, tmp_path / rel)
    proc = subprocess.run(
        [sys.executable, str(tmp_path / "docs/interop/gen_scitt_statement_vector_v3.py")],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "docs/interop/scitt-statement-vector-v3.json").read_bytes() == (
        VECTOR.read_bytes()
    )


def test_the_reference_roots_are_the_packages_roots(doc):
    hashes = [bytes.fromhex(h) for h in doc["subject_chain"]["record_hashes_hex"]]
    for s in doc["statements"].values():
        n = s["inputs"]["last_seq"] + 1
        assert MerkleFrontier.from_record_hashes(hashes[:n]).root().hex() == s["inputs"]["root_hex"]


# ── the case v3 exists for ─────────────────────────────────────────────────


def test_two_statements_and_a_proof_need_no_chain(doc):
    """Signatures -> roots the signatures cover -> the proof between them."""
    pub = _key(doc).public_key()
    checks = {}
    for name, s in doc["statements"].items():
        c = scitt.verify_statement(
            bytes.fromhex(s["expected"]["statement_hex"]), pub,
            bytes.fromhex(s["inputs"]["chain_head_hex"]),
        )
        assert c.version == "v3" and c.root_status == "carried, not recomputed"
        checks[name] = c
    proof = doc["consistency"]
    assert verify_consistency(
        proof["first"], proof["second"],
        checks["earlier"].root, checks["later"].root,  # read from the statements
        [bytes.fromhex(p) for p in proof["path"]],
    )


def test_with_the_chain_the_root_is_recomputed(doc, chain):
    s = doc["statements"]["later"]
    c = scitt.verify_statement(
        bytes.fromhex(s["expected"]["statement_hex"]), _key(doc).public_key(),
        bytes.fromhex(s["inputs"]["chain_head_hex"]), reader=chain,
    )
    assert c.root_status == "recomputed"
    assert c.payload[2] == 8  # first_seq 8, and still the root over 0..11


# ── tamper expectations ────────────────────────────────────────────────────


def _sign(doc, *, root, first_seq=8, last_seq=11, content_type=None, payload=None):
    head = bytes.fromhex(doc["statements"]["later"]["inputs"]["chain_head_hex"])
    if payload is None and content_type is None:
        return scitt.build_signed_statement(
            head, first_seq=first_seq, last_seq=last_seq, key=_key(doc),
            issuer="i", subject="s", alg=scitt.ALG_EDDSA, root=root,
        ), head
    return scitt._cose_sign1(
        payload, _key(doc), alg=scitt.ALG_EDDSA, content_type=content_type
    ), head


def test_a_flipped_root_breaks_the_signature(doc):
    s = doc["statements"]["later"]
    stmt = bytearray.fromhex(s["expected"]["statement_hex"])
    root = bytes.fromhex(s["inputs"]["root_hex"])
    i = bytes(stmt).index(root)
    stmt[i] ^= 0x01
    with pytest.raises(ValueError):
        scitt.verify_statement(bytes(stmt), _key(doc).public_key(),
                               bytes.fromhex(s["inputs"]["chain_head_hex"]))


@pytest.mark.parametrize("wrong", ["range", "one_short", "one_over", "other"])
def test_a_wrong_root_is_rejected_against_the_chain(doc, chain, wrong):
    hashes = chain._headers
    root = {
        "range": MerkleFrontier.from_record_hashes(hashes[8:12]).root(),  # first_seq..last_seq
        "one_short": MerkleFrontier.from_record_hashes(hashes[:11]).root(),  # last_seq records
        "one_over": MerkleFrontier.from_record_hashes(hashes + hashes[:1]).root(),  # +1
        "other": b"\x42" * 32,
    }[wrong]
    stmt, head = _sign(doc, root=root)
    assert scitt.verify_statement(stmt, _key(doc).public_key(), head).root_status == (
        "carried, not recomputed"  # without the chain nothing can tell
    )
    with pytest.raises(ValueError, match="not the derived root"):
        scitt.verify_statement(stmt, _key(doc).public_key(), head, reader=chain)


def test_a_range_root_does_not_verify_in_the_proof(doc):
    hashes = [bytes.fromhex(h) for h in doc["subject_chain"]["record_hashes_hex"]]
    p = doc["consistency"]
    range_root = MerkleFrontier.from_record_hashes(hashes[8:12]).root()
    assert not verify_consistency(
        p["first"], p["second"], bytes.fromhex(p["first_root"]), range_root,
        [bytes.fromhex(x) for x in p["path"]],
    )


def test_content_type_and_payload_must_agree(doc):
    head = bytes.fromhex(doc["statements"]["later"]["inputs"]["chain_head_hex"])
    v2_payload = scitt.head_payload(head, 8, 11)
    v3_payload = scitt.head_payload(head, 8, 11, root=b"\x00" * 32)
    pub = _key(doc).public_key()
    for payload, ctype in ((v2_payload, scitt.CONTENT_TYPE_V3), (v3_payload, scitt.CONTENT_TYPE)):
        stmt = scitt._cose_sign1(payload, _key(doc), alg=scitt.ALG_EDDSA, content_type=ctype)
        with pytest.raises(ValueError, match="payload keys"):
            scitt.verify_statement(stmt, pub, head)
    unknown = scitt._cose_sign1(v2_payload, _key(doc), alg=scitt.ALG_EDDSA,
                                content_type="application/cbor")
    with pytest.raises(ValueError, match="unknown statement content type"):
        scitt.verify_statement(unknown, pub, head)


def test_a_damaged_proof_does_not_verify(doc):
    p = doc["consistency"]
    a, b = bytes.fromhex(p["first_root"]), bytes.fromhex(p["second_root"])
    path = [bytes.fromhex(x) for x in p["path"]]
    assert not verify_consistency(p["first"], p["second"], a, b, path[:-1])
    assert not verify_consistency(p["first"], p["second"], b, a, path)


# ── v2 is untouched, and the writer makes v3 ───────────────────────────────


def test_v2_still_verifies_and_reports_no_root():
    v2 = json.loads((REPO / "docs/interop/scitt-statement-vector.json").read_text())
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v2["key"]["private_seed_hex"]))
    c = scitt.verify_statement(
        bytes.fromhex(v2["expected"]["statement_hex"]), key.public_key(),
        bytes.fromhex(v2["subject_chain"]["chain_head_hex"]),
    )
    assert c.version == "v2" and c.root is None and c.root_status == "absent"


def test_a_writers_chain_root_makes_a_statement_a_reader_recomputes(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader

    p = tmp_path / "c.pala"
    with PalaWriter(p) as w:
        w.genesis()
        for _ in range(20):
            w.prefix_warm(token_count=1)
        head, root, last = w.head, w.chain_root(), w.seq - 1
    key = ed25519.Ed25519PrivateKey.generate()
    stmt = scitt.build_signed_statement(
        head, first_seq=0, last_seq=last, key=key, issuer="i",
        subject=f"pala-1:chain:{head.hex()}", alg=scitt.ALG_EDDSA, root=root,
    )
    with AuditReader.open(p) as r:
        c = scitt.verify_statement(stmt, key.public_key(), head, reader=r)
    assert c.version == "v3" and c.root_status == "recomputed"
