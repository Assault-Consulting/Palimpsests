# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""WS-PROOF — prefix-consistency proofs over the derived tree.

* Construction agrees with RFC 6962's recursive ``SUBPROOF`` and
  verification (RFC 9162 §2.1.4.2) accepts every ``(first, second)``
  pair up to 70 leaves and rejects a truncated path, a wrong root, and
  a tampered second tree.
* The companion vectors regenerate byte-identically from the reference
  implementation, and the package reproduces every root and accepts
  every proof in them; the negatives verify ``False``.
* The chain-level API: ``chain_root`` equals ``merkle_root`` over record
  hashes; a proof round-trips through JSON; sizes outside the chain are
  rejected.
"""
from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from palimpsests.audit.pala.merkle import (
    consistency_proof,
    merkle_root,
    verify_consistency,
)
from palimpsests.audit.pala.proofs import (
    CONSISTENCY_FORMAT,
    ConsistencyProof,
    chain_root,
)
from palimpsests.audit.pala.proofs import (
    consistency_proof as chain_consistency_proof,
)
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "docs" / "specs" / "pala-1"
VECTORS = SPEC / "consistency-vectors.json"


def _leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _mth(nodes):
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    return _node(_mth(nodes[:k]), _mth(nodes[k:]))


def _rfc_subproof(m, nodes, b):
    n = len(nodes)
    if m == n:
        return [] if b else [_mth(nodes)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _rfc_subproof(m, nodes[:k], b) + [_mth(nodes[k:])]
    return _rfc_subproof(m - k, nodes[k:], False) + [_mth(nodes[:k])]


def test_construction_matches_rfc_6962_and_verifies_for_every_pair():
    rng = random.Random(6962)
    for n in range(1, 71):
        leaves = [rng.randbytes(32) for _ in range(n)]
        rn = merkle_root(leaves)
        hashed = [_leaf(x) for x in leaves]
        for m in range(1, n + 1):
            p = consistency_proof(leaves, m)
            assert p == _rfc_subproof(m, hashed, True)
            rm = merkle_root(leaves[:m])
            assert verify_consistency(m, n, rm, rn, p)
            assert not verify_consistency(m, n, hashlib.sha256(b"x").digest(), rn, p)
            if p:
                assert not verify_consistency(m, n, rm, rn, p[:-1])
            if m < n:
                other = merkle_root(leaves[: n - 1] + [b"z" * 32])
                assert not verify_consistency(m, n, rm, other, p)


def test_degenerate_inputs_are_rejected_not_raised():
    leaves = [b"\x01" * 32, b"\x02" * 32]
    r = merkle_root(leaves)
    assert not verify_consistency(0, 2, r, r, [])
    assert not verify_consistency(3, 2, r, r, [])
    assert verify_consistency(2, 2, r, r, [])
    assert not verify_consistency(2, 2, r, r, [r])
    assert not verify_consistency(1, 2, r, r, [])  # missing node
    import pytest

    with pytest.raises(IndexError):
        consistency_proof(leaves, 0)
    with pytest.raises(IndexError):
        consistency_proof(leaves, 3)


def test_companion_vectors_regenerate_byte_identically(tmp_path):
    # run the generator in a copy so the committed file is compared, not rewritten
    import shutil

    work = tmp_path / "pala-1"
    (work / "profiles").mkdir(parents=True)
    shutil.copy(SPEC / "gen_consistency_vectors.py", work)
    shutil.copy(SPEC / "palaudit_ref.py", work)
    shutil.copy(SPEC / "profiles" / "inference-vectors.json", work / "profiles")
    proc = subprocess.run(
        [sys.executable, str(work / "gen_consistency_vectors.py")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (work / "consistency-vectors.json").read_bytes() == VECTORS.read_bytes()


def test_package_reproduces_the_vectors():
    v = json.loads(VECTORS.read_text())
    src = json.loads((SPEC / "profiles" / "inference-vectors.json").read_text())
    assert v["source_chain_head"] == src["chain_head"]
    hashes = [bytes.fromhex(r["record_hash"]) for r in src["records"]]
    for i in range(len(hashes) + 1):
        assert merkle_root(hashes[:i]).hex() == v["roots_by_count"][str(i)]
    for p in v["proofs"]:
        cp = ConsistencyProof.from_json({"format": v["format"], **p})
        assert cp.verify(), p
        assert [h.hex() for h in consistency_proof(hashes[: p["second"]], p["first"])] == p["path"]
    for name, p in v["negative"].items():
        if isinstance(p, dict):
            assert not ConsistencyProof.from_json({"format": v["format"], **p}).verify(), name


def _chain(tmp_path: Path, n: int = 300) -> Path:
    log = tmp_path / "c.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        for i in range(n):
            w.kv_save(bytes([i % 256]) * 32)
    return log


def test_chain_level_api_and_json_round_trip(tmp_path):
    path = _chain(tmp_path)
    with AuditReader.open(path) as r:
        n = len(r._headers)
        hashes = [hashlib.sha256(hb).digest() for hb in r._headers]
        assert chain_root(r) == merkle_root(hashes)
        assert chain_root(r, 0) == hashlib.sha256(b"").digest()
        proof = chain_consistency_proof(r, 100)
        assert proof.second == n and proof.first == 100
        assert proof.first_root == merkle_root(hashes[:100])
        assert proof.verify()
        doc = proof.to_json()
        assert doc["format"] == CONSISTENCY_FORMAT
        again = ConsistencyProof.from_json(json.loads(json.dumps(doc)))
        assert again == proof and again.verify()
        # an archived prefix root taken earlier still verifies against today's chain
        assert verify_consistency(100, n, chain_root(r, 100), chain_root(r), proof.path)
        import pytest

        with pytest.raises(IndexError):
            chain_consistency_proof(r, 0)
        with pytest.raises(IndexError):
            chain_consistency_proof(r, n + 1)
        with pytest.raises(ValueError):
            ConsistencyProof.from_json({**doc, "format": "something-else"})
