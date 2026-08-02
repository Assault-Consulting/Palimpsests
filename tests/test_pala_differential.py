"""Differential tests: the production codec against the reference one.

The reference implementation in docs/specs/pala-1/ is standalone on
purpose — it imports nothing from palimpsests, so these tests pit two
independent encoders against each other on the same inputs. Byte-identical
headers, identical hashes, identical Merkle roots, and the same verdicts on
the same attacks: any divergence means one of them has drifted from the
prose, and the prose decides which.
"""
from __future__ import annotations

import importlib.util
import pytest
import random
import sys
from palimpsests.audit.pala import (
    Header,
    merkle_proof,
    merkle_root,
    record_hash,
    verify_headers,
)
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"


@pytest.fixture(scope="module")
def ref():
    spec = importlib.util.spec_from_file_location(
        "palaudit_ref", SPEC_DIR / "palaudit_ref.py"
    )
    mod = importlib.util.module_from_spec(spec)
    # dataclasses resolve their defining module through sys.modules at
    # class-creation time; register before exec or @dataclass breaks.
    sys.modules["palaudit_ref"] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop("palaudit_ref", None)


def _random_headers(ref, rng: random.Random, n: int = 12):
    """Build one chain twice — through the reference and through the
    production codec — from the same random field values."""
    prev_ref = ref.ZERO32
    prev_prod = b"\x00" * 32
    ref_hbs, prod_hbs = [], []
    for i in range(n):
        rtype = ref.RT_GENESIS if i == 0 else rng.choice(
            [ref.RT_EVENT, ref.RT_SPAN_START, ref.RT_SPAN_END, ref.RT_SAFETY]
        )
        kw = dict(
            seq=i,
            boot_id=rng.randbytes(16),
            span_id=rng.randbytes(16),
            parent_span_id=rng.randbytes(16),
            assurance_tier=rng.choice([0, 1, 2]),
            time_trust=rng.choice([1, 2, 3]),
            monotonic_ns=rng.randrange(2**63),
            wall_clock_ns=rng.randrange(2**62),
            key_id=rng.randrange(2**16),
            body_len=0,
            tlvs=[(0x0001, rng.randbytes(rng.randrange(0, 24)))],
        )
        rh = ref.Header(record_type=rtype, prev_hash=prev_ref, **kw)
        ph = Header(record_type=rtype, prev_hash=prev_prod, **kw)
        ref_hb, prod_hb = rh.encode(), ph.encode()
        ref_hbs.append(ref_hb)
        prod_hbs.append(prod_hb)
        prev_ref = ref.record_hash(ref_hb)
        prev_prod = record_hash(prod_hb)
    return ref_hbs, prod_hbs


def test_encoders_agree_byte_for_byte(ref) -> None:
    rng = random.Random(1729)
    for _ in range(20):
        ref_hbs, prod_hbs = _random_headers(ref, rng)
        assert ref_hbs == prod_hbs


def test_verifiers_agree_on_clean_chains(ref) -> None:
    rng = random.Random(6300)
    ref_hbs, prod_hbs = _random_headers(ref, rng, n=30)
    r = ref.verify_chain(ref_hbs, expected_head=ref.record_hash(ref_hbs[-1]))
    p = verify_headers(prod_hbs, expected_head=record_hash(prod_hbs[-1]))
    assert r.chain_ok and p.chain_ok
    assert r.head == p.head
    assert r.complete_to_anchor is True and p.complete_to_anchor is True


def test_verifiers_agree_on_mutations(ref) -> None:
    """Same corrupted input, same verdict from both implementations."""
    rng = random.Random(41)
    ref_hbs, prod_hbs = _random_headers(ref, rng, n=10)
    for _ in range(30):
        idx = rng.randrange(len(ref_hbs))
        pos = rng.randrange(len(ref_hbs[idx]))
        mut_r, mut_p = list(ref_hbs), list(prod_hbs)
        b = bytearray(mut_r[idx])
        b[pos] ^= 0x40
        mut_r[idx] = bytes(b)
        b = bytearray(mut_p[idx])
        b[pos] ^= 0x40
        mut_p[idx] = bytes(b)
        r = ref.verify_chain(mut_r)
        p = verify_headers(mut_p)
        assert r.chain_ok == p.chain_ok, f"divergence on flip at record {idx} offset {pos}"


def test_merkle_agrees_across_sizes(ref) -> None:
    """Promotion vs promotion, but independently coded — and both against
    the recursive RFC 6962 definition for good measure."""
    import hashlib

    def mth(d):
        if len(d) == 1:
            return hashlib.sha256(b"\x00" + d[0]).digest()
        k = 1
        while k * 2 < len(d):
            k *= 2
        return hashlib.sha256(b"\x01" + mth(d[:k]) + mth(d[k:])).digest()

    rng = random.Random(6962)
    for n in [1, 2, 3, 5, 6, 7, 11, 30, 64, 65, 127]:
        leaves = [rng.randbytes(32) for _ in range(n)]
        assert merkle_root(leaves) == ref.merkle_root(leaves) == mth(leaves)
        idx = rng.randrange(n)
        assert merkle_proof(leaves, idx) == ref.merkle_proof(leaves, idx)
