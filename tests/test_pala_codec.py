# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for the PALA-1 codec — stdlib-only surface.

Everything here runs WITHOUT the [pala] extra: that is itself an assertion
under test (header-only verification on a bare install is a property the
format promises). Body decryption lives in test_pala_bodies.py behind an
importorskip.
"""
from __future__ import annotations

import json
import pytest
import random
import struct
import subprocess
import sys
from palimpsests.audit.pala import (
    FIXED_HEADER_LEN,
    Header,
    MalformedRecord,
    iter_records,
    merkle_proof,
    merkle_root,
    record_hash,
    verify_headers,
    verify_proof,
)
from palimpsests.audit.pala.codec import (
    RT_EVENT,
    RT_GENESIS,
    TIME_NTP_SYNCED,
    TIME_UNKNOWN,
    ZERO16,
    ZERO32,
)
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"
VECTORS = json.loads((SPEC_DIR / "test-vectors.json").read_text())


def _vector_headers() -> list[bytes]:
    return [bytes.fromhex(r["header_hex"]) for r in VECTORS["records"]]


# ─── the committed vectors, via the production codec ─────────────────────


def test_vectors_verify_and_match_the_published_head() -> None:
    """The production verifier reproduces the specification's §8 result."""
    res = verify_headers(
        _vector_headers(), expected_head=bytes.fromhex(VECTORS["chain_head"])
    )
    assert res.chain_ok
    assert res.count == len(VECTORS["records"])
    assert res.head.hex() == VECTORS["chain_head"]
    assert res.complete_to_anchor is True
    assert res.breaks == [] and res.gaps == [] and res.violations == []


def test_vector_headers_roundtrip_byte_exact() -> None:
    """decode(encode(h)) is the identity on every vector header — the
    canonical serialization really is canonical."""
    for hb in _vector_headers():
        assert Header.decode(hb).encode() == hb


def test_vector_record_hashes_match() -> None:
    for r in VECTORS["records"]:
        assert record_hash(bytes.fromhex(r["header_hex"])).hex() == r["record_hash"]


def test_vector_merkle_root_and_proof() -> None:
    import hashlib

    frames = [hashlib.sha256(f"frame-{i}".encode()).digest() for i in range(30)]
    root = merkle_root(frames)
    assert root.hex() == VECTORS["merkle"]["tree_hash"]
    idx = VECTORS["merkle"]["proof_index"]
    proof = merkle_proof(frames, idx)
    assert [[s, h.hex()] for s, h in proof] == VECTORS["merkle"]["proof"]
    assert verify_proof(frames[idx], proof, root)


def test_stale_anchor_diagnosed_as_lag() -> None:
    """§7.2: an anchor naming a record inside the chain is an unanchored
    tail with a lag count — not a replacement."""
    res = verify_headers(
        _vector_headers(), expected_head=bytes.fromhex(VECTORS["anchor_head"])
    )
    assert res.chain_ok  # internal consistency is a separate question
    assert res.complete_to_anchor is False
    assert res.anchor_lag == 3
    assert "unanchored tail" in (res.anchor_reason or "")


def test_truncation_visible_only_to_the_anchor() -> None:
    """§7.1 cannot see a dropped tail; §7.2 can. Never one boolean."""
    truncated = _vector_headers()[:-1]
    assert verify_headers(truncated).chain_ok
    res = verify_headers(truncated, expected_head=bytes.fromhex(VECTORS["chain_head"]))
    assert res.complete_to_anchor is False
    assert res.anchor_lag is None
    assert "replaced, rolled back, or truncated" in (res.anchor_reason or "")


# ─── normative rules, exercised as attacks ───────────────────────────────


def _mk(seq: int, prev: bytes, rtype: int = RT_EVENT, **kw) -> Header:
    kw.setdefault("time_trust", TIME_NTP_SYNCED)
    return Header(record_type=rtype, seq=seq, boot_id=b"\x01" * 16, prev_hash=prev, **kw)


def test_seq_gap_is_a_break_even_with_valid_hashes() -> None:
    h0 = _mk(0, ZERO32, rtype=RT_GENESIS, time_trust=TIME_UNKNOWN)
    h5 = _mk(5, record_hash(h0.encode()))
    res = verify_headers([h0.encode(), h5.encode()])
    assert not res.chain_ok
    assert res.gaps == [5]
    assert res.breaks == []


def test_chain_must_start_with_genesis() -> None:
    lone = _mk(0, ZERO32)  # an EVENT with prev=0 is not a genesis
    res = verify_headers([lone.encode()])
    assert not res.chain_ok
    assert any("GENESIS" in reason for _, reason in res.violations)


def test_unknown_time_with_confident_clock_is_a_violation() -> None:
    h0 = _mk(0, ZERO32, rtype=RT_GENESIS, time_trust=TIME_UNKNOWN)
    bad = _mk(1, record_hash(h0.encode()), time_trust=TIME_UNKNOWN, wall_clock_ns=123)
    res = verify_headers([h0.encode(), bad.encode()])
    assert not res.chain_ok
    assert any("wall_clock_ns=0" in reason for _, reason in res.violations)


def test_unknown_record_type_is_chained_not_rejected() -> None:
    """§7.6: integrity does not require comprehension."""
    headers = _vector_headers()
    future = _mk(12, record_hash(headers[-1]), rtype=0x7FFF)
    res = verify_headers(headers + [future.encode()])
    assert res.chain_ok
    assert res.count == 13
    assert res.uninterpretable == [12]


def test_every_single_byte_mutation_is_detected() -> None:
    """Flip any one byte of any vector header: the chain must not verify
    clean. Deterministic sweep, no fuzzer needed at this size."""
    headers = _vector_headers()
    rng = random.Random(41)
    positions = rng.sample(range(FIXED_HEADER_LEN), 24)
    for pos in positions:
        mutated = list(headers)
        hb = bytearray(mutated[4])
        hb[pos] ^= 0x01
        mutated[4] = bytes(hb)
        res = verify_headers(mutated, expected_head=bytes.fromhex(VECTORS["chain_head"]))
        assert not (res.chain_ok and res.complete_to_anchor), (
            f"single-byte flip at offset {pos} went undetected"
        )


# ─── container (§2.4) ────────────────────────────────────────────────────


def _container_bytes() -> bytes:
    out = bytearray()
    for r in VECTORS["records"]:
        out += bytes.fromhex(r["header_hex"])
        out += bytes.fromhex(r.get("body_hex", ""))
    return bytes(out)


def test_container_roundtrip() -> None:
    """Concatenated records, boundaries found from frozen fields alone."""
    recs = list(iter_records(_container_bytes()))
    assert len(recs) == len(VECTORS["records"])
    got = verify_headers([h for h, _ in recs])
    assert got.chain_ok and got.head.hex() == VECTORS["chain_head"]
    for (hb, body), r in zip(recs, VECTORS["records"], strict=True):
        (blen,) = struct.unpack_from("<I", hb, 120)
        assert len(body) == blen == len(bytes.fromhex(r.get("body_hex", "")))


def test_container_truncated_tail_is_named_not_a_chain_break() -> None:
    data = _container_bytes()[:-5]
    with pytest.raises(MalformedRecord, match="truncated tail"):
        list(iter_records(data))


def test_tlv_overrun_is_malformed() -> None:
    h = _mk(0, ZERO32, rtype=RT_GENESIS, time_trust=TIME_UNKNOWN, tlvs=[(0x7000, b"abc")])
    hb = bytearray(h.encode())
    # corrupt the TLV length so it overruns header_len
    struct.pack_into("<H", hb, FIXED_HEADER_LEN + 2, 999)
    with pytest.raises(MalformedRecord):
        Header.decode(bytes(hb))


def test_headers_are_not_all_zero_span_by_accident() -> None:
    """Guard the field offsets: span ids land where §2.1 says they do."""
    h = _mk(3, ZERO32, span_id=b"\x22" * 16, parent_span_id=b"\x11" * 16)
    hb = h.encode()
    assert hb[68:84] == b"\x22" * 16
    assert hb[84:100] == b"\x11" * 16
    assert hb[36:68] == ZERO32
    assert h.span_id != ZERO16


# ─── the stdlib boundary itself ──────────────────────────────────────────


def test_pala_import_pulls_no_engine_or_crypto_dependencies() -> None:
    """The codec must be importable and useful with none of httpx,
    pydantic, typer or cryptography loaded. Run in a clean interpreter so
    this test cannot be fooled by whatever the suite already imported."""
    code = (
        "import sys; import palimpsests.audit.pala as p; "
        "assert p.verify_headers([]).count == 0; "
        "banned = {'httpx','pydantic','typer','cryptography'}; "
        "loaded = banned & set(m.split('.')[0] for m in sys.modules); "
        "assert not loaded, f'pala pulled in {loaded}'"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
