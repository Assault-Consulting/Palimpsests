# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U5: from a seq to a verified membership proof, against the chain's root."""
from __future__ import annotations

import struct
from palimpsests.audit.pala.codec import (
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_MERKLE,
    TLV_MERKLE_LEAF_COUNT,
    TLV_MERKLE_TREE_HASH,
    ZERO32,
    Header,
    record_hash,
)
from palimpsests.audit.pala.merkle import merkle_root, verify_proof
from palimpsests.audit.pala.proofs import inclusion_proof, range_proofs
from palimpsests.audit.reader import AuditReader

BOOT_ID = bytes(range(16))


def _chain(tmp_path):
    """genesis, boot, 3 events, a MERKLE over all five, one uncovered event."""
    headers: list[bytes] = []
    hashes: list[bytes] = []
    prev = ZERO32

    def emit(h: Header) -> None:
        nonlocal prev
        hb = h.encode()
        headers.append(hb)
        hashes.append(record_hash(hb))
        prev = hashes[-1]

    emit(Header(record_type=RT_GENESIS, seq=0, boot_id=BOOT_ID, prev_hash=prev))
    emit(Header(record_type=RT_BOOT, seq=1, boot_id=BOOT_ID, prev_hash=prev))
    for seq in (2, 3, 4):
        emit(Header(record_type=RT_EVENT, seq=seq, boot_id=BOOT_ID, prev_hash=prev))
    root = merkle_root(hashes[:5])
    emit(
        Header(
            record_type=RT_MERKLE,
            seq=5,
            boot_id=BOOT_ID,
            prev_hash=prev,
            tlvs=[
                (TLV_MERKLE_TREE_HASH, root),
                (TLV_MERKLE_LEAF_COUNT, struct.pack("<I", 5)),
            ],
        )
    )
    emit(Header(record_type=RT_EVENT, seq=6, boot_id=BOOT_ID, prev_hash=prev))

    path = tmp_path / "chain.pala"
    path.write_bytes(b"".join(headers))
    return path, root


def test_every_covered_record_proves_against_the_chain_root(tmp_path):
    path, _ = _chain(tmp_path)
    with AuditReader.open(path) as reader:
        assert reader.verify().chain.chain_ok is True
        for seq in range(5):
            p = inclusion_proof(reader, seq)
            assert p is not None and p.root_seq == 5
            # against the root as read from the chain, never recomputed
            assert verify_proof(p.leaf, p.path, p.root) is True


def test_tampered_leaf_fails_the_proof(tmp_path):
    path, _ = _chain(tmp_path)
    with AuditReader.open(path) as reader:
        p = inclusion_proof(reader, 3)
    assert p is not None
    forged = bytes([p.leaf[0] ^ 0xFF]) + p.leaf[1:]
    assert verify_proof(forged, p.path, p.root) is False


def test_unaggregated_tail_is_none_not_an_error(tmp_path):
    path, _ = _chain(tmp_path)
    with AuditReader.open(path) as reader:
        assert inclusion_proof(reader, 6) is None  # not yet aggregated
        assert inclusion_proof(reader, 99) is None  # absent entirely


def test_range_proofs_cover_the_provable_subset_in_one_walk(tmp_path):
    path, _ = _chain(tmp_path)
    with AuditReader.open(path) as reader:
        proofs = range_proofs(reader, 3, 6)
    assert [p.seq for p in proofs] == [3, 4]
    assert all(verify_proof(p.leaf, p.path, p.root) for p in proofs)
