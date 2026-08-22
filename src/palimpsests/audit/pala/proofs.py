# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U5 — the bridge from a ``seq`` to the Merkle primitives.

The primitives (§4.3: RFC 6962 domain separation, promotion not
duplication) already live in ``merkle.py``. What was missing is the
answer to three questions a bundle has to ask: *which leaves are these
records, in which aggregation, and what root does the proof land on.*

The coverage rule, stated once: a ``MERKLE`` record at seq ``M`` whose
``MERKLE_LEAF_COUNT`` TLV says ``N`` covers the ``N`` records
immediately preceding it — leaves are their record hashes, in seq
order, ``[M-N, M-1]``. Coverage is thus derivable from the count alone:
no extra TLV, no wire change, and windows tile the chain exactly when a
writer checkpoints periodically (each MERKLE record's own hash falls
into the next window).

``None``, not an exception, for a record no MERKLE record covers yet —
that is the *normal* state of a recent record, and the distinction
matters downstream: "not yet aggregated" is not "not included", and a
bundle must be able to say which.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    RT_MERKLE,
    TLV_MERKLE_LEAF_COUNT,
    TLV_MERKLE_TREE_HASH,
    decode_tlvs,
)
from palimpsests.audit.pala.codec import (
    record_hash as _record_hash,
)
from palimpsests.audit.pala.merkle import merkle_proof


@dataclass(frozen=True)
class InclusionProof:
    """One record's membership in one chain-carried aggregation."""

    seq: int
    leaf: bytes  # the record hash
    path: list[tuple[str, bytes]]  # as merkle_proof returns
    root: bytes  # the MERKLE record's tree hash, as read from the chain
    root_seq: int  # which MERKLE record carries it


def _index(reader) -> tuple[dict[int, bytes], list[tuple[int, bytes, int]]]:
    """One walk: record hash by seq, and every MERKLE (seq, root, count).

    Reads the reader's raw header view — package-internal by design: the
    proof must be built from the bytes the chain hash covered, not from
    a decoded projection.
    """
    hashes: dict[int, bytes] = {}
    merkles: list[tuple[int, bytes, int]] = []
    for hb in reader._headers:
        (hlen,) = struct.unpack_from("<H", hb, 6)
        (rtype,) = struct.unpack_from("<H", hb, 8)
        (seq,) = struct.unpack_from("<Q", hb, 12)
        hashes[seq] = _record_hash(hb)
        if rtype != RT_MERKLE:
            continue
        root: bytes | None = None
        count: int | None = None
        for t, v in decode_tlvs(hb[FIXED_HEADER_LEN:hlen]):
            if t == TLV_MERKLE_TREE_HASH and len(v) == 32:
                root = v
            elif t == TLV_MERKLE_LEAF_COUNT and len(v) == 4:
                (count,) = struct.unpack("<I", v)
        if root is not None and count:
            merkles.append((seq, root, count))
    return hashes, merkles


def _proof_from_index(
    hashes: dict[int, bytes],
    merkles: list[tuple[int, bytes, int]],
    seq: int,
) -> InclusionProof | None:
    if seq not in hashes:
        return None
    for mseq, root, count in merkles:
        lo = mseq - count
        if not (lo <= seq < mseq):
            continue
        window = [hashes.get(s) for s in range(lo, mseq)]
        if any(h is None for h in window):
            # The window is not fully present in what was walked; a proof
            # built from a partial window would land on a different root.
            continue
        leaves = [h for h in window if h is not None]
        return InclusionProof(
            seq=seq,
            leaf=hashes[seq],
            path=merkle_proof(leaves, seq - lo),
            root=root,
            root_seq=mseq,
        )
    return None


def inclusion_proof(reader, seq: int) -> InclusionProof | None:
    """The proof binding record ``seq`` to a chain-carried root, or None.

    None means *cannot prove from this stream*: the seq is absent, no
    MERKLE record covers it yet, or the covering window is not fully
    present. Checking the proof is the caller's act:
    ``verify_proof(p.leaf, p.path, p.root)`` — against the root as read
    from the chain, never one recomputed beside it.
    """
    hashes, merkles = _index(reader)
    return _proof_from_index(hashes, merkles, seq)


def range_proofs(reader, lo: int, hi: int) -> list[InclusionProof]:
    """Proofs for every provable seq in ``[lo, hi]`` — one walk, not many."""
    hashes, merkles = _index(reader)
    out: list[InclusionProof] = []
    for seq in range(lo, hi + 1):
        p = _proof_from_index(hashes, merkles, seq)
        if p is not None:
            out.append(p)
    return out
