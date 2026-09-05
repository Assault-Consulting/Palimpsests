# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""RFC 6962 Merkle tree hash for PALA-1 aggregation records (§4.3).

Domain-separated (0x00 for leaves, 0x01 for interior nodes) and with the
unpaired node **promoted, never duplicated** — duplication is the
CVE-2012-2459 mistake, where two distinct leaf sets collapse to one root.

The iterative promotion here is equivalent to RFC 6962's recursive
split-at-largest-power-of-two definition (the specification states this so
implementers do not go hunting for a discrepancy); it is written
iteratively because that is the shape a streaming writer wants.
"""
from __future__ import annotations

import hashlib

__all__ = ["leaf_hash", "merkle_proof", "merkle_root", "node_hash", "verify_proof"]


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """Tree hash over ``leaves``; SHA-256 of the empty string for none."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    layer = [leaf_hash(x) for x in leaves]
    while len(layer) > 1:
        nxt = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer) - 1, 2)]
        if len(layer) % 2:
            nxt.append(layer[-1])  # promote, do not duplicate
        layer = nxt
    return layer[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """Inclusion proof for ``leaves[index]``: ~log2(n) siblings, each step
    naming which side the sibling joins from. This is the selective
    disclosure §4.3 exists for — prove one frame without revealing the
    other twenty-nine."""
    if not 0 <= index < len(leaves):
        raise IndexError("proof index out of range")
    layer = [leaf_hash(x) for x in leaves]
    proof: list[tuple[str, bytes]] = []
    idx = index
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer) - 1, 2):
            if i == idx:
                proof.append(("R", layer[i + 1]))
            elif i + 1 == idx:
                proof.append(("L", layer[i]))
            nxt.append(node_hash(layer[i], layer[i + 1]))
        if len(layer) % 2:
            nxt.append(layer[-1])
        idx //= 2
        layer = nxt
    return proof


def verify_proof(leaf: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    """Recompute the path from one leaf through its siblings to the root."""
    h = leaf_hash(leaf)
    for side, sib in proof:
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == root


# ─── prefix consistency (RFC 6962 §2.1.2 / RFC 9162 §2.1.4) ─────────────
#
# A consistency proof shows that the tree over the first ``m`` leaves is
# a prefix of the tree over ``n`` leaves — that nothing before position
# ``m`` was changed, reordered, or removed between the two roots. It is
# O(log n) nodes and needs neither leaf set to verify. The construction
# below is RFC 6962's ``SUBPROOF``; the verification is RFC 9162's
# corrected algorithm. Because §4.3's promote-not-duplicate bottom-up
# tree equals the RFC's recursive one (PALA-1 §4.3 says so, and the
# differential tests check it), the RFC algorithms apply unchanged.


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_of_hashed(nodes: list[bytes]) -> bytes:
    """Tree hash over already leaf-hashed nodes — the bottom-up form."""
    layer = list(nodes)
    while len(layer) > 1:
        nxt = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer) - 1, 2)]
        if len(layer) % 2:
            nxt.append(layer[-1])
        layer = nxt
    return layer[0]


def _subproof(m: int, nodes: list[bytes], b: bool) -> list[bytes]:
    n = len(nodes)
    if m == n:
        return [] if b else [_root_of_hashed(nodes)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, nodes[:k], b) + [_root_of_hashed(nodes[k:])]
    return _subproof(m - k, nodes[k:], False) + [_root_of_hashed(nodes[:k])]


def consistency_proof(leaves: list[bytes], first: int) -> list[bytes]:
    """RFC 6962 ``PROOF(m, D[n])``: the nodes that let a verifier holding
    ``merkle_root(leaves[:first])`` and ``merkle_root(leaves)`` check that
    the former is a prefix of the latter. ``first`` MUST satisfy
    ``1 <= first <= len(leaves)``; a proof for ``first == len(leaves)`` is
    empty (the roots are simply equal)."""
    n = len(leaves)
    if not 1 <= first <= n:
        raise IndexError("consistency proof: first must be in 1..len(leaves)")
    return _subproof(first, [leaf_hash(x) for x in leaves], True)


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, proof: list[bytes]
) -> bool:
    """RFC 9162 §2.1.4.2. ``True`` iff ``proof`` shows the tree of size
    ``first`` with root ``first_root`` is a prefix of the tree of size
    ``second`` with root ``second_root``. Never raises on a bad proof."""
    if first < 1 or second < first:
        return False
    if first == second:
        return not proof and first_root == second_root
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two: the first root is its own node
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
