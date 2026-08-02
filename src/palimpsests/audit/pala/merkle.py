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
