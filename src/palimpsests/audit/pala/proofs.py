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
from bisect import bisect_right
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
from palimpsests.audit.pala.merkle import consistency_proof as merkle_consistency_proof
from palimpsests.audit.pala.merkle import (
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
)

__all__ = [
    "CONSISTENCY_FORMAT",
    "ConsistencyProof",
    "InclusionProof",
    "chain_root",
    "consistency_proof",
    "inclusion_proof",
    "range_proofs",
]


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


def _layers(leaves: list[bytes]) -> list[list[bytes]]:
    """Every layer of the §4.3 tree over ``leaves``, leaf hashes first.

    The same tree ``merkle_proof`` builds — pairs hashed, an odd node
    promoted and not duplicated — kept, so that many paths cost one tree.
    """
    layer = [leaf_hash(x) for x in leaves]
    layers = [layer]
    while len(layer) > 1:
        nxt = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer) - 1, 2)]
        if len(layer) % 2:
            nxt.append(layer[-1])
        layer = nxt
        layers.append(layer)
    return layers


def _path(layers: list[list[bytes]], index: int) -> list[tuple[str, bytes]]:
    """``merkle_proof(leaves, index)``, read off the kept layers."""
    path: list[tuple[str, bytes]] = []
    for layer in layers[:-1]:
        sibling = index ^ 1
        if sibling < len(layer):  # a promoted node has none at this level
            path.append(("L" if sibling < index else "R", layer[sibling]))
        index //= 2
    return path


class _Windows:
    """The chain-carried aggregations, each tree built at most once.

    A proof used to rebuild its window's whole tree: a range of ``n``
    records under a checkpoint of ``w`` leaves cost ``n × w`` hashes, and a
    bundle of a chain checkpointed every 50,000 records took a minute per
    thousand records. One tree per window makes it ``w + n·log w``. Only
    the latest window's layers are held: a range is walked in seq order.
    """

    def __init__(self, hashes: dict[int, bytes], merkles: list[tuple[int, bytes, int]]):
        self._hashes = hashes
        self._merkles = merkles
        self._starts = [mseq - count for mseq, _root, count in merkles]
        # Windows written by ``merkle_checkpoint`` tile the chain: each
        # starts where the one before ended. Then one window can hold a
        # seq and it is found by bisection. Windows that overlap or are
        # out of order are answered as before: the first, in file order,
        # that holds the seq and is fully present.
        self._tiled = all(
            mseq <= start
            for (mseq, _root, _count), start in zip(merkles, self._starts[1:], strict=False)
        )
        self._cached: tuple[int, list[list[bytes]] | None] | None = None

    def _candidates(self, seq: int):
        if not self._tiled:
            return range(len(self._merkles))
        i = bisect_right(self._starts, seq) - 1
        return (i,) if i >= 0 else ()

    def _layers_of(self, j: int) -> list[list[bytes]] | None:
        if self._cached is not None and self._cached[0] == j:
            return self._cached[1]
        mseq, _root, count = self._merkles[j]
        window = [self._hashes.get(s) for s in range(mseq - count, mseq)]
        # A window not fully present in what was walked: a proof built
        # from part of it would land on a different root.
        layers = None if any(h is None for h in window) else _layers(window)
        self._cached = (j, layers)
        return layers

    def proof(self, seq: int) -> InclusionProof | None:
        if seq not in self._hashes:
            return None
        for j in self._candidates(seq):
            mseq, root, count = self._merkles[j]
            lo = mseq - count
            if not (lo <= seq < mseq):
                continue
            layers = self._layers_of(j)
            if layers is None:
                continue
            return InclusionProof(
                seq=seq,
                leaf=self._hashes[seq],
                path=_path(layers, seq - lo),
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
    return _Windows(*_index(reader)).proof(seq)


def range_proofs(reader, lo: int, hi: int) -> list[InclusionProof]:
    """Proofs for every provable seq in ``[lo, hi]`` — one walk, not many."""
    windows = _Windows(*_index(reader))
    out: list[InclusionProof] = []
    for seq in range(lo, hi + 1):
        p = windows.proof(seq)
        if p is not None:
            out.append(p)
    return out


# ─── prefix consistency over the whole chain (WS-PROOF) ─────────────────
#
# The chain-carried MERKLE records cover windows. Prefix consistency
# needs one tree over the *whole* chain, so it is **derived**: the §4.3
# tree whose leaves are every record's hash in seq order, computed by
# any verifier from headers alone. Nothing is added to the wire; the
# root is a function of bytes the chain hash already covers. Two
# verifiers holding two derived roots — an archived prefix's, taken
# when it was archived, and the live chain's today — can check with
# O(log n) nodes that the prefix is intact under the live chain, without
# the archived records, and without re-hashing them. That is the formal
# half of retention (RETENTION.md §3) and the value the continuation
# profile's ``SEG_PRIOR_ROOT`` is defined to carry.

CONSISTENCY_FORMAT = "pala-consistency-proof/1"


@dataclass(frozen=True)
class ConsistencyProof:
    """A prefix-consistency proof between two derived roots of one chain.

    ``first`` and ``second`` are record *counts* (``seq + 1`` of the last
    record covered), not seqs; ``first <= second``. ``path`` is the RFC
    6962 consistency path. Derived and unsigned, like a bundle: the
    chain stays authoritative and the proof re-verifies from the spec
    alone.
    """

    first: int
    second: int
    first_root: bytes
    second_root: bytes
    path: list[bytes]

    def to_json(self) -> dict:
        return {
            "format": CONSISTENCY_FORMAT,
            "tree": "PALA-1 §4.3 over record hashes, seq order, whole chain",
            "first": self.first,
            "second": self.second,
            "first_root": self.first_root.hex(),
            "second_root": self.second_root.hex(),
            "path": [h.hex() for h in self.path],
        }

    @classmethod
    def from_json(cls, doc: dict) -> ConsistencyProof:
        """Read a document, or raise ``ValueError`` — and nothing else — when
        it is not of this shape.

        Shape is checked, not coerced: the counts are JSON integers (``2.7``
        is not 2, ``true`` is not 1, ``"7"`` is not 7), the roots and the
        path's elements are hex strings. A document of the right shape whose
        path does not connect its roots is not an error: it reads, and
        :meth:`verify` returns ``False``.
        """
        if not isinstance(doc, dict) or doc.get("format") != CONSISTENCY_FORMAT:
            raise ValueError(f"not a {CONSISTENCY_FORMAT} document")

        def count(key: str) -> int:
            v = doc.get(key)
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(f"'{key}' is not an integer")
            return v

        def hexbytes(v: object, what: str) -> bytes:
            if not isinstance(v, str):
                raise ValueError(f"{what} is not a hex string")
            try:
                return bytes.fromhex(v)
            except ValueError as e:
                raise ValueError(f"{what} is not a hex string") from e

        path = doc.get("path")
        if not isinstance(path, list):
            raise ValueError("'path' is not a list")
        return cls(
            first=count("first"),
            second=count("second"),
            first_root=hexbytes(doc.get("first_root"), "'first_root'"),
            second_root=hexbytes(doc.get("second_root"), "'second_root'"),
            path=[hexbytes(h, "a path element") for h in path],
        )

    def verify(self) -> bool:
        """The proof against its own roots — RFC 9162 §2.1.4.2. A caller
        who holds a root from elsewhere (an archive manifest, a receipt)
        compares it to ``first_root`` / ``second_root`` first; the proof
        only says the two roots are consistent, never where they came
        from."""
        return verify_consistency(
            self.first, self.second, self.first_root, self.second_root, self.path
        )


def _record_hashes(reader, count: int | None = None) -> list[bytes]:
    headers = reader._headers
    n = len(headers) if count is None else count
    if not 0 <= n <= len(headers):
        raise IndexError("count exceeds the records present")
    return [_record_hash(headers[i]) for i in range(n)]


def chain_root(reader, count: int | None = None) -> bytes:
    """The derived root over the first ``count`` records (all, by
    default): the §4.3 tree over their record hashes in seq order. The
    empty chain's root is ``SHA-256("")`` per §4.3.

    Computed through a :class:`~palimpsests.audit.pala.frontier.MerkleFrontier`
    rather than a list of every record hash and a layer of every leaf:
    the same root (the frontier tests compare them at every size), in
    O(log n) memory instead of two O(n) lists — measured on a
    million-record chain, a Python-heap peak of about 175 MiB down to
    nothing worth printing.
    """
    from palimpsests.audit.pala.frontier import MerkleFrontier

    headers = reader._headers
    n = len(headers) if count is None else count
    if not 0 <= n <= len(headers):
        raise IndexError("count exceeds the records present")
    return MerkleFrontier.from_record_hashes(_record_hash(headers[i]) for i in range(n)).root()


def consistency_proof(reader, first: int, second: int | None = None) -> ConsistencyProof:
    """Prove that the first ``first`` records are a prefix of the first
    ``second`` (default: every record present). Both are counts, not
    seqs, and ``1 <= first <= second``."""
    leaves = _record_hashes(reader, second)
    second_n = len(leaves)
    if not 1 <= first <= second_n:
        raise IndexError("first must be in 1..second")
    return ConsistencyProof(
        first=first,
        second=second_n,
        first_root=merkle_root(leaves[:first]),
        second_root=merkle_root(leaves),
        path=merkle_consistency_proof(leaves, first),
    )
