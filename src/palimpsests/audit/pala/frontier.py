# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""The derived chain root, kept incrementally: a Merkle frontier.

The derived root of a chain prefix — the §4.3 tree over the record
hashes of records ``0..n-1``, as ``consistency-proof.md`` §1 defines it
— is what a prefix-consistency proof lands on, what the
retention-continuation design calls ``SEG_PRIOR_ROOT``, and what a
signed statement would carry to make two statements comparable. All
three need it **from record 0, always**, including after the oldest
records have been deleted under a retention policy. Recomputing it from
the records is then impossible: they are gone.

A frontier keeps exactly what is needed to go on: the roots of the
perfect subtrees the leaves so far decompose into — one per set bit of
the leaf count, so at most 64, and on a million-record chain 8. Adding a
leaf costs O(1) amortised; the root is a fold over at most 64 hashes.
Serialised it is the count and those roots: a few hundred bytes that
let a writer, after deleting segments, still state the root over
everything it ever wrote.

Same tree, not a variant: leaves are ``leaf_hash(record_hash)``,
interior nodes ``node_hash(left, right)``, an unpaired node promoted and
never duplicated — :func:`merkle.merkle_root`'s own rule, which equals
RFC 6962's split at the largest power of two. A frontier fed the record
hashes of a chain's first ``n`` records yields ``chain_root(reader, n)``
exactly; the tests check that for every size up to a few hundred.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable
from palimpsests.audit.pala.merkle import leaf_hash, node_hash

__all__ = ["MerkleFrontier"]

_EMPTY_ROOT = hashlib.sha256(b"").digest()
_COUNT = struct.Struct("<Q")


class MerkleFrontier:
    """Roots of the perfect subtrees covering the leaves appended so far."""

    __slots__ = ("_count", "_peaks")

    def __init__(self) -> None:
        self._count = 0
        # (height, hash), left to right; heights strictly decreasing —
        # the binary representation of the count, highest bit first.
        self._peaks: list[tuple[int, bytes]] = []

    @classmethod
    def from_record_hashes(cls, record_hashes: Iterable[bytes]) -> MerkleFrontier:
        f = cls()
        for h in record_hashes:
            f.append(h)
        return f

    @property
    def count(self) -> int:
        """How many record hashes have been appended."""
        return self._count

    def append(self, record_hash: bytes) -> None:
        """Add the next record's hash, in seq order."""
        if len(record_hash) != 32:
            raise ValueError("a record hash is 32 bytes")
        h = leaf_hash(record_hash)
        height = 0
        peaks = self._peaks
        while peaks and peaks[-1][0] == height:
            h = node_hash(peaks.pop()[1], h)
            height += 1
        peaks.append((height, h))
        self._count += 1

    def root(self) -> bytes:
        """The derived root over every record hash appended so far.

        The empty chain's root is ``SHA-256("")`` (§4.3). Otherwise the
        subtree roots fold right to left: the smallest, rightmost one is
        the unpaired node each larger one is joined with.
        """
        peaks = self._peaks
        if not peaks:
            return _EMPTY_ROOT
        acc = peaks[-1][1]
        for _height, h in reversed(peaks[:-1]):
            acc = node_hash(h, acc)
        return acc

    def to_bytes(self) -> bytes:
        """The count (u64, little-endian), then each subtree root, largest first.

        Nothing else is needed: which subtrees exist, and how tall each
        one is, follows from the count's set bits.
        """
        return _COUNT.pack(self._count) + b"".join(h for _, h in self._peaks)

    @classmethod
    def from_bytes(cls, data: bytes) -> MerkleFrontier:
        """Inverse of :meth:`to_bytes`; rejects anything it could not have produced."""
        if len(data) < _COUNT.size:
            raise ValueError("frontier too short for its count")
        (count,) = _COUNT.unpack_from(data, 0)
        heights = [b for b in range(63, -1, -1) if count >> b & 1]
        if len(data) != _COUNT.size + 32 * len(heights):
            raise ValueError(
                f"frontier for {count} leaves needs {len(heights)} roots, "
                f"got {(len(data) - _COUNT.size) / 32:g}"
            )
        f = cls()
        f._count = count
        f._peaks = [
            (height, bytes(data[_COUNT.size + 32 * i : _COUNT.size + 32 * (i + 1)]))
            for i, height in enumerate(heights)
        ]
        return f

    def copy(self) -> MerkleFrontier:
        f = MerkleFrontier()
        f._count = self._count
        f._peaks = list(self._peaks)
        return f
