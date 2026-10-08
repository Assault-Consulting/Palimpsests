# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A Merkle frontier is the §4.3 tree, kept incrementally — not a variant of it."""
from __future__ import annotations

import hashlib
import pytest
import random
from palimpsests.audit.pala.frontier import MerkleFrontier
from palimpsests.audit.pala.merkle import merkle_root


def _hashes(n: int, seed: int = 9162) -> list[bytes]:
    rng = random.Random(seed)
    return [rng.randbytes(32) for _ in range(n)]


def test_every_prefix_root_equals_the_tree_built_from_scratch():
    # Every size from 0 to 300, each compared with merkle_root over the
    # same leaves — the definition chain_root and consistency proofs use.
    leaves = _hashes(300)
    f = MerkleFrontier()
    assert f.root() == merkle_root([]) == hashlib.sha256(b"").digest()
    for n in range(1, 301):
        f.append(leaves[n - 1])
        assert f.count == n
        assert f.root() == merkle_root(leaves[:n]), n


def test_the_state_stays_logarithmic():
    f = MerkleFrontier.from_record_hashes(_hashes(1000))
    # one subtree root per set bit of the count: 1000 = 0b1111101000
    assert len(f.to_bytes()) == 8 + 32 * bin(1000).count("1")


def test_serialised_and_restored_it_continues_as_if_never_stopped():
    leaves = _hashes(260)
    for cut in (0, 1, 2, 3, 7, 8, 64, 100, 127, 128, 129, 259):
        f = MerkleFrontier.from_record_hashes(leaves[:cut])
        g = MerkleFrontier.from_bytes(f.to_bytes())
        assert g.count == cut and g.root() == f.root()
        for h in leaves[cut:]:
            g.append(h)
        assert g.root() == merkle_root(leaves), cut


def test_a_copy_is_independent():
    leaves = _hashes(10)
    f = MerkleFrontier.from_record_hashes(leaves[:5])
    g = f.copy()
    g.append(leaves[5])
    assert f.count == 5 and f.root() == merkle_root(leaves[:5])
    assert g.root() == merkle_root(leaves[:6])


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x01\x00\x00\x00",  # shorter than the count
        (3).to_bytes(8, "little") + b"\x00" * 32,  # 3 leaves need 2 roots
        (4).to_bytes(8, "little") + b"\x00" * 64,  # 4 leaves need 1 root
        (1).to_bytes(8, "little") + b"\x00" * 31,  # a truncated root
    ],
)
def test_bytes_it_could_not_have_produced_are_rejected(data):
    with pytest.raises(ValueError):
        MerkleFrontier.from_bytes(data)


def test_a_record_hash_must_be_32_bytes():
    with pytest.raises(ValueError):
        MerkleFrontier().append(b"\x00" * 31)


def test_on_a_real_chain_frontier_and_chain_root_match_the_tree_at_every_length(tmp_path):
    from palimpsests.audit.pala.codec import record_hash
    from palimpsests.audit.pala.proofs import chain_root
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader

    path = tmp_path / "c.pala"
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        span = w.session_start("s")
        for i in range(40):
            w.kv_save(bytes([i]) * 32, span_id=span)
        w.session_end(span)
    with AuditReader.open(path) as r:
        hashes = [record_hash(hb) for hb in r._headers]
        f = MerkleFrontier()
        assert f.root() == merkle_root([]) == chain_root(r, 0)
        for i, h in enumerate(hashes):
            f.append(h)
            # merkle_root over the record hashes is the independent
            # definition; chain_root is checked against it too, because
            # chain_root itself now goes through a frontier — comparing
            # the frontier only with chain_root would compare it with
            # itself.
            expected = merkle_root(hashes[: i + 1])
            assert f.root() == expected
            assert chain_root(r, i + 1) == expected
