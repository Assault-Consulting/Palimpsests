# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A range of proofs builds each checkpoint's tree once.

Every proof rebuilt its window's whole tree, so a range of ``n`` records
under a checkpoint of ``w`` leaves cost ``n × w`` hashes. Measured on a
chain of one million records checkpointed every 50,000: 64 ms a proof —
a bundle of 1,000 records took a minute, and a bundle of the whole chain
did not finish in twenty.
"""
from __future__ import annotations

import pytest
import random
from palimpsests.audit.pala import merkle, proofs
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala.merkle import merkle_proof, merkle_root, verify_proof
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader


@pytest.mark.parametrize("n", [*range(1, 70), 127, 128, 129, 1000])
def test_a_path_read_off_the_layers_is_merkle_proof(n):
    leaves = [bytes([i % 251]) * 32 + i.to_bytes(4, "big") for i in range(n)]
    layers = proofs._layers(leaves)
    assert layers[-1] == [merkle_root(leaves)]
    for index in (range(n) if n < 200 else random.Random(n).sample(range(n), 60)):
        path = proofs._path(layers, index)
        assert path == merkle_proof(leaves, index)
        assert verify_proof(leaves[index], path, layers[-1][0])


def _chain(tmp_path, windows):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    for size in windows:
        for _ in range(size):
            w.prefix_warm(token_count=5)
        merkle_checkpoint(w)
    for _ in range(3):
        w.prefix_warm(token_count=5)  # an unaggregated tail
    w.close()
    return log


def _reference(reader, lo, hi):
    """The construction as it was: one whole tree per proof."""
    hashes, merkles = proofs._index(reader)
    out = []
    for seq in range(lo, hi + 1):
        if seq not in hashes:
            continue
        for mseq, root, count in merkles:
            first = mseq - count
            if not first <= seq < mseq:
                continue
            window = [hashes.get(s) for s in range(first, mseq)]
            if any(h is None for h in window):
                continue
            out.append(proofs.InclusionProof(
                seq, hashes[seq], merkle_proof(window, seq - first), root, mseq))
            break
    return out


@pytest.mark.parametrize("windows", [[1], [7], [1, 1, 1], [5, 13, 2, 30], [64, 63, 65]])
def test_the_proofs_are_the_ones_built_one_tree_at_a_time(tmp_path, windows):
    log = _chain(tmp_path, windows)
    with AuditReader.open(log) as reader:
        n = reader.record_count
        got = proofs.range_proofs(reader, 0, n + 5)
        assert got == _reference(reader, 0, n + 5)
        assert all(verify_proof(p.leaf, p.path, p.root) for p in got)
        assert len(got) == n - 4  # the last checkpoint and the tail of three
        for seq in (0, 1, n // 2, n - 5, n - 4, n - 1, n):
            one = proofs.inclusion_proof(reader, seq)
            assert [one] == [p for p in got if p.seq == seq] or (one is None)
        assert proofs.range_proofs(reader, 3, 9) == [p for p in got if 3 <= p.seq <= 9]


def test_a_window_with_a_missing_record_proves_nothing(tmp_path):
    """Records dropped from the front: the first window is not whole, and a
    path built from part of it would land on another root."""
    from palimpsests.audit import testing

    log = _chain(tmp_path, [10, 10])
    cut = tmp_path / "cut.pala"
    cut.write_bytes(testing.drop_first_records(log.read_bytes()))
    with AuditReader.open(cut) as reader:
        got = proofs.range_proofs(reader, 0, 40)
        assert got == _reference(reader, 0, 40)
        assert got and min(p.seq for p in got) >= 11  # nothing from the first window


def test_windows_that_overlap_are_answered_in_file_order():
    """Not what ``merkle_checkpoint`` writes; a foreign writer may. The
    answer stays the first window, in file order, that holds the seq."""
    hashes = {s: bytes([s]) * 32 for s in range(12)}
    merkles = [(10, b"A" * 32, 10), (11, b"B" * 32, 6), (6, b"C" * 32, 6)]
    windows = proofs._Windows(hashes, merkles)
    assert not windows._tiled
    assert [windows.proof(s).root_seq for s in range(11)] == [10] * 10 + [11]
    assert windows.proof(11) is None and windows.proof(99) is None


def test_a_range_hashes_each_window_once(tmp_path, monkeypatch):
    log = _chain(tmp_path, [200, 200, 200])
    calls = {"n": 0}
    real = merkle.node_hash

    def counted(left, right):
        calls["n"] += 1
        return real(left, right)

    monkeypatch.setattr(proofs, "node_hash", counted)
    with AuditReader.open(log) as reader:
        got = proofs.range_proofs(reader, 0, reader.record_count)
    assert len(got) == 603  # genesis, 600 records, two earlier checkpoints
    # three trees of ~200 leaves: under 200 inner nodes each. One tree per
    # proof was 600 × 200.
    assert calls["n"] < 700
