# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Checkpoints tile the chain, and writer-produced chains now prove."""
from __future__ import annotations

from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala.merkle import verify_proof
from palimpsests.audit.pala.proofs import inclusion_proof
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader


def test_writer_chain_becomes_provable(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()  # seq 0
    for _ in range(3):  # seq 1..3
        w.prefix_warm(token_count=7)
    assert merkle_checkpoint(w) is not None  # seq 4 covers [0, 3]
    w.prefix_warm(token_count=7)  # seq 5, tail
    w.close()

    with AuditReader.open(log) as reader:
        assert reader.verify().chain.chain_ok is True
        for seq in range(4):
            p = inclusion_proof(reader, seq)
            assert p is not None and p.root_seq == 4
            assert verify_proof(p.leaf, p.path, p.root) is True
        assert inclusion_proof(reader, 5) is None  # honest tail


def test_second_checkpoint_tiles_including_the_first(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()  # 0
    w.prefix_warm(token_count=1)  # 1
    merkle_checkpoint(w)  # 2 covers [0, 1]
    w.prefix_warm(token_count=1)  # 3
    w.prefix_warm(token_count=1)  # 4
    merkle_checkpoint(w)  # 5 covers [2, 4] — the first MERKLE included
    w.close()

    with AuditReader.open(log) as reader:
        assert reader.verify().chain.chain_ok is True
        # the first checkpoint record itself is provable via the second
        p = inclusion_proof(reader, 2)
        assert p is not None and p.root_seq == 5
        assert verify_proof(p.leaf, p.path, p.root) is True
        # every record except the final checkpoint is covered
        assert all(inclusion_proof(reader, s) is not None for s in range(5))
        assert inclusion_proof(reader, 5) is None


def test_empty_file_checkpoints_nothing(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    assert merkle_checkpoint(w) is None
    w.close()
