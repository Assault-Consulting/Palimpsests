# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``palimpsests.audit.testing``: damaged chains, and what the reader says.

The expectations in ``DAMAGE`` are a published promise to a consumer's test
suite, so they are held here against the reader, the CLI and the table in
``docs/WRITER-SURFACE.md``.
"""
from __future__ import annotations

import json
import pytest
import re
from palimpsests.audit import testing
from palimpsests.audit.anchors import ManualAnchor
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import DIAGNOSIS_PATTERNS, AuditReader
from palimpsests.audit.testing import DAMAGE
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

DOC = (Path(__file__).resolve().parent.parent / "docs" / "WRITER-SURFACE.md").read_text(
    encoding="utf-8")


@pytest.fixture
def chain(tmp_path) -> bytes:
    path = tmp_path / "source.pala"
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        w.model_load(b"\x11" * 32, b"\x22" * 32)
        for i in range(3):
            w.prefix_warm(token_count=i)
    return path.read_bytes()


@pytest.mark.parametrize("kind", sorted(DAMAGE))
def test_the_reader_says_what_the_table_says(kind, chain):
    damage = DAMAGE[kind]
    damaged = damage.apply(chain)
    assert damaged != chain
    with AuditReader.from_bytes(damaged) as r:
        diagnosis = r.verify().diagnosis
        assert (diagnosis.pattern if diagnosis else None) == damage.pattern
        assert (diagnosis.code if diagnosis else None) == damage.code
        assert r.is_consistent() is damage.consistent


@pytest.mark.parametrize("kind", sorted(DAMAGE))
def test_pala_verify_agrees(kind, chain, tmp_path):
    path = tmp_path / "d.pala"
    path.write_bytes(DAMAGE[kind].apply(chain))
    res = CliRunner().invoke(app, ["pala", "verify", str(path), "--json"])
    payload = json.loads(res.output)
    assert payload["consistency"]["ok"] is DAMAGE[kind].consistent
    assert res.exit_code == (2 if DAMAGE[kind].consistent else 1)


def test_the_source_is_never_changed(chain):
    before = bytes(chain)
    for damage in DAMAGE.values():
        damage.apply(chain)
    assert chain == before


def test_every_builder_is_in_the_table_and_the_document():
    builders = {n for n in testing.__all__
                if callable(getattr(testing, n)) and n != "Damage"}
    assert builders == set(DAMAGE)
    documented = {
        name: (text, flag)
        for name, text, flag in re.findall(
            r"^\| `([a-z_]+)` \| (.+?) \| (yes|no) \|$", DOC, re.M)
    }
    assert set(documented) == set(DAMAGE)
    for name, damage in DAMAGE.items():
        text, flag = documented[name]
        assert flag == ("yes" if damage.consistent else "no"), name
        if damage.pattern is not None:
            assert f"`{damage.pattern}`" in text, name
        if damage.code is not None:
            assert f"`{damage.code}`" in text, name
        assert damage.pattern is None or damage.pattern in DIAGNOSIS_PATTERNS


def test_one_defect_is_one_finding(chain):
    """Each builder makes the damage it names and no second one beside it."""
    with AuditReader.from_bytes(DAMAGE["violate_must"].apply(chain)) as r:
        chain_result = r.verify().chain
        assert len(chain_result.violations) == 1 and chain_result.breaks == []
    with AuditReader.from_bytes(DAMAGE["alter_body"].apply(chain)) as r:
        assert r.verify().chain.chain_ok is True
        assert len(r.container_check().body_digest_mismatches) == 1
    with AuditReader.from_bytes(DAMAGE["cut_mid_record"].apply(chain)) as r:
        assert r.record_count == len(list(iter_records(chain))) - 1
        assert r.container_check().well_formed is False


def test_the_tail_dropped_at_a_boundary_is_found_only_by_an_anchor(chain):
    with AuditReader.from_bytes(chain) as r:
        head_before = r.verify().chain.head.hex()
    shorter = testing.drop_last_records(chain, count=2)
    with AuditReader.from_bytes(shorter) as r:
        assert r.verify().diagnosis is None and r.is_consistent()  # nothing to see
    with AuditReader.from_bytes(shorter, anchor=ManualAnchor(head_before)) as r:
        ver = r.verify()
        assert ver.complete_to_anchor is False
        assert ver.diagnosis.pattern == "replaced_or_rolled_back"
        assert ver.diagnosis.question == "completeness" and r.is_consistent()


def test_a_record_can_be_picked_by_its_seq(chain):
    with AuditReader.from_bytes(testing.break_link(chain, seq=4)) as r:
        # the altered record, and the one after it, which named its old hash
        assert r.verify().chain.breaks == [4, 5]
        assert r.verify().diagnosis.at_seq == 4
    with AuditReader.from_bytes(testing.remove_record(chain, seq=3)) as r:
        assert r.verify().diagnosis.pattern == "seq_gap"
        assert [r.record_at(i).seq for i in range(r.record_count)] == [0, 1, 2, 4, 5]
    with AuditReader.from_bytes(testing.alter_body(chain, seq=2)) as r:
        assert list(r.container_check().body_digest_mismatches) == [2]


def test_what_cannot_be_done_is_refused_with_a_reason(chain):
    short = b"".join(h + b for h, b in list(iter_records(chain))[:2])
    for call in (
        lambda: testing.break_link(short),
        lambda: testing.break_link(chain, seq=0),
        lambda: testing.break_link(chain, seq=99),
        lambda: testing.remove_record(chain, seq=0),
        lambda: testing.remove_record(chain, seq=5),
        lambda: testing.alter_body(chain, seq=0),  # GENESIS here has no body
        lambda: testing.drop_first_records(chain, count=0),
        lambda: testing.drop_last_records(chain, count=6),
        lambda: testing.cut_mid_record(chain, missing=10**6),
    ):
        with pytest.raises(ValueError):
            call()


def test_the_table_is_read_only():
    with pytest.raises(TypeError):
        DAMAGE["new"] = DAMAGE["alter_body"]
