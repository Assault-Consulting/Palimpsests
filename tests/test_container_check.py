# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The body walk as a reader method (U21) — and the report built from it.

Half of question one — is the container well-formed, does every body
match its header's digest — used to be reachable only by building a
report. It is now ``AuditReader.container_check()``, and the report's
``container`` section is that object, so the two can never disagree.
"""
from __future__ import annotations

import dataclasses
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader, ContainerCheck
from palimpsests.audit.report import build_report


def _chain(tmp_path):
    p = tmp_path / "c.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.model_load(b"\x01" * 32, b"\x02" * 32, detail="model")
        w.prefix_warm(token_count=3)
    return p


def test_a_sound_container(tmp_path):
    p = _chain(tmp_path)
    with AuditReader.open(p) as r:
        c = r.container_check()
    size = p.stat().st_size
    assert c == ContainerCheck(True, None, size, size, [])


def test_a_swapped_body_is_seen_here_and_not_by_verify(tmp_path):
    p = _chain(tmp_path)
    data = bytearray(p.read_bytes())
    i = data.rfind(b"model")  # inside the MODEL_LOAD body
    data[i] ^= 0x20
    with AuditReader.from_bytes(bytes(data)) as r:
        assert r.verify().chain.chain_ok is True  # header-only: blind to bodies
        c = r.container_check()
    assert c.well_formed and len(c.body_digest_mismatches) == 1


def test_a_cut_container_is_not_well_formed(tmp_path):
    data = _chain(tmp_path).read_bytes()[:-3]
    with AuditReader.from_bytes(data) as r:
        c = r.container_check()
    assert not c.well_formed and c.malformed and c.bytes_parsed < c.bytes_total


def test_it_is_computed_once(tmp_path):
    with AuditReader.open(_chain(tmp_path)) as r:
        assert r.container_check() is r.container_check()


def test_the_report_section_is_the_method(tmp_path):
    # a swapped body, so the section has something in it to get wrong
    data = bytearray(_chain(tmp_path).read_bytes())
    data[data.rfind(b"model")] ^= 0x20
    p = tmp_path / "swapped.pala"
    p.write_bytes(bytes(data))
    with AuditReader.open(p) as r:
        expected = dataclasses.asdict(r.container_check())
        assert expected["body_digest_mismatches"]  # not vacuous
        assert build_report(p, reader=r).data["container"] == expected
    assert build_report(p).data["container"] == expected  # its own reader, same answer

