# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""structure(): one probe per boot, kept once computed; origin_state_at()."""
from __future__ import annotations

from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import AuditReader, OriginState


def _resumed_chain(path):
    """Boot 1 with ordinary events; boot 2 opens with RECOVERY_TRUNCATED_TAIL."""
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    span = w.session_start("s")
    for i in range(5):
        w.kv_save(bytes([i]) * 32, span_id=span)
    w.close()
    with open(path, "ab") as fh:  # a torn partial record, as a crash leaves one
        fh.write(b"PALA" + b"\x00" * 20)
    w2 = PalaWriter.open_existing(path)  # truncates the torn tail
    w2.boot()
    w2.recovery_truncated_tail()  # the first record after the resumed BOOT
    w2.kv_save(b"\x09" * 32)
    w2.close()
    return path


def test_recovery_is_found_where_the_profile_puts_it(tmp_path):
    with AuditReader.open(_resumed_chain(tmp_path / "c.pala")) as r:
        boots = r.boots()
    assert len(boots) == 2
    assert boots[0].recovery_seq is None
    assert boots[1].recovery_seq is not None


def test_structure_probes_one_record_per_boot_not_every_event(tmp_path, monkeypatch):
    # The cost U14 left in the report path: a body read for every EVENT on
    # a chain that never crashed. The profile places the recovery record
    # first after BOOT, so one probe per boot is the whole job.
    path = _resumed_chain(tmp_path / "c.pala")
    with AuditReader.open(path) as r:
        calls = {"n": 0}
        original = r._kind_probe

        def counting(*a, **k):
            calls["n"] += 1
            return original(*a, **k)

        monkeypatch.setattr(r, "_kind_probe", counting)
        r.structure()
        boots = len(r.boots())
    assert calls["n"] <= boots


def test_structure_is_computed_once_and_callers_cannot_alter_it(tmp_path, monkeypatch):
    path = _resumed_chain(tmp_path / "c.pala")
    with AuditReader.open(path) as r:
        passes = {"n": 0}
        original = r._structure_pass

        def counting():
            passes["n"] += 1
            return original()

        monkeypatch.setattr(r, "_structure_pass", counting)
        boots, spans = r.structure()
        boots.clear()
        spans.clear()
        again_boots, again_spans = r.structure()
        r.boots()
        r.spans()
    assert passes["n"] == 1
    assert len(again_boots) == 2 and again_spans  # unaffected by the caller's clear()


def _load_unload_chain(path):
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        w.model_load(b"\x11" * 32, b"\x22" * 32, detail="m")
        w.model_unload()
    return path


def test_origin_state_at_matches_the_two_methods_and_covers_all_three_states(tmp_path):
    with AuditReader.open(_load_unload_chain(tmp_path / "o.pala")) as r:
        states = []
        for seq in range(len(r._headers)):
            st = r.origin_state_at(seq)
            assert isinstance(st, OriginState)
            assert st.origin == r.origin_at(seq)
            assert st.unloaded == r.unloaded_at(seq)
            states.append((st.origin is not None, st.unloaded))
    assert (False, False) in states  # never declared
    assert (True, False) in states  # loaded
    assert (False, True) in states  # declared, then unloaded


def test_origin_state_at_walks_once(tmp_path, monkeypatch):
    with AuditReader.open(_load_unload_chain(tmp_path / "o.pala")) as r:
        calls = {"n": 0}
        original = r._origin_state_at

        def counting(seq):
            calls["n"] += 1
            return original(seq)

        monkeypatch.setattr(r, "_origin_state_at", counting)
        r.origin_state_at(2)
    assert calls["n"] == 1
