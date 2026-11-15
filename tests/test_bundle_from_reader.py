# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``assemble_bundle(reader=…)``, and the fields the bundle reads.

A consumer that holds the chain open could not hand it over: the bundle
took a path, read the file whole into memory, and then opened a reader on
it as well. ``build_report`` has taken ``reader=`` since 0.13.
"""
from __future__ import annotations

import json
import pytest
import struct
import tarfile
from palimpsests.audit import testing
from palimpsests.audit.anchors import ManualAnchor
from palimpsests.audit.pala import bundle
from palimpsests.audit.pala.bundle import assemble_bundle
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala_writer import PalaWriter
from palimpsests.audit.reader import HEADER_FIELDS, AuditReader


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "w.pala"
    w = PalaWriter(path)
    w.genesis()
    for i in range(30):
        w.prefix_warm(token_count=5)
        if i % 9 == 8:
            merkle_checkpoint(w)
    w.close()
    return path


CASES = ["good", "empty", *testing.DAMAGE]


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("rng", [(None, None), (4, 17)])
def test_a_bundle_from_a_reader_is_the_bundle_from_the_path(log, tmp_path, case, rng):
    good = log.read_bytes()
    data = good if case == "good" else b"" if case == "empty" else testing.DAMAGE[case].apply(good)
    src = tmp_path / "s.pala"
    src.write_bytes(data)
    a, b = tmp_path / "a.tar", tmp_path / "b.tar"
    by_path = assemble_bundle(src, a, from_seq=rng[0], to_seq=rng[1])
    with AuditReader.open(src) as reader:
        # the source is not opened: a name that does not exist is enough
        by_reader = assemble_bundle(
            tmp_path / "no-such-file", b, from_seq=rng[0], to_seq=rng[1], reader=reader)
        assert reader.record_count >= 0  # still open: used as given, never closed
    assert a.read_bytes() == b.read_bytes()
    assert (by_path.records, by_path.proven, by_path.head, by_path.consistent) == (
        by_reader.records, by_reader.proven, by_reader.head, by_reader.consistent)


def test_the_reader_answers_with_the_anchor_it_was_opened_with(log, tmp_path):
    with AuditReader.open(log) as plain:
        head = plain.verify().chain.head
        with pytest.raises(ValueError, match="not both"):
            assemble_bundle(log, tmp_path / "x.tar", reader=plain,
                            anchor_source=ManualAnchor(head.hex()))
        assert not (tmp_path / "x.tar").exists()
    a, b = tmp_path / "a.tar", tmp_path / "b.tar"
    assemble_bundle(log, a, anchor_source=ManualAnchor(head.hex()))
    with AuditReader.open(log, anchor=ManualAnchor(head.hex())) as anchored:
        assemble_bundle(log, b, reader=anchored)
    assert a.read_bytes() == b.read_bytes()
    with tarfile.open(b) as tar:
        assert json.loads(tar.extractfile("verification.json").read())[
            "completeness"]["checked"] is True


def test_the_source_file_is_not_read_into_memory(log, tmp_path, monkeypatch):
    """It was: ``Path(source).read_bytes()``, and then a mapping as well."""
    from pathlib import Path

    def refuse(self):
        raise AssertionError(f"read_bytes({self.name}) — the bundle copies the source")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    assert assemble_bundle(log, tmp_path / "b.tar").records == 34


def test_time_claims_are_the_decoded_header_fields(log, tmp_path):
    out = tmp_path / "b.tar"
    assemble_bundle(log, out)
    with tarfile.open(out) as tar:
        claims = json.loads(tar.extractfile("time-claims.json").read())["claims"]
    with AuditReader.open(log) as reader:
        assert len(claims) == reader.record_count
        for i, claim in enumerate(claims):
            h = reader.header_at(i)
            assert (claim["seq"], claim["time_trust"], claim["monotonic_ns"],
                    claim["wall_clock_ns"]) == (
                h.seq, h.time_trust, h.monotonic_ns, h.wall_clock_ns)


def test_the_bundle_takes_its_offsets_from_the_field_map(monkeypatch, log, tmp_path):
    """The bundle read ``seq``, ``time_trust``, ``monotonic_ns`` and
    ``wall_clock_ns`` at 12, 11, 100 and 108, written out in the module — a
    second statement of the layout, outside the codec's contract test. Here
    the field map is moved, and the bundle must follow it."""
    assert {f.name: bundle._FIELD[f.name] for f in HEADER_FIELDS} == bundle._FIELD
    fields = dict(bundle._FIELD)
    fields["monotonic_ns"], fields["wall_clock_ns"] = (
        fields["wall_clock_ns"], fields["monotonic_ns"])
    monkeypatch.setattr(bundle, "_FIELD", fields)
    out = tmp_path / "b.tar"
    assemble_bundle(log, out)
    with tarfile.open(out) as tar:
        claims = json.loads(tar.extractfile("time-claims.json").read())["claims"]
    with AuditReader.open(log) as reader:
        h = reader.header_at(3)
    q = struct.unpack("<q", struct.pack("<Q", h.monotonic_ns))[0]
    assert claims[3]["wall_clock_ns"] == q  # followed the map, not a literal
