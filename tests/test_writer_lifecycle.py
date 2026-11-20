# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Inference profile r8: a writer marks where it began and that it was closed.

A chain that simply stopped said nothing about why: closed in order, killed,
or the power cut — and a power cut can be someone's choice. A crash in the
middle of a record left a torn tail, which a resumed writer records; a stop
between two records left nothing. ``WRITER_OPEN`` behind the writer's first
GENESIS or BOOT and ``WRITER_CLOSE`` as its last record make that stop
visible as the missing second half, once the chain goes on.
"""
from __future__ import annotations

import os
import pytest
from palimpsests import __version__
from palimpsests.audit.pala import vectors
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy
from palimpsests.audit.reader import (
    ADVISORY_CODES,
    KIND_WRITER_CLOSE,
    KIND_WRITER_OPEN,
    AuditReader,
)
from palimpsests.audit.report import build_report
from palimpsests.audit.segment_set import verify_segment_set

CODE = "boot_ended_without_close"


def _kinds(path):
    with AuditReader.open(path) as reader:
        return [d.kind_name or d.type_name for d in reader.records()]


def _unclosed(path, whole=True):
    with AuditReader.open(path) as reader:
        ver = reader.verify()
        assert reader.is_consistent() or not whole
        return [(i.at_seq, i.boot_id) for i in ver.advisory.items if i.code == CODE]


def _stop_without_close(writer):
    """What a kill or a power cut leaves: the records, and no close. The
    file and the lock are released as the dead process would release them."""
    writer._fh.close()
    writer._xlock.release()


def test_a_writer_opens_behind_its_first_record_and_closes_last(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.prefix_warm(token_count=1)
    assert (KIND_WRITER_CLOSE, KIND_WRITER_OPEN) == (12, 13)
    assert _kinds(log) == ["GENESIS", "WRITER_OPEN", "BOOT", "PREFIX_WARM", "WRITER_CLOSE"]
    with AuditReader.open(log) as reader:
        opened = reader.record_at(1)
        closed = reader.record_at(4)
    assert opened.detail == f"palimpsests {__version__}; inference r8"
    assert closed.detail is None and closed.header.key_id == 0
    assert _unclosed(log) == []


def test_one_open_per_writer_whatever_it_starts_with(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
    assert _kinds(log) == ["GENESIS", "WRITER_OPEN", "WRITER_CLOSE"]
    with PalaWriter.open_existing(log) as w:
        w.boot()
        w.boot()  # a second BOOT by the same writer opens nothing again
    assert _kinds(log) == ["GENESIS", "WRITER_OPEN", "WRITER_CLOSE",
                           "BOOT", "WRITER_OPEN", "BOOT", "WRITER_CLOSE"]
    assert _unclosed(log) == []


def test_close_is_written_once_and_nothing_follows_it(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    w.close()
    w.close()
    assert _kinds(log).count("WRITER_CLOSE") == 1
    with pytest.raises(ValueError):
        w.prefix_warm(token_count=1)  # a closed writer writes nothing more
    assert _kinds(log)[-1] == "WRITER_CLOSE"


def test_a_writer_that_wrote_nothing_marks_nothing(tmp_path):
    log = tmp_path / "w.pala"
    PalaWriter(log).close()
    assert log.read_bytes() == b""


def test_a_boot_stopped_without_a_close_is_reported_once_the_chain_goes_on(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    w.prefix_warm(token_count=1)
    first_boot = w.boot_id
    _stop_without_close(w)
    # the last boot in the file is never judged: its writer may be writing still
    assert _unclosed(log) == []

    with PalaWriter.open_existing(log) as w2:
        w2.boot()
        w2.prefix_warm(token_count=2)
    assert _unclosed(log) == [(2, first_boot)]  # at the stopped boot's last record
    with AuditReader.open(log) as reader:
        ver = reader.verify()
        assert ver.chain.chain_ok is True and ver.diagnosis is None  # advisory, not a verdict
    assert build_report(log).data["verdict"] == "partial"  # as any unanchored chain


def test_each_stopped_boot_is_reported_and_each_closed_one_is_not(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    stopped = [w.boot_id]
    _stop_without_close(w)
    for kill in (False, True, False):
        w = PalaWriter.open_existing(log)
        w.boot()
        w.prefix_warm(token_count=1)
        if kill:
            stopped.append(w.boot_id)
            _stop_without_close(w)
        else:
            w.close()
    assert [boot for _seq, boot in _unclosed(log)] == stopped
    assert CODE in ADVISORY_CODES


def test_a_chain_written_before_r8_is_not_judged(tmp_path):
    """No WRITER_OPEN, no promise: every chain of 0.9-0.14 is such a chain."""
    log = tmp_path / "old.pala"
    w = PalaWriter(log, lifecycle=False)
    w.genesis()
    w.prefix_warm(token_count=1)
    _stop_without_close(w)
    w = PalaWriter.open_existing(log, lifecycle=False)
    w.boot()
    w.close()
    assert "WRITER_OPEN" not in _kinds(log) and "WRITER_CLOSE" not in _kinds(log)
    assert _unclosed(log) == []
    # and the same chain continued by an r8 writer judges only what r8 wrote
    w = PalaWriter.open_existing(log)
    w.boot()
    _stop_without_close(w)
    with PalaWriter.open_existing(log) as w:
        w.boot()
    assert len(_unclosed(log)) == 1


def test_a_torn_tail_and_a_missing_close_are_both_on_the_record(tmp_path):
    """Power lost in the middle of a record: the resumed writer truncates and
    records the torn tail (kind 7), and the boot is reported as unclosed."""
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    w.prefix_warm(token_count=1)
    _stop_without_close(w)
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x00" * 40)  # half a header
    with PalaWriter.open_existing(log) as w2:
        w2.boot()
        w2.recovery_truncated_tail()
    kinds = _kinds(log)
    assert "RECOVERY_TRUNCATED_TAIL" in kinds and kinds[-1] == "WRITER_CLOSE"
    assert len(_unclosed(log)) == 1


def test_the_head_of_a_closed_chain_is_the_hash_of_its_close(tmp_path):
    """A head read from a running writer is the head of a chain that then
    grew by one record. An emitter that anchors at shutdown anchors after
    the close."""
    from palimpsests.audit.anchors import ManualAnchor

    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()
    w.prefix_warm(token_count=1)
    before = w.head
    w.close()
    after = w.head  # still readable on a closed writer
    assert before != after
    with AuditReader.open(log) as reader:
        assert reader.verify().chain.head == after
    assert build_report(log, anchor_source=ManualAnchor(after.hex())).data["verdict"] == "sound"
    # the earlier head is the anchor of a shorter chain: the file extends one
    # record beyond it, and is not complete against it
    early = build_report(log, anchor_source=ManualAnchor(before.hex())).data
    assert early["diagnosis"]["pattern"] == "unanchored_tail"
    assert early["completeness"]["complete_to_anchor"] is False
    assert early["completeness"]["anchor_lag"] == 1 and early["verdict"] != "sound"


def test_rotation_never_leaves_a_segment_behind_the_close(tmp_path):
    folder = tmp_path / "rot"
    folder.mkdir()
    with PalaWriter(folder / "w.pala", rotation=RotationPolicy(max_records=3)) as w:
        w.genesis()
        for i in range(7):  # the close lands exactly on a rotation threshold
            w.prefix_warm(token_count=i)
    v = verify_segment_set(folder / "w.pala.segments.json")
    assert v.consistent and v.complete
    tail = v.segments[-1]
    assert tail.listed is False and tail.verified  # the live file holds the close
    live = folder / tail.file
    assert _kinds(live) == ["SEGMENT_CONTINUATION", "WRITER_CLOSE"]
    assert _kinds(folder / "w.pala")[:2] == ["GENESIS", "WRITER_OPEN"]
    # a file that is not the chain's first segment holds no WRITER_OPEN of
    # its boot: read on its own, it promises nothing and is not judged
    assert _unclosed(live, whole=False) == []


def test_a_checkpoint_and_a_bundle_take_the_marks_as_ordinary_records(tmp_path):
    from palimpsests.audit.pala.bundle import assemble_bundle
    from palimpsests.audit.pala.proofs import range_proofs

    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        for _ in range(5):
            w.prefix_warm(token_count=1)
        merkle_checkpoint(w)
    with AuditReader.open(log) as reader:
        n = reader.record_count
        proofs = range_proofs(reader, 0, n)
    assert n == 9 and len(proofs) == 7  # GENESIS, WRITER_OPEN and five events proven
    result = assemble_bundle(log, tmp_path / "b.tar")
    assert result.consistent and result.records == 9


def test_the_serve_closes_its_chain(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from palimpsests.providers.native.audit import NativeAudit
    from palimpsests.server.openai_api import create_app

    log = tmp_path / "serve.pala"
    audit = NativeAudit(PalaWriter(log))
    client = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                   audit=audit))
    client.post("/v1/pala/events", json={"events": [
        {"type": "tool_call", "id": "c", "name": "t"}]})
    records_before = client.get("/v1/pala/status").json()["chain"]["records"]
    audit.writer.close()
    kinds = _kinds(log)
    assert kinds[1] == "WRITER_OPEN" and kinds[-1] == "WRITER_CLOSE"
    assert len(kinds) == records_before + 1


def test_the_vectors_show_an_opened_and_closed_boot(tmp_path):
    doc = vectors.load("inference")
    assert doc["profile_revision"] in ("r8", "r9") and len(doc["records"]) >= 27
    assert [r["label"] for r in doc["records"][24:27]] == ["boot_2", "writer_open",
                                                           "writer_close"]
    assert doc["semantics"]["25"]["kind_name"] == "WRITER_OPEN"
    assert doc["semantics"]["26"] == {"kind": 12, "kind_name": "WRITER_CLOSE"}

    def container(records):
        return b"".join(bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
                        for r in records)

    whole = tmp_path / "v.pala"
    whole.write_bytes(container(doc["records"]))
    with AuditReader.open(whole) as reader:
        ver = reader.verify()
        assert ver.chain.chain_ok and len(reader.boots()) >= 2
        assert [reader.record_at(i).kind_name for i in (25, 26)] == ["WRITER_OPEN",
                                                                    "WRITER_CLOSE"]
        assert reader.record_at(25).detail == doc["semantics"]["25"]["detail"]
    assert _unclosed(whole) == []


def test_the_lock_is_released_even_if_the_close_cannot_be_written(tmp_path):
    log = tmp_path / "w.pala"
    w = PalaWriter(log)
    w.genesis()

    def fail(*_a, **_k):
        raise OSError("disk gone")

    w._write_locked = fail
    with pytest.raises(OSError, match="disk gone"):
        w.close()
    assert w._fh.closed
    PalaWriter.open_existing(log).close()  # not ChainLocked
    assert os.path.getsize(log) > 0
