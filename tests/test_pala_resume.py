# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Writer cross-boot resume: open_existing, torn-tail recovery, discipline.

The lifecycle claim under test is core §4.2: the chain is continuous
across power cycles — a ``BOOT`` record's ``prev_hash`` is the previous
boot's head — and §2.4: a truncated tail is a reportable condition, not
a silent one.
"""
from __future__ import annotations

import pytest
import struct
from palimpsests.audit.pala import decode_tlvs, iter_records, verify_headers
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_SPAN_END,
    RT_SPAN_START,
)
from palimpsests.audit.pala_writer import (
    EVT_KIND,
    KIND_RECOVERY_TRUNCATED_TAIL,
    PalaWriter,
)
from palimpsests.providers.native.audit import NativeAudit


def _headers(path):
    return [hb for hb, _ in iter_records(path.read_bytes())]


def _types(path):
    return [struct.unpack_from("<H", hb, 8)[0] for hb in _headers(path)]


def _first_boot(tmp_path, *, leave_span_open: bool = False):
    """A first boot: genesis, boot, a session (optionally left unclosed)."""
    log = tmp_path / "serving.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    span = w.session_start("s-boot1")
    w.prefix_copy(64, span_id=span)
    if not leave_span_open:
        w.session_end(span)
    w.close()
    return log


def test_resume_continues_the_chain_across_boots(tmp_path):
    log = _first_boot(tmp_path, leave_span_open=True)
    first_boot_count = len(_headers(log))

    w2 = PalaWriter.open_existing(log)
    assert w2.recovered_tail_bytes == 0
    w2.boot()
    span2 = w2.session_start("s-boot2")
    w2.session_end(span2)
    w2.close()

    headers = _headers(log)
    res = verify_headers(headers)
    # One continuous, internally consistent chain across both boots.
    assert res.chain_ok is True
    assert res.count == first_boot_count + 3
    assert res.breaks == [] and res.gaps == [] and res.violations == []

    types = _types(log)
    assert types.count(RT_GENESIS) == 1, "resume must never write a second GENESIS"
    assert types.count(RT_BOOT) == 2
    # The unclosed span from boot 1 is still visibly unclosed (§3.1):
    # two SPAN_STARTs, only one SPAN_END.
    assert types.count(RT_SPAN_START) == 2
    assert types.count(RT_SPAN_END) == 1
    # Distinct boots carry distinct boot_ids.
    boot_ids = {hb[20:36] for hb in headers}
    assert len(boot_ids) == 2


def test_fresh_writer_refuses_a_non_empty_file(tmp_path):
    log = _first_boot(tmp_path)
    with pytest.raises(ValueError, match="open_existing"):
        PalaWriter(log)


def test_open_existing_refuses_empty_and_recordless_files(tmp_path):
    empty = tmp_path / "empty.pala"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        PalaWriter.open_existing(empty)

    garbage = tmp_path / "garbage.pala"
    garbage.write_bytes(b"\x00" * 200)
    with pytest.raises(ValueError, match="no complete record"):
        PalaWriter.open_existing(garbage)


def test_first_record_after_resume_must_be_boot(tmp_path):
    log = _first_boot(tmp_path)
    w2 = PalaWriter.open_existing(log)
    with pytest.raises(RuntimeError, match="MUST be BOOT"):
        w2.prefix_warm(token_count=8)
    w2.boot()  # and after the link, normal operation resumes
    w2.prefix_warm(token_count=8)
    w2.close()
    assert verify_headers(_headers(log)).chain_ok is True


def test_torn_tail_is_truncated_and_recorded(tmp_path):
    log = _first_boot(tmp_path)
    intact = log.stat().st_size
    # A crash mid-write: half a fixed header of a would-be record.
    with open(log, "ab") as fh:
        fh.write(b"PALA" + b"\x07" * (FIXED_HEADER_LEN // 2))

    w2 = PalaWriter.open_existing(log)
    assert w2.recovered_tail_bytes == FIXED_HEADER_LEN // 2 + 4
    assert log.stat().st_size == intact, "torn bytes truncated back to the last record"
    w2.boot()
    w2.recovery_truncated_tail()
    w2.close()

    headers = _headers(log)
    assert verify_headers(headers).chain_ok is True
    # The recovery is on the record: an EVENT with kind 7 and the byte count.
    last = headers[-1]
    (hlen,) = struct.unpack_from("<H", last, 6)
    (rtype,) = struct.unpack_from("<H", last, 8)
    assert rtype == RT_EVENT
    (body_len,) = struct.unpack_from("<I", last, 120)
    body = log.read_bytes()[-body_len:]
    tlvs = dict(decode_tlvs(body))
    assert struct.unpack("<H", tlvs[EVT_KIND])[0] == KIND_RECOVERY_TRUNCATED_TAIL


def test_recovery_note_about_nothing_is_refused(tmp_path):
    log = _first_boot(tmp_path)
    w2 = PalaWriter.open_existing(log)
    w2.boot()
    with pytest.raises(RuntimeError, match="no torn tail"):
        w2.recovery_truncated_tail()
    w2.close()


def test_mid_stream_damage_is_refused_not_auto_repaired(tmp_path):
    log = _first_boot(tmp_path)
    data = bytearray(log.read_bytes())
    # Corrupt the SECOND record's magic: bytes after the damage still
    # contain further record magic — this is not a torn tail.
    second_off = struct.unpack_from("<H", data, 6)[0]  # header_len of record 0
    data[second_off] ^= 0xFF
    log.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="mid-stream damage"):
        PalaWriter.open_existing(log)


def test_native_audit_over_a_resumed_writer_emits_boot_and_recovery(tmp_path):
    log = _first_boot(tmp_path)
    with open(log, "ab") as fh:
        fh.write(b"torn!")

    adapter = NativeAudit(PalaWriter.open_existing(log))
    adapter.writer.close()

    types = _types(log)
    assert types.count(RT_GENESIS) == 1
    assert types.count(RT_BOOT) == 2
    assert types[-1] == RT_EVENT  # the recovery, right after the second BOOT
    assert verify_headers(_headers(log)).chain_ok is True
