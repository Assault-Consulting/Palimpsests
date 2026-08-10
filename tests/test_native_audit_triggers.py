# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r2 pre-registered triggers, wired in the adapter.

Three triggers, three properties pinned: the guard-escalation window
emits exactly one candidate per threshold-crossing and demands a fresh
window afterwards; ``self_check`` puts a failing self-verification on
the very chain that failed; and the anchor-anomaly counter is
*consecutive* — one candidate per outage, reset by success, never one
per attempt. Trigger clocks are injected so window expiry is tested
without sleeping.
"""
from __future__ import annotations

import struct
from palimpsests.audit.pala import decode_tlvs, iter_records, verify_headers
from palimpsests.audit.pala_writer import (
    CAT_ANCHOR_ANOMALY,
    CAT_GUARD_ESCALATION,
    CAT_SELF_CHECK_FAILED,
    EVT_CATEGORY,
    EVT_KIND,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    KIND_INCIDENT_CANDIDATE,
    PalaWriter,
)
from palimpsests.providers.native.audit import NativeAudit


class FakeClock:
    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now


def _candidates(path) -> list[dict[int, bytes]]:
    out = []
    for _, body in iter_records(path.read_bytes()):
        if not body:
            continue
        tlvs = dict(decode_tlvs(body))
        kind = tlvs.get(EVT_KIND)
        if kind and struct.unpack("<H", kind)[0] == KIND_INCIDENT_CANDIDATE:
            out.append(tlvs)
    return out


def _cat(tlvs: dict[int, bytes]) -> int:
    return struct.unpack("<H", tlvs[EVT_CATEGORY])[0]


def test_guard_escalation_emits_once_per_window_and_references_the_last_guard(tmp_path):
    log = tmp_path / "a.pala"
    clock = FakeClock()
    w = PalaWriter(log)
    audit = NativeAudit(w, guard_escalation_threshold=3, clock=clock)

    audit.prefix_release_refused(1, 1)
    audit.prefix_release_refused(2, 1)
    assert _candidates(log) == []
    audit.state_rejected("bad frame", None)  # third refusal crosses the threshold
    last_guard_seq = w.seq - 2  # the guard just before the candidate
    cands = _candidates(log)
    assert len(cands) == 1 and _cat(cands[0]) == CAT_GUARD_ESCALATION
    assert struct.unpack("<Q", cands[0][EVT_REF_SEQ])[0] == last_guard_seq
    # the window was cleared: two more refusals do NOT re-trigger…
    audit.prefix_release_refused(3, 1)
    audit.prefix_release_refused(4, 1)
    assert len(_candidates(log)) == 1
    # …the third fresh one does.
    audit.prefix_release_refused(5, 1)
    assert len(_candidates(log)) == 2
    w.close()


def test_guard_refusals_outside_the_window_do_not_accumulate(tmp_path):
    log = tmp_path / "a.pala"
    clock = FakeClock()
    w = PalaWriter(log)
    audit = NativeAudit(
        w, guard_escalation_threshold=3, guard_escalation_window_ns=10, clock=clock
    )
    audit.prefix_release_refused(1, 1)
    clock.now = 20  # the first refusal is now outside the 10ns window
    audit.prefix_release_refused(2, 1)
    audit.prefix_release_refused(3, 1)
    assert _candidates(log) == []  # only two live entries — no escalation
    w.close()


def test_self_check_green_emits_nothing(tmp_path):
    log = tmp_path / "a.pala"
    w = PalaWriter(log)
    audit = NativeAudit(w)
    res = audit.self_check()
    assert res.chain_ok is True
    assert _candidates(log) == []
    w.close()


def test_self_check_failure_lands_on_the_chain_it_failed(tmp_path):
    log = tmp_path / "a.pala"
    w = PalaWriter(log)
    audit = NativeAudit(w)
    span = audit.session_opened()
    audit.session_closed(span)

    # Corrupt an already-written record on disk: flip one byte inside the
    # GENESIS header's prev_hash region. The writer's in-memory head is
    # untouched, so appends remain sound — exactly the situation the
    # docstring describes.
    data = bytearray(log.read_bytes())
    data[40] ^= 0xFF
    log.write_bytes(data)

    res = audit.self_check()
    assert res.chain_ok is False
    cands = _candidates(log)
    assert len(cands) == 1 and _cat(cands[0]) == CAT_SELF_CHECK_FAILED
    # and the machine-noticed-it record chains onto the damaged file:
    headers = [hb for hb, _ in iter_records(log.read_bytes())]
    res2 = verify_headers(headers)
    assert res2.count == res.count + 1  # the candidate itself
    w.close()


def test_anchor_anomaly_is_consecutive_and_resets_on_success(tmp_path):
    log = tmp_path / "a.pala"
    w = PalaWriter(log)
    audit = NativeAudit(w, anchor_failure_threshold=3)

    audit.anchor_store_failed("keychain locked")
    audit.anchor_store_failed("keychain locked")
    assert _candidates(log) == []
    audit.anchor_stored()  # success resets — the two failures were not consecutive
    audit.anchor_store_failed("io error")
    audit.anchor_store_failed("io error")
    assert _candidates(log) == []
    audit.anchor_store_failed("io error")  # third consecutive
    cands = _candidates(log)
    assert len(cands) == 1 and _cat(cands[0]) == CAT_ANCHOR_ANOMALY
    # a dead store keeps failing but does not spam candidates…
    audit.anchor_store_failed("io error")
    audit.anchor_store_failed("io error")
    assert len(_candidates(log)) == 1
    # …until a success closes the outage and a new one begins.
    audit.anchor_stored()
    for _ in range(3):
        audit.anchor_store_failed("down again")
    assert len(_candidates(log)) == 2
    # the escalation reference machinery was never involved: no ref TLVs
    assert EVT_REF_SEQ not in cands[0] and EVT_REF_HASH not in cands[0]
    w.close()
