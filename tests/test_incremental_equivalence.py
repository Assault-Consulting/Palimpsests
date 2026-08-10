# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""IncrementalVerifier: batch(N) ≡ N × incremental, and the advisory pass.

The refactor moved the §7.1 per-record rules into ``IncrementalVerifier``;
``verify_headers`` now drives it. This suite pins the property the sketch
requires — a chain verified as a batch and the same chain folded record by
record produce the identical result — on the §8 vector chain, a generated
chain, a two-boot resume chain, and each mutation-demo input. It also
covers the boot-scoped advisory signals gathered in that one pass.

The existing differential test against ``palaudit_ref.py`` and the §8 vector
values (test_pala_verify, test_pala_codec) remain the outer safety net and
pass unchanged.
"""

from __future__ import annotations

import json
from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.codec import (
    KNOWN_RECORD_TYPES,
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    TIME_NTP_SYNCED,
    ZERO16,
    ZERO32,
    Header,
    record_hash,
)
from palimpsests.audit.pala.incremental import IncrementalVerifier
from palimpsests.audit.pala_writer import PalaWriter
from pathlib import Path

VECTORS_PATH = Path(__file__).parent.parent / "docs/specs/pala-1/test-vectors.json"


def _fold(headers):
    """N × incremental: drive one IncrementalVerifier by hand."""
    v = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
    for hb in headers:
        v.step(hb)
        if v.halted:
            break
    return v.result()


def _headers(path):
    return [hb for hb, _ in iter_records(path.read_bytes())]


def _vector_headers():
    vectors = json.loads(VECTORS_PATH.read_text())
    container = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in vectors["records"]
    )
    return [hb for hb, _ in iter_records(container)], vectors


def _generated_chain(tmp_path):
    log = tmp_path / "gen.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.model_load(model_digest=bytes(range(32)), config_digest=bytes(range(32)))
    span = w.session_start("s1")
    w.prefix_copy(128, span_id=span)
    w.kv_save(bytes(range(32)), span_id=span)
    w.session_end(span)
    w.anchor()
    w.close()
    return log


def _resume_chain(tmp_path):
    log = tmp_path / "resume.pala"
    w = PalaWriter(log)
    w.genesis()
    w.boot()
    w.session_start("s-boot1")  # left open on purpose
    w.close()
    w2 = PalaWriter.open_existing(log)
    w2.boot()
    s2 = w2.session_start("s-boot2")
    w2.session_end(s2)
    w2.anchor()
    w2.close()
    return log


# --------------------------------------------------------------------------- #
# Equivalence — verify_headers(H) == fold(step, H)
# --------------------------------------------------------------------------- #


def test_equivalence_on_vector_chain():
    headers, vectors = _vector_headers()
    batch = verify_headers(headers)
    assert batch == _fold(headers)
    # and the fold reproduces the frozen §8 head.
    assert batch.chain_ok is True
    assert batch.head.hex() == vectors["chain_head"]


def test_equivalence_on_generated_chain(tmp_path):
    headers = _headers(_generated_chain(tmp_path))
    assert verify_headers(headers) == _fold(headers)
    assert verify_headers(headers).chain_ok is True


def test_equivalence_on_resume_chain(tmp_path):
    headers = _headers(_resume_chain(tmp_path))
    assert verify_headers(headers) == _fold(headers)
    assert verify_headers(headers).chain_ok is True


def test_equivalence_on_truncated_tail(tmp_path):
    headers = _headers(_generated_chain(tmp_path))[:-1]
    assert verify_headers(headers) == _fold(headers)


def test_equivalence_on_broken_link(tmp_path):
    headers = _headers(_generated_chain(tmp_path))
    tampered = bytearray(headers[2])
    tampered[40] ^= 0x01  # flip a prev_hash byte in a middle record
    headers[2] = bytes(tampered)
    assert verify_headers(headers) == _fold(headers)
    assert verify_headers(headers).chain_ok is False


def test_equivalence_on_missing_genesis(tmp_path):
    headers = _headers(_generated_chain(tmp_path))[1:]  # drop GENESIS
    batch = verify_headers(headers)
    assert batch == _fold(headers)
    # freeze-cycle rule: exactly one violation keyed at position 0.
    assert (0, "chain does not start with a GENESIS record") in batch.violations


# --------------------------------------------------------------------------- #
# Advisory — boot-scoped, header-only, never a verdict
# --------------------------------------------------------------------------- #

B1 = b"\x01" * 16
B2 = b"\x02" * 16


def _link(specs):
    """Build a properly-linked chain of headers from field specs.

    Each spec: (record_type, boot_id, monotonic_ns, wall_clock_ns, time_trust).
    seq auto-increments from 0; prev_hash chains via record_hash.
    """
    headers = []
    prev = ZERO32
    for i, (rtype, boot, mono, wall, tt) in enumerate(specs):
        hb = Header(
            record_type=rtype,
            seq=i,
            boot_id=boot,
            prev_hash=prev,
            time_trust=tt,
            span_id=ZERO16,
            parent_span_id=ZERO16,
            monotonic_ns=mono,
            wall_clock_ns=wall,
            body_len=0,
            body_digest=ZERO32,
        ).encode()
        headers.append(hb)
        prev = record_hash(hb)
    return headers


def _advisory_codes(headers):
    v = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
    for hb in headers:
        v.step(hb)
    return [item.code for item in v.advisory().items]


def test_mono_regression_within_a_boot_fires():
    headers = _link(
        [
            (RT_GENESIS, B1, 100, 0, TIME_NTP_SYNCED),
            (RT_EVENT, B1, 200, 0, TIME_NTP_SYNCED),
            (RT_EVENT, B1, 150, 0, TIME_NTP_SYNCED),  # regression
            (RT_ANCHOR, B1, 300, 0, TIME_NTP_SYNCED),
        ]
    )
    assert "mono_regression_in_boot" in _advisory_codes(headers)


def test_mono_reset_across_boot_does_not_fire():
    # A resume: boot 2 restarts monotonic below boot 1 — expected, not a signal.
    headers = _link(
        [
            (RT_GENESIS, B1, 100, 0, TIME_NTP_SYNCED),
            (RT_EVENT, B1, 200, 0, TIME_NTP_SYNCED),
            (RT_BOOT, B2, 5, 0, TIME_NTP_SYNCED),  # new boot_id, clock reset
            (RT_EVENT, B2, 10, 0, TIME_NTP_SYNCED),
            (RT_ANCHOR, B2, 20, 0, TIME_NTP_SYNCED),
        ]
    )
    assert "mono_regression_in_boot" not in _advisory_codes(headers)


def test_mid_boot_time_trust_change_fires():
    headers = _link(
        [
            (RT_GENESIS, B1, 100, 0, TIME_NTP_SYNCED),
            (RT_EVENT, B1, 200, 0, 1),  # time_trust changed within the boot
            (RT_ANCHOR, B1, 300, 0, 1),
        ]
    )
    assert "mid_boot_time_trust_change" in _advisory_codes(headers)


def test_anchor_never_written_fires_without_anchor():
    headers = _link(
        [
            (RT_GENESIS, B1, 100, 0, TIME_NTP_SYNCED),
            (RT_EVENT, B1, 200, 0, TIME_NTP_SYNCED),
        ]
    )
    assert "anchor_never_written" in _advisory_codes(headers)


def test_anchor_never_written_absent_with_anchor():
    headers = _link(
        [
            (RT_GENESIS, B1, 100, 0, TIME_NTP_SYNCED),
            (RT_ANCHOR, B1, 200, 0, TIME_NTP_SYNCED),
        ]
    )
    assert "anchor_never_written" not in _advisory_codes(headers)
