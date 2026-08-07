# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for the PALA-1 inference-profile writer.

The definition of done for the inference profile (profile §7) is the library
verifying its own log: emit a representative serving stream, then confirm the
core verifier and the ``pala verify`` CLI accept it. These tests also assert the
profile *semantics* — origin triple on MODEL_LOAD, guard refusals as SAFETY, the
session span, AGG_PREFILL_SAVED present — so "the chain verifies" cannot pass
while the bytes mean the wrong thing.

Stdlib-only surface: the writer and the codec both run without the [pala] extra,
so nothing here imports cryptography.
"""
from __future__ import annotations

import struct
from palimpsests.audit.pala import (
    Header,
    decode_tlvs,
    iter_records,
    verify_headers,
)
from palimpsests.audit.pala.codec import (
    RT_AGGREGATE,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_SAFETY,
    RT_SHED,
    RT_SPAN_END,
    RT_SPAN_START,
    TLV_ORIGIN_CONFIG_DIGEST,
    TLV_ORIGIN_MODEL_DIGEST,
    TLV_ORIGIN_ROLE,
    ZERO16,
)
from palimpsests.audit.pala_writer import (
    AGG_PREFILL_SAVED,
    EVT_KIND,
    KIND_GUARD_PREFIX_RELEASE,
    KIND_KV_SAVE,
    KIND_MODEL_LOAD,
    KIND_PREFIX_COPY,
    ROLE_KV_STORE,
    ROLE_NATIVE,
    ROLE_SCHEDULER,
    PalaWriter,
    canonical_config_digest,
    session_span_id,
)


def _stream(path) -> PalaWriter:
    """A plausible slice of serving: boot, load a model, run a session with a
    KV save/restore and a shared-prefix copy, hit a guard refusal, publish a
    window of statistics, shed under load, and anchor."""
    model_digest = bytes(range(32))
    config_digest = canonical_config_digest({"window": 4096, "sink": 4, "block": 512})
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    w.model_load(model_digest, config_digest, detail="SmolLM2 @ q4")
    span = w.session_start("sess-abc")
    w.prefix_copy(128, span_id=span)
    w.kv_save(bytes(range(32, 64)), span_id=span, detail="checkpoint")
    w.kv_restore(bytes(range(32, 64)), span_id=span)
    w.guard_prefix_release(holder_seq=3, consumer_count=2, span_id=span)
    w.session_end(span)
    w.aggregate(
        window_ns=1_000_000_000,
        requests=12,
        tokens_prefill=3_000,
        tokens_decode=1_500,
        prefill_saved=2_048,
        sessions_open=1,
    )
    w.shed(shed_class=1, count=40, window_ns=2_000_000_000)
    return w


def _records(path) -> list[tuple[Header, bytes]]:
    data = path.read_bytes()
    return [(Header.decode(hb), body) for hb, body in iter_records(data)]


# ─── definition of done: the library verifies its own log ───────────────────


def test_emitted_stream_is_a_valid_complete_chain(tmp_path):
    p = tmp_path / "inference.pala"
    w = _stream(p)
    head = w.anchor()  # anchor the tip; the returned head is what the store holds
    w.close()

    headers = [h.encode() for h, _ in _records(p)]
    res = verify_headers(headers, expected_head=head)
    assert res.chain_ok, (res.breaks, res.gaps, res.violations)
    assert res.complete_to_anchor is True
    assert res.breaks == [] and res.gaps == [] and res.violations == []
    assert res.count == len(headers)


def test_pala_verify_cli_accepts_the_emitted_log(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    p = tmp_path / "inference.pala"
    w = _stream(p)
    head = w.anchor()
    w.close()

    result = CliRunner().invoke(app, ["pala", "verify", str(p), "--anchor", head.hex()])
    assert result.exit_code == 0, result.output
    assert "matches the supplied anchor" in result.output


def test_container_boundaries_and_record_hashes_chain(tmp_path):
    """The emitted bytes are a valid §2.4 container: boundaries recover, and
    each record's prev_hash links to the previous record's hash."""
    from palimpsests.audit.pala import record_hash

    p = tmp_path / "inference.pala"
    _stream(p).close()
    recs = _records(p)
    prev = b"\x00" * 32
    for hb_header, _ in ((h.encode(), b) for h, b in recs):
        assert Header.decode(hb_header).prev_hash == prev
        prev = record_hash(hb_header)


# ─── profile semantics: the bytes mean the right thing ──────────────────────


def test_chain_opens_with_genesis_then_boot(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    recs = _records(p)
    assert recs[0][0].record_type == RT_GENESIS
    assert recs[1][0].record_type == RT_BOOT
    # exactly one genesis, at position 0
    assert sum(h.record_type == RT_GENESIS for h, _ in recs) == 1


def test_model_load_carries_the_origin_triple(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    load = next(
        h
        for h, _ in _records(p)
        if h.record_type == RT_EVENT
        and any(t == TLV_ORIGIN_MODEL_DIGEST for t, _ in h.tlvs)
    )
    types = {t for t, _ in load.tlvs}
    assert TLV_ORIGIN_ROLE in types
    assert TLV_ORIGIN_MODEL_DIGEST in types
    assert TLV_ORIGIN_CONFIG_DIGEST in types
    role = dict(load.tlvs)[TLV_ORIGIN_ROLE].decode()
    assert role == ROLE_NATIVE


def test_session_records_share_one_span_id(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    span = session_span_id("sess-abc")
    recs = _records(p)
    starts = [h for h, _ in recs if h.record_type == RT_SPAN_START]
    ends = [h for h, _ in recs if h.record_type == RT_SPAN_END]
    assert len(starts) == 1 and len(ends) == 1
    assert starts[0].span_id == span and ends[0].span_id == span
    # the KV save inside the session carries the same span; a windowed
    # aggregate outside any session does not.
    kv = next(
        h
        for h, b in recs
        if h.record_type == RT_EVENT and _evt_kind(b) == KIND_KV_SAVE
    )
    assert kv.span_id == span
    agg = next(h for h, _ in recs if h.record_type == RT_AGGREGATE)
    assert agg.span_id == ZERO16


def test_guard_refusal_is_a_safety_record(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    safety = [(h, b) for h, b in _records(p) if h.record_type == RT_SAFETY]
    assert len(safety) == 1
    h, body = safety[0]
    assert _evt_kind(body) == KIND_GUARD_PREFIX_RELEASE
    assert dict(h.tlvs)[TLV_ORIGIN_ROLE].decode() == ROLE_SCHEDULER


def test_prefix_copy_records_token_count(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    copy = next(
        b
        for h, b in _records(p)
        if h.record_type == RT_EVENT and _evt_kind(b) == KIND_PREFIX_COPY
    )
    tlvs = dict(decode_tlvs(copy))
    # EVT_TOKEN_COUNT (0x0003) = 128, little-endian u32
    (token_count,) = struct.unpack("<I", tlvs[0x0003])
    assert token_count == 128


def test_aggregate_exposes_prefill_saved_as_a_series(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    agg_body = next(b for h, b in _records(p) if h.record_type == RT_AGGREGATE)
    tlvs = dict(decode_tlvs(agg_body))
    assert AGG_PREFILL_SAVED in tlvs
    (saved,) = struct.unpack("<Q", tlvs[AGG_PREFILL_SAVED])
    assert saved == 2_048


def test_shed_is_recorded(tmp_path):
    p = tmp_path / "inference.pala"
    _stream(p).close()
    assert any(h.record_type == RT_SHED for h, _ in _records(p))


def test_bodies_are_cleartext_metadata_only(tmp_path):
    """The profile's discipline: operation bodies are cleartext (key_id=0)."""
    p = tmp_path / "inference.pala"
    _stream(p).close()
    for h, body in _records(p):
        assert h.key_id == 0
        if body:
            # body_len/body_digest are consistent with the actual bytes
            assert h.body_len == len(body)


# ─── truncation is visible: emit, drop the anchor tail, completeness fails ───


def test_dropping_the_tail_breaks_completeness_not_the_chain(tmp_path):
    p = tmp_path / "inference.pala"
    w = _stream(p)
    head = w.anchor()
    w.close()
    recs = _records(p)
    truncated = [h.encode() for h, _ in recs[:-1]]  # drop the last record
    # the chain alone still links...
    assert verify_headers(truncated).chain_ok
    # ...but against the anchored head, the missing tail shows.
    res = verify_headers(truncated, expected_head=head)
    assert res.complete_to_anchor is False


# ─── config digest is deterministic and order-independent ───────────────────


def test_config_digest_is_deterministic_and_order_independent():
    a = canonical_config_digest({"window": 4096, "sink": 4})
    b = canonical_config_digest({"sink": 4, "window": 4096})
    assert a == b and len(a) == 32
    assert a != canonical_config_digest({"window": 8192, "sink": 4})


def _evt_kind(body: bytes) -> int:
    """EVT_KIND is the first TLV of an event/safety body (u16, LE)."""
    tlvs = dict(decode_tlvs(body))
    (kind,) = struct.unpack("<H", tlvs[EVT_KIND])
    return kind


# a tiny sanity check that the module surface is importable/usable
def test_role_and_kind_constants_match_profile():
    assert ROLE_NATIVE == "engine.native"
    assert ROLE_KV_STORE == "kv_store"
    assert KIND_MODEL_LOAD == 1
    assert KIND_GUARD_PREFIX_RELEASE == 100
    # profile allocates AGG quantities from 0x0003 upward
    assert AGG_PREFILL_SAVED == 0x0006


def test_remaining_event_kinds_and_context_manager(tmp_path):
    """Exercise the less-common profile methods and the context-manager path,
    and confirm the whole thing still verifies."""
    from palimpsests.audit.pala import verify_headers as _verify
    from palimpsests.audit.pala_writer import (
        KIND_GUARD_STATE_REJECT,
        KIND_MODEL_UNLOAD,
        KIND_PREFIX_WARM,
    )

    p = tmp_path / "misc.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.prefix_warm(token_count=64)
        w.guard_state_reject(detail="bad PALKV1 magic")
        w.model_unload(detail="evicted")
        head = w.anchor()

    recs = _records(p)
    kinds = {_evt_kind(b) for h, b in recs if b and _has_evt_kind(b)}
    assert {KIND_PREFIX_WARM, KIND_GUARD_STATE_REJECT, KIND_MODEL_UNLOAD} <= kinds
    assert _verify([h.encode() for h, _ in recs], expected_head=head).chain_ok


def test_genesis_must_be_first_and_unique(tmp_path):
    import pytest

    p = tmp_path / "order.pala"
    w = PalaWriter(p)
    with pytest.raises(RuntimeError, match="GENESIS"):
        w.boot()  # nothing emitted yet -> first record must be GENESIS
    w.genesis()
    with pytest.raises(RuntimeError, match="GENESIS"):
        w.genesis()  # a second GENESIS is refused
    w.close()


def _has_evt_kind(body: bytes) -> bool:
    return EVT_KIND in dict(decode_tlvs(body))
