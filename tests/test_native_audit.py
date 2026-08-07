# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for the PALA-1 wiring of the native engine (Phase 3, step 2).

PR #102 proved the writer *can* emit a valid inference-profile chain; this
proves the emission is *alive* — the engine produces it at its real points:
MODEL_LOAD at backend acquisition, a span per session, KV_SAVE/KV_RESTORE at
the persistence boundary, GUARD_STATE_REJECT and GUARD_PREFIX_RELEASE where
the guards actually fire, PREFIX_WARM/PREFIX_COPY in the sharing policy, and
MODEL_UNLOAD + ANCHOR at shutdown. The exit assertions are the same as the
writer's definition of done — ``verify_headers`` and the ``pala verify`` CLI
accept the engine-produced file — plus the wiring-specific ones: nothing is
emitted per token (hot path untouched), and nothing at all with audit off.

FakeBackend is defined inline (matching the other native test files, none of
which import across test modules), extended with non-empty per-sequence state
so save/load round-trips.
"""
from __future__ import annotations

import pytest
import struct
from collections.abc import Sequence
from hashlib import sha256
from palimpsests.audit.pala import Header, decode_tlvs, iter_records, verify_headers
from palimpsests.audit.pala.codec import (
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_SAFETY,
    RT_SPAN_END,
    RT_SPAN_START,
    TLV_ORIGIN_CONFIG_DIGEST,
    TLV_ORIGIN_MODEL_DIGEST,
    TLV_ORIGIN_ROLE,
    ZERO16,
)
from palimpsests.audit.pala_writer import (
    EVT_BLOB_DIGEST,
    EVT_KIND,
    EVT_TOKEN_COUNT,
    KIND_GUARD_PREFIX_RELEASE,
    KIND_GUARD_STATE_REJECT,
    KIND_KV_RESTORE,
    KIND_KV_SAVE,
    KIND_MODEL_LOAD,
    KIND_MODEL_UNLOAD,
    KIND_PREFIX_COPY,
    KIND_PREFIX_WARM,
    PalaWriter,
    canonical_config_digest,
)
from palimpsests.providers.native import ENGINE_ID, NativeEngine
from palimpsests.providers.native.audit import injected_backend_digest
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import PrefixHolderInUseError
from palimpsests.providers.native.session import StateBlobError


class FakeBackend:
    """Deterministic backend: scripted one-hot decode, stateful KV bytes.

    ``state_get`` returns non-empty bytes unique to the sequence, so the
    session's framed save/load round-trips through the scheduler.
    """

    def __init__(
        self,
        *,
        vocab_size: int = 32,
        n_seq_max: int = 4,
        eos: Token = 0,
        script: dict[int, list[Token]] | None = None,
    ) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self._eos = eos
        self._script = script or {}
        self._decode_count: dict[int, int] = {}
        self.states: dict[int, bytes] = {}

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return " ".join(str(t) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            if not entry.wants_logits:
                continue
            i = self._decode_count.get(entry.seq_id, 0)
            self._decode_count[entry.seq_id] = i + 1
            script = self._script.get(entry.seq_id, [])
            token = script[i] if i < len(script) else self._eos
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    def seq_copy(self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1) -> None:
        return None

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return self.states.get(seq_id, f"kv-of-seq-{seq_id}".encode())

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.states[seq_id] = state

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


# ─── helpers ────────────────────────────────────────────────────────────────


def _records(path) -> list[tuple[Header, bytes]]:
    return [(Header.decode(hb), body) for hb, body in iter_records(path.read_bytes())]


def _kind_of(body: bytes) -> int:
    tlvs = dict(decode_tlvs(body))
    return struct.unpack("<H", tlvs[EVT_KIND])[0]


def _events(recs, kind: int) -> list[tuple[Header, dict[int, bytes]]]:
    """All EVENT/SAFETY records of an EVT_KIND, with their body TLVs."""
    out = []
    for h, body in recs:
        if h.record_type in (RT_EVENT, RT_SAFETY) and body and _kind_of(body) == kind:
            out.append((h, dict(decode_tlvs(body))))
    return out


def _engine(tmp_path, *, share_prefixes: bool = False, backend=None):
    writer = PalaWriter(tmp_path / "serving.pala")
    backend = backend or FakeBackend()
    eng = NativeEngine(backend=backend, audit=writer, share_prefixes=share_prefixes)
    return eng, writer, backend


# ─── chain lifecycle ────────────────────────────────────────────────────────


def test_constructing_the_engine_opens_the_chain(tmp_path):
    _, writer, _ = _engine(tmp_path)
    recs = _records(tmp_path / "serving.pala")
    assert [h.record_type for h, _ in recs] == [RT_GENESIS, RT_BOOT]
    assert writer.seq == 2


def test_second_engine_on_a_live_writer_adds_only_a_boot(tmp_path):
    """The cross-boot link (core §4.2): GENESIS once, a BOOT per engine."""
    writer = PalaWriter(tmp_path / "serving.pala")
    NativeEngine(backend=FakeBackend(), audit=writer)
    NativeEngine(backend=FakeBackend(), audit=writer)
    types = [h.record_type for h, _ in _records(tmp_path / "serving.pala")]
    assert types == [RT_GENESIS, RT_BOOT, RT_BOOT]


def test_without_audit_nothing_is_wired_and_serving_works(tmp_path):
    eng = NativeEngine(backend=FakeBackend(), share_prefixes=True)
    sess = eng.open_session(model="m", system_prompt="be terse")
    blob = sess.save_state()
    sess.load_state(blob)
    sess.close()
    eng.close()
    assert not (tmp_path / "serving.pala").exists()


# ─── model origin ───────────────────────────────────────────────────────────


def test_model_load_announced_once_with_the_origin_triple(tmp_path):
    eng, _, backend = _engine(tmp_path)
    eng.open_session(model="m")
    eng.open_session(model="m")  # second acquisition must not re-announce
    loads = _events(_records(tmp_path / "serving.pala"), KIND_MODEL_LOAD)
    assert len(loads) == 1
    header, _ = loads[0]
    tlvs = dict(header.tlvs)
    assert tlvs[TLV_ORIGIN_ROLE] == b"engine.native"
    # No model artefact behind an injected backend: the digest derives from
    # the backend's identity and the detail says so.
    assert tlvs[TLV_ORIGIN_MODEL_DIGEST] == injected_backend_digest(backend)
    assert tlvs[TLV_ORIGIN_CONFIG_DIGEST] == canonical_config_digest(
        {
            "engine": ENGINE_ID,
            "model_path": "",
            "max_tokens": 512,
            "max_sessions": 4,
            "share_prefixes": False,
        }
    )
    body_tlvs = loads[0][1]
    assert body_tlvs[0x0004].startswith(b"injected:")  # EVT_DETAIL


def test_model_digest_is_the_file_digest_when_a_model_path_exists(tmp_path):
    gguf = tmp_path / "tiny.gguf"
    gguf.write_bytes(b"GGUF\x00fake-weights")
    writer = PalaWriter(tmp_path / "serving.pala")
    eng = NativeEngine(
        backend=FakeBackend(), model_path=str(gguf), audit=writer
    )
    eng.open_session(model="m")
    loads = _events(_records(tmp_path / "serving.pala"), KIND_MODEL_LOAD)
    tlvs = dict(loads[0][0].tlvs)
    assert tlvs[TLV_ORIGIN_MODEL_DIGEST] == sha256(gguf.read_bytes()).digest()
    assert loads[0][1][0x0004] == b"gguf:tiny.gguf"


# ─── session spans and the KV boundary ──────────────────────────────────────


def test_session_span_wraps_its_kv_events_and_closes(tmp_path):
    eng, _, _ = _engine(tmp_path)
    sess = eng.open_session(model="m")
    blob = sess.save_state()
    sess.load_state(blob)
    sess.close()

    recs = _records(tmp_path / "serving.pala")
    starts = [h for h, _ in recs if h.record_type == RT_SPAN_START]
    ends = [h for h, _ in recs if h.record_type == RT_SPAN_END]
    assert len(starts) == 1 and len(ends) == 1
    span = starts[0].span_id
    assert span != ZERO16
    assert ends[0].span_id == span

    (save_h, save_tlvs), = _events(recs, KIND_KV_SAVE)
    (restore_h, restore_tlvs), = _events(recs, KIND_KV_RESTORE)
    assert save_h.span_id == span and restore_h.span_id == span
    # The recorded digest is of exactly the framed blob the caller holds.
    assert save_tlvs[EVT_BLOB_DIGEST] == sha256(blob).digest()
    assert restore_tlvs[EVT_BLOB_DIGEST] == sha256(blob).digest()


def test_rejected_blob_is_a_safety_record_and_still_raises(tmp_path):
    """The audit observes the guard; it never replaces it."""
    eng, _, _ = _engine(tmp_path)
    sess = eng.open_session(model="m")
    with pytest.raises(StateBlobError):
        sess.load_state(b"not a palimpsests blob")
    recs = _records(tmp_path / "serving.pala")
    (reject_h, _), = _events(recs, KIND_GUARD_STATE_REJECT)
    assert reject_h.record_type == RT_SAFETY
    assert dict(reject_h.tlvs)[TLV_ORIGIN_ROLE] == b"kv_store"
    # Scoped to the session whose load refused the blob.
    (start_h,) = [h for h, _ in recs if h.record_type == RT_SPAN_START]
    assert reject_h.span_id == start_h.span_id
    assert _events(recs, KIND_KV_RESTORE) == []  # no restore was recorded


# ─── shared prefixes ────────────────────────────────────────────────────────


def test_prefix_warm_once_and_a_copy_per_session(tmp_path):
    eng, _, _ = _engine(tmp_path, share_prefixes=True)
    s1 = eng.open_session(model="m", system_prompt="shared system prompt")
    s2 = eng.open_session(model="m", system_prompt="shared system prompt")
    recs = _records(tmp_path / "serving.pala")

    warms = _events(recs, KIND_PREFIX_WARM)
    copies = _events(recs, KIND_PREFIX_COPY)
    assert len(warms) == 1  # decoded once per unique prefix
    assert len(copies) == 2  # seeded into each session
    prefix_len = struct.unpack("<I", warms[0][1][EVT_TOKEN_COUNT])[0]
    assert prefix_len > 0
    spans = [h for h, _ in recs if h.record_type == RT_SPAN_START]
    assert len(spans) == 2
    for (copy_h, copy_tlvs), start_h in zip(copies, spans, strict=True):
        assert struct.unpack("<I", copy_tlvs[EVT_TOKEN_COUNT])[0] == prefix_len
        assert copy_h.span_id == start_h.span_id  # each copy on its session
    s1.close()
    s2.close()


def test_refused_holder_release_is_recorded_at_the_scheduler(tmp_path):
    """The canonical guard, from its real point: releasing a holder with a
    live consumer raises AND leaves a SAFETY record from the scheduler role."""
    eng, _, _ = _engine(tmp_path, share_prefixes=True)
    eng.open_session(model="m", system_prompt="shared system prompt")
    scheduler = eng._get_session_scheduler()
    (holder,) = eng._holders.values()
    with pytest.raises(PrefixHolderInUseError):
        scheduler.release_prefix_holder(holder.seq_id)
    recs = _records(tmp_path / "serving.pala")
    (guard_h, guard_tlvs), = _events(recs, KIND_GUARD_PREFIX_RELEASE)
    assert guard_h.record_type == RT_SAFETY
    assert dict(guard_h.tlvs)[TLV_ORIGIN_ROLE] == b"scheduler"
    assert b"1 live consumer" in guard_tlvs[0x0004]  # EVT_DETAIL


# ─── hot path ───────────────────────────────────────────────────────────────


def test_generating_tokens_emits_no_records(tmp_path):
    """Wiring stays off the decode path: a full turn adds zero records."""
    backend = FakeBackend(script={0: [5, 6, 7, 8, 9]})
    eng, _, _ = _engine(tmp_path, backend=backend)
    sess = eng.open_session(model="m")
    before = len(_records(tmp_path / "serving.pala"))
    text = "".join(chunk.delta for chunk in sess.send("hello"))
    assert text  # tokens were actually generated
    after = len(_records(tmp_path / "serving.pala"))
    assert after == before


# ─── shutdown and the exit test ─────────────────────────────────────────────


def test_close_unloads_and_anchors_and_the_chain_verifies(tmp_path):
    eng, writer, _ = _engine(tmp_path, share_prefixes=True)
    sess = eng.open_session(model="m", system_prompt="be terse")
    blob = sess.save_state()
    sess.load_state(blob)
    sess.close()
    eng.close()

    recs = _records(tmp_path / "serving.pala")
    assert _events(recs, KIND_MODEL_UNLOAD)
    assert recs[-1][0].record_type == RT_ANCHOR

    headers = [h.encode() for h, _ in recs]
    res = verify_headers(headers, expected_head=writer.head)
    assert res.chain_ok, (res.breaks, res.gaps, res.violations)
    assert res.complete_to_anchor is True
    assert res.breaks == [] and res.gaps == [] and res.violations == []


def test_pala_verify_cli_accepts_the_engine_produced_log(tmp_path):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    eng, writer, _ = _engine(tmp_path)
    sess = eng.open_session(model="m")
    sess.save_state()
    sess.close()
    eng.close()
    head = writer.head
    writer.close()

    result = CliRunner().invoke(
        app, ["pala", "verify", str(tmp_path / "serving.pala"), "--anchor", head.hex()]
    )
    assert result.exit_code == 0, result.output
    assert "matches the supplied anchor" in result.output


def test_forced_shutdown_leaves_an_unclosed_span_visible(tmp_path):
    """A session its owner never closed stays open in the chain — including
    one force-released by engine shutdown. The chain still verifies; the
    unclosed span is the honest record, not an error."""
    eng, writer, _ = _engine(tmp_path)
    eng.open_session(model="m")  # never closed by its owner
    eng.close()

    recs = _records(tmp_path / "serving.pala")
    starts = [h for h, _ in recs if h.record_type == RT_SPAN_START]
    ends = [h for h, _ in recs if h.record_type == RT_SPAN_END]
    assert len(starts) == 1 and ends == []
    res = verify_headers([h.encode() for h, _ in recs], expected_head=writer.head)
    assert res.chain_ok and res.complete_to_anchor is True
