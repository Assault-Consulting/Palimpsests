# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tests for the server-side tool loop (N5).

The point of N5: after an external tool runs, append_tool_result feeds
only the tool result into the live KV and resumes generation — the
conversation is not re-prefilled. The fake backend records the size of
each sequence's feeds, so a test can prove the tool-result feed is small
(just the result) rather than a re-read of the whole conversation.

FakeBackend is defined inline to keep the import block simple, matching
the other native test files.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession


class FakeBackend:
    """Deterministic NativeBackend recording every feed's first-decode size.

    ``feed_sizes`` collects, per turn, the number of input tokens in the
    first decode of that turn — so a test can compare the tool-result
    feed against the original turn feed.
    """

    def __init__(
        self,
        *,
        vocab_size: int = 64,
        n_seq_max: int = 4,
        eos: Token = 0,
        script: dict[int, list[Token]] | None = None,
    ) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self._eos = eos
        self._script = script or {}
        self._decode_count: dict[int, int] = {}
        self.removed: list[int] = []
        # Every decode's batch entry sizes, in call order, per seq.
        self.feed_sizes: list[int] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        return [(ord(c) % self._vocab) for c in text if not c.isspace()]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return "".join(chr(65 + (t % 26)) for t in tokens)

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            self.feed_sizes.append(len(list(entry.tokens)))
            i = self._decode_count.get(entry.seq_id, 0)
            self._decode_count[entry.seq_id] = i + 1
            script = self._script.get(entry.seq_id, [])
            token = script[i] if i < len(script) else self._eos
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        pass

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return b""

    def state_set(self, seq_id: int, state: bytes) -> None:
        pass

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None


def _session(backend: FakeBackend, **kwargs) -> NativeSession:
    kwargs.setdefault("stop_tokens", (0,))
    return NativeSession(backend, Scheduler(backend, max_active=1), **kwargs)


# ─── append_tool_result continues the same turn ───────────────────────────


def test_append_tool_result_streams_a_continuation():
    # First the model turn generates two tokens then a stop; then, after a
    # tool result, it generates two more then stop.
    backend = FakeBackend(eos=0, script={0: [5, 6, 0, 7, 8, 0]})
    sess = _session(backend)
    list(sess.send("use a tool please"))
    chunks = list(sess.append_tool_result("call_1", "42"))
    text = "".join(c.delta for c in chunks)
    assert text  # produced a continuation
    assert chunks[-1].done is True
    assert chunks[-1].finish_reason == "stop"


# ─── the whole point: the tool result is not a re-prefill ─────────────────


def test_tool_result_feed_is_small_not_a_reprefill():
    backend = FakeBackend(eos=0, script={0: [5, 6, 0, 7, 0]})
    sess = _session(
        backend, system_prompt="a long detailed system prompt for the agent"
    )
    # The first turn's first feed is system prompt + a long user message.
    list(sess.send("a fairly long user message asking for a tool call"))
    first_turn_feed = backend.feed_sizes[0]

    # Mark where the tool-result feeds begin.
    boundary = len(backend.feed_sizes)
    list(sess.append_tool_result("call_1", "7"))
    tool_feed = backend.feed_sizes[boundary]

    # The tool-result feed carries only the short result, not the whole
    # conversation — so it must be much smaller than the first turn's feed.
    assert tool_feed < first_turn_feed


def test_tool_loop_keeps_slot_alive_until_close():
    backend = FakeBackend(eos=0, script={0: [5, 0, 6, 0]})
    sess = _session(backend)
    list(sess.send("hi"))
    list(sess.append_tool_result("call_1", "r"))
    # nothing released while the session lives
    assert backend.removed == []
    sess.close()
    assert backend.removed == [0]


def test_append_tool_result_after_close_raises():
    backend = FakeBackend(eos=0, script={0: [5, 0]})
    sess = _session(backend)
    sess.close()
    with pytest.raises(RuntimeError):
        list(sess.append_tool_result("call_1", "r"))


# ─── r3: the loop is on the record (audit-wired) ──────────────────────────


def _audited_session(tmp_path, backend: FakeBackend, **kwargs):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.providers.native.audit import NativeAudit

    writer = PalaWriter(tmp_path / "loop.pala")
    audit = NativeAudit(writer, **kwargs.pop("audit_kwargs", {}))
    span = audit.session_opened()
    sess = NativeSession(
        backend,
        Scheduler(backend, max_active=1),
        stop_tokens=(0,),
        audit=audit,
        audit_span=span,
        **kwargs,
    )
    return sess, writer, tmp_path / "loop.pala"


def _recorded(path):
    from palimpsests.audit.pala import decode_tlvs, iter_records
    from palimpsests.audit.pala_writer import EVT_KIND

    out = []
    for hb, body in iter_records(path.read_bytes()):
        if body:
            tlvs = dict(decode_tlvs(body))
            if EVT_KIND in tlvs:
                import struct

                out.append((struct.unpack("<H", tlvs[EVT_KIND])[0], tlvs, hb))
    return out


def test_tool_loop_emits_call_and_hash_bound_result(tmp_path):
    import struct
    from hashlib import sha256
    from palimpsests.audit.pala_writer import (
        EVT_OUTCOME,
        EVT_PAYLOAD_DIGEST,
        EVT_REF_HASH,
        EVT_REF_SEQ,
        EVT_TOOL_NAME,
        KIND_TOOL_CALL,
        KIND_TOOL_RESULT,
        OUTCOME_OK,
    )

    backend = FakeBackend(eos=0, script={0: [5, 6, 0, 7, 0]})
    sess, writer, path = _audited_session(tmp_path, backend)
    list(sess.send("use a tool"))
    sess.note_tool_call("call_1", "web.search", arguments={"q": "pala"})
    list(sess.append_tool_result("call_1", "42"))
    sess.close()

    kinds = _recorded(path)
    call = next(x for x in kinds if x[0] == KIND_TOOL_CALL)
    result = next(x for x in kinds if x[0] == KIND_TOOL_RESULT)
    assert call[1][EVT_TOOL_NAME] == b"web.search"
    assert len(call[1][EVT_PAYLOAD_DIGEST]) == 32
    # the result binds to the call by BOTH seq and record hash
    from palimpsests.audit.pala import record_hash

    assert result[1][EVT_REF_HASH] == record_hash(call[2])
    assert struct.unpack("<H", result[1][EVT_OUTCOME])[0] == OUTCOME_OK
    assert result[1][EVT_PAYLOAD_DIGEST] == sha256(b"42").digest()
    assert struct.unpack("<Q", result[1][EVT_REF_SEQ])[0] >= 2


def test_loop_cap_records_the_guard_and_raises(tmp_path):
    import struct
    from palimpsests.audit.pala_writer import (
        EVT_TOKEN_COUNT,
        KIND_GUARD_TOOL_LOOP_LIMIT,
    )
    from palimpsests.providers.native.session import ToolLoopLimitError

    backend = FakeBackend(eos=0, script={0: [5, 0, 6, 0, 7, 0, 8, 0]})
    sess, _, path = _audited_session(tmp_path, backend, max_tool_hops=2)
    list(sess.send("go"))
    list(sess.append_tool_result("c1", "a"))
    list(sess.append_tool_result("c2", "b"))
    fed_before = len(backend.feed_sizes)
    with pytest.raises(ToolLoopLimitError):
        list(sess.append_tool_result("c3", "c"))
    # the refusal happened BEFORE anything was fed
    assert len(backend.feed_sizes) == fed_before
    limit = next(x for x in _recorded(path) if x[0] == KIND_GUARD_TOOL_LOOP_LIMIT)
    assert struct.unpack("<I", limit[1][EVT_TOKEN_COUNT])[0] == 2
    sess.close()


def test_send_resets_the_hop_counter(tmp_path):
    backend = FakeBackend(eos=0, script={0: [5, 0] * 8})
    sess, _, _path = _audited_session(tmp_path, backend, max_tool_hops=2)
    list(sess.send("t1"))
    list(sess.append_tool_result("a", "1"))
    list(sess.append_tool_result("b", "2"))
    list(sess.send("t2"))  # a new user turn is a new loop
    list(sess.append_tool_result("c", "3"))  # would raise without the reset
    sess.close()


def test_close_cancels_pending_dispatches(tmp_path):
    import struct
    from palimpsests.audit.pala_writer import (
        EVT_OUTCOME,
        KIND_TOOL_RESULT,
        OUTCOME_CANCELLED,
    )

    backend = FakeBackend(eos=0, script={0: [5, 0]})
    sess, _, path = _audited_session(tmp_path, backend)
    list(sess.send("go"))
    sess.note_tool_call("orphan", "slow.tool")
    sess.close()
    results = [x for x in _recorded(path) if x[0] == KIND_TOOL_RESULT]
    assert len(results) == 1
    assert struct.unpack("<H", results[0][1][EVT_OUTCOME])[0] == OUTCOME_CANCELLED


def test_fail_tool_call_records_without_feeding(tmp_path):
    import struct
    from palimpsests.audit.pala_writer import (
        EVT_OUTCOME,
        KIND_TOOL_RESULT,
        OUTCOME_TIMEOUT,
    )

    backend = FakeBackend(eos=0, script={0: [5, 0]})
    sess, _, path = _audited_session(tmp_path, backend)
    list(sess.send("go"))
    sess.note_tool_call("c1", "slow.tool")
    fed = len(backend.feed_sizes)
    sess.fail_tool_call("c1", OUTCOME_TIMEOUT)
    assert len(backend.feed_sizes) == fed  # nothing entered the KV
    sess.close()
    results = [x for x in _recorded(path) if x[0] == KIND_TOOL_RESULT]
    assert struct.unpack("<H", results[0][1][EVT_OUTCOME])[0] == OUTCOME_TIMEOUT


def test_repeated_limits_feed_the_escalation_trigger(tmp_path):
    from palimpsests.audit.pala_writer import KIND_INCIDENT_CANDIDATE
    from palimpsests.providers.native.session import ToolLoopLimitError

    backend = FakeBackend(eos=0, script={0: [5, 0, 6, 0]})
    sess, _, path = _audited_session(
        tmp_path,
        backend,
        max_tool_hops=1,
        audit_kwargs={"guard_escalation_threshold": 1},
    )
    list(sess.send("go"))
    list(sess.append_tool_result("a", "1"))
    with pytest.raises(ToolLoopLimitError):
        list(sess.append_tool_result("b", "2"))
    sess.close()
    kinds = [k for k, _t, _h in _recorded(path)]
    assert KIND_INCIDENT_CANDIDATE in kinds  # category-1 via the r2 trigger


def test_without_audit_the_cap_still_guards(tmp_path):
    from palimpsests.providers.native.session import ToolLoopLimitError

    backend = FakeBackend(eos=0, script={0: [5, 0, 6, 0]})
    sess = _session(backend, max_tool_hops=1)
    list(sess.send("go"))
    sess.note_tool_call("c1", "t")  # tracked, no audit — must not crash
    list(sess.append_tool_result("c1", "1"))
    with pytest.raises(ToolLoopLimitError):
        list(sess.append_tool_result("c2", "2"))
    sess.close()
