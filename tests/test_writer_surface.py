# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The writer's contract (docs/WRITER-SURFACE.md), held to the code.

The reader's surface has had this since 0.14 (test_consumer_surface.py).
The writer has two audiences — a runtime recording its own loop, and a
consumer's test suite that needs chains to read — and neither had a
document to hold it to, or a test that held the document.
"""
from __future__ import annotations

import inspect
import pytest
import re
import threading
from palimpsests.audit import pala_writer
from palimpsests.audit import reader as R
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala_writer import (
    ChainLocked,
    FrontierUnavailable,
    PalaWriter,
    RotationPolicy,
    session_span_id,
)
from palimpsests.audit.reader import AuditReader
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "WRITER-SURFACE.md").read_text(encoding="utf-8")
D = b"\x11" * 32

DECLARED = {
    "PalaWriter", "RotationPolicy", "Durability", "ChainLocked", "FrontierUnavailable",
    "session_span_id", "canonical_config_digest", "canonical_tool_args_digest",
    "canonical_tool_names_digest",
}

#: Every public member of ``PalaWriter``, with the parameters a caller may
#: rely on, in order. A release may add a keyword parameter with a default;
#: it does not remove or reorder one of these.
METHODS = {
    "genesis": [],
    "boot": [],
    "session_start": ["session_id", "role"],
    "session_end": ["span_id"],
    "model_load": ["model_digest", "config_digest", "role", "detail", "span_id"],
    "model_unload": ["role", "detail"],
    "kv_save": ["blob_digest", "span_id", "detail"],
    "kv_restore": ["blob_digest", "span_id"],
    "prefix_copy": ["token_count", "span_id"],
    "prefix_warm": ["token_count"],
    "tool_call": ["name", "args_digest", "detail", "span_id"],
    "tool_result": ["call_seq", "call_hash", "outcome", "result_digest", "span_id"],
    "tools_offered_no_call": ["count", "tools_digest", "span_id", "role"],
    "recovery_truncated_tail": ["role"],
    "reports_refused": ["route", "empty", "wrong", "accepted", "role"],
    "guard_prefix_release": ["holder_seq", "consumer_count", "span_id", "return_seq"],
    "guard_state_reject": ["detail", "span_id", "return_seq"],
    "guard_tool_loop_limit": ["iterations", "call_seq", "call_hash", "span_id"],
    "incident_candidate": ["category", "severity", "recoverable", "ref_seq", "ref_hash",
                           "detail", "role", "return_seq"],
    "oversight_ack": ["candidate_seq", "candidate_hash", "disposition", "operator_id", "role"],
    "aggregate": ["window_ns", "requests", "tokens_prefill", "tokens_decode",
                  "prefill_saved", "sessions_open"],
    "shed": ["shed_class", "count", "window_ns"],
    "anchor": [],
    "key_shred": ["key_id", "reason", "target_seqs", "detail"],
    "chain_root": [],
    "rotate": ["next_path"],
    "close": [],
    "open_existing": ["path", "rotation", "boot_id", "time_trust", "assurance_tier",
                      "recover_torn_tail"],
}
PROPERTIES = {"head", "head_hex", "seq", "path", "boot_id", "recovered_tail_bytes",
              "durability"}
RETURN_SEQ = {"tool_call", "incident_candidate", "guard_prefix_release",
              "guard_state_reject", "guard_tool_loop_limit"}


# ── what is declared ────────────────────────────────────────────────────────


def test_the_module_declares_exactly_the_documented_names():
    assert set(pala_writer.__all__) == DECLARED
    for name in DECLARED:
        assert f"`{name}" in DOC, f"{name} is declared and not documented"


def test_the_writer_has_exactly_the_documented_members():
    public = {n for n in dir(PalaWriter) if not n.startswith("_")}
    props = {n for n in public
             if isinstance(inspect.getattr_static(PalaWriter, n), property)}
    assert props == PROPERTIES
    assert public - props == set(METHODS)
    for name in public:
        assert f"`{name}" in DOC, f"PalaWriter.{name} is public and not documented"


def test_the_parameters_a_caller_relies_on_are_there_in_order():
    for name, promised in METHODS.items():
        params = [p for p in inspect.signature(getattr(PalaWriter, name)).parameters.values()
                  if p.name not in ("self", "cls")]
        names = [p.name for p in params]
        assert names[: len(promised)] == promised, name
        for extra in params[len(promised):]:
            # added since the list was written: must not break an old call
            assert extra.default is not inspect.Parameter.empty, (name, extra.name)
            assert extra.kind is inspect.Parameter.KEYWORD_ONLY, (name, extra.name)


@pytest.mark.lifecycle
def test_the_constructor_takes_what_the_document_says():
    params = inspect.signature(PalaWriter.__init__).parameters
    assert list(params)[1:] == ["path", "boot_id", "time_trust", "assurance_tier", "rotation",
                                "durability", "lifecycle"]
    assert params["lifecycle"].default is True
    assert all(params[p].kind is inspect.Parameter.KEYWORD_ONLY
               for p in ("boot_id", "time_trust", "assurance_tier", "rotation", "durability"))
    assert list(inspect.signature(RotationPolicy).parameters) == [
        "max_records", "max_bytes", "max_age_s", "retention_s"]


# ── every method, on a real chain ───────────────────────────────────────────


def _every_record(path):
    """Calls every record-writing method once. -> [(method, seq, returned)]"""
    calls = []
    w = PalaWriter(path)

    def do(name, *a, **k):
        seq = w.seq
        returned = getattr(w, name)(*a, **k)
        calls.append((name, seq, returned))
        return returned

    sid = session_span_id("s1")
    do("genesis")
    do("boot")
    do("model_load", D, D)
    do("session_start", "s1")
    do("kv_save", D, span_id=sid)
    do("kv_restore", D, span_id=sid)
    do("prefix_copy", 5, span_id=sid)
    do("prefix_warm", token_count=5)
    do("guard_prefix_release", 2, 1)
    do("guard_state_reject", detail="a reference")
    cand_seq, cand_hash = do("incident_candidate", 1, 2, detail="a reference", return_seq=True)
    do("oversight_ack", cand_seq, cand_hash, 1, b"\x01" * 16)
    call_seq, call_hash = do("tool_call", "search", args_digest=D, span_id=sid, return_seq=True)
    do("tool_result", call_seq, call_hash, 0, result_digest=D, span_id=sid)
    do("tools_offered_no_call", 2, D, span_id=sid)
    do("guard_tool_loop_limit", 3)
    do("aggregate", 10**9, requests=1, tokens_prefill=1, tokens_decode=1,
       prefill_saved=0, sessions_open=1)
    do("shed", 1, 2, 10**9)
    do("anchor")
    do("key_shred", 7)
    do("session_end", sid)
    do("model_unload")
    w.close()
    return calls


def _documented_table() -> dict[str, tuple[str, str]]:
    rows = re.findall(r"^\| `([a-z_]+)` \| ([A-Z_]+) \| ([A-Z_]+|—) \|$", DOC, re.M)
    return {method: (rtype, kind) for method, rtype, kind in rows}


def test_each_method_writes_the_record_the_document_says(tmp_path):
    names = {getattr(R, n): n[3:] for n in R.__all__ if n.startswith("RT_")}
    calls = _every_record(tmp_path / "all.pala")
    written = {}
    with AuditReader.open(tmp_path / "all.pala") as r:
        for method, seq, returned in calls:
            rec = r.record_at(seq)
            if method == "session_start":
                # the one method that returns something else: the span id
                assert returned == session_span_id("s1") == rec.header.span_id
            else:
                rh = returned[1] if isinstance(returned, tuple) else returned
                assert rec.record_hash == rh, method  # a method returns its record's hash
            if isinstance(returned, tuple):
                assert returned[0] == seq == rec.seq, method
            written[method] = (names[rec.record_type], rec.kind_name or "—")
    table = _documented_table()
    table.pop("recovery_truncated_tail")  # needs a torn tail: its own test below
    # its record is itself a remark (the reports_refused advisory), so it is
    # kept out of the chain "with nothing to remark": tests/test_reports_refused.py
    table.pop("reports_refused")
    assert written == table


def test_a_chain_written_through_every_method_verifies_with_nothing_to_remark(tmp_path):
    path = tmp_path / "all.pala"
    _every_record(path)
    with AuditReader.open(path) as r:
        ver = r.verify()
        assert r.is_consistent() and ver.diagnosis is None
        assert ver.chain.violations == [] and ver.advisory.items == []
    res = CliRunner().invoke(app, ["pala", "verify", str(path)])
    assert res.exit_code == 2  # consistent; no anchor was given


def test_return_seq_is_offered_where_a_later_record_refers_back():
    offering = {n for n in METHODS
                if "return_seq" in inspect.signature(getattr(PalaWriter, n)).parameters}
    assert offering == RETURN_SEQ


# ── a chain's life ──────────────────────────────────────────────────────────


def test_the_rules_of_a_chains_life(tmp_path):
    path = tmp_path / "life.pala"
    w = PalaWriter(path)
    with pytest.raises(RuntimeError, match="GENESIS"):
        w.boot()  # genesis comes first
    w.genesis()
    with pytest.raises(RuntimeError, match="GENESIS"):
        w.genesis()  # and only first
    with pytest.raises(ChainLocked):
        PalaWriter.open_existing(path)  # one writer per chain
    w.boot()
    w.close()
    with pytest.raises(ValueError, match="open_existing"):
        PalaWriter(path)  # a new writer on a file that holds records
    with PalaWriter.open_existing(path) as w2:
        with pytest.raises(RuntimeError, match="BOOT"):
            w2.prefix_warm()  # boot comes first after a resume
        w2.boot()
        w2.prefix_warm()
    empty = tmp_path / "empty.pala"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        PalaWriter.open_existing(empty)
    with AuditReader.open(path) as r:
        assert r.is_consistent() and r.record_count == 4


def test_leaving_the_with_block_releases_the_chain(tmp_path):
    path = tmp_path / "w.pala"
    with PalaWriter(path) as w:
        w.genesis()
    with PalaWriter.open_existing(path) as w:  # would raise ChainLocked otherwise
        w.boot()


def test_a_torn_tail_is_truncated_recorded_or_refused(tmp_path):
    path = tmp_path / "torn.pala"
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
    whole = path.stat().st_size
    with open(path, "ab") as fh:
        fh.write(b"PALA\x01\x00half a record")
    with pytest.raises(ValueError, match="torn"):
        PalaWriter.open_existing(path, recover_torn_tail=False)
    assert path.stat().st_size > whole  # refused: nothing was removed
    with PalaWriter.open_existing(path) as w:
        assert w.recovered_tail_bytes == len(b"PALA\x01\x00half a record")
        assert path.stat().st_size == whole  # truncated back to the last whole record
        w.boot()
        rh = w.recovery_truncated_tail()
    with AuditReader.open(path) as r:
        assert r.is_consistent()
        last = r.record_at(r.record_count - 1)
        assert last.record_hash == rh and last.kind_name == "RECOVERY_TRUNCATED_TAIL"
    with PalaWriter.open_existing(path) as w:
        w.boot()
        with pytest.raises(RuntimeError, match="no torn tail"):
            w.recovery_truncated_tail()


# ── the guarantees ──────────────────────────────────────────────────────────


def test_threads_writing_at_once_leave_one_chain(tmp_path):
    path = tmp_path / "threads.pala"
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    seen: list[tuple[int, bytes]] = []
    lock = threading.Lock()

    def work():
        for _ in range(50):
            pair = w.tool_call("t", args_digest=D, return_seq=True)
            with lock:
                seen.append(pair)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()
    with AuditReader.open(path) as r:
        assert r.is_consistent() and r.record_count == 402
        # the seq a call was given is the seq its record has — for every call
        assert len({s for s, _h in seen}) == 400
        for seq, rh in seen:
            assert r.record_at(seq).record_hash == rh


def test_the_head_and_seq_follow_the_chain(tmp_path):
    with PalaWriter(tmp_path / "w.pala") as w:
        assert w.seq == 0
        rh = w.genesis()
        assert (w.seq, w.head, w.head_hex) == (1, rh, rh.hex())
        assert w.path.endswith("w.pala") and len(w.boot_id) == 16
        root = w.chain_root()
    with AuditReader.open(tmp_path / "w.pala") as r:
        assert r.verify().chain.head == rh and len(root) == 32


def test_a_checkpoint_is_one_more_record_of_the_same_chain(tmp_path):
    path = tmp_path / "m.pala"
    with PalaWriter(path) as w:
        w.genesis()
        w.boot()
        rh = merkle_checkpoint(w)
        assert rh == w.head
    with AuditReader.open(path) as r:
        assert r.is_consistent() and r.record_at(2).record_type == R.RT_MERKLE


# ── segments ────────────────────────────────────────────────────────────────


def test_rotation_keeps_one_chain_across_files(tmp_path):
    base = tmp_path / "w.pala"
    with PalaWriter(base, rotation=RotationPolicy(max_records=4, retention_s=3600)) as w:
        w.genesis()
        for i in range(9):
            w.prefix_warm(token_count=i)
    assert (tmp_path / "w.pala.segments.json").is_file()
    segments = [base, *sorted(tmp_path.glob("w.pala.0*"))]
    assert len(segments) >= 3
    whole = b"".join(p.read_bytes() for p in segments)
    with AuditReader.from_bytes(whole) as r:
        assert r.is_consistent()  # the segments, end to end, are the chain
        kinds = [r.record_at(i).kind_name for i in range(r.record_count)]
        assert kinds.count("SEGMENT_CONTINUATION") == len(segments) - 1
    with pytest.raises(ValueError, match="threshold"):
        RotationPolicy()


def test_a_cut_by_hand_does_not_sever_an_open_span(tmp_path):
    with PalaWriter(tmp_path / "w.pala") as w:
        w.genesis()
        w.session_start("s1")
        with pytest.raises(ValueError, match="span"):
            w.rotate(tmp_path / "w.pala.next")
        w.session_end(session_span_id("s1"))
        w.rotate(tmp_path / "w.pala.next")
        w.prefix_warm()


def test_the_root_is_refused_rather_than_guessed(tmp_path):
    base = tmp_path / "w.pala"
    with PalaWriter(base, rotation=RotationPolicy(max_records=4)) as w:
        w.genesis()
        for i in range(6):
            w.prefix_warm(token_count=i)
    later = sorted(tmp_path.glob("w.pala.0*"))[-1]
    (tmp_path / "w.pala.segments.json").unlink()  # no recorded frontier to continue from
    with PalaWriter.open_existing(later) as w:
        w.boot()
        with pytest.raises(FrontierUnavailable):
            w.chain_root()


# ── what the document promises about itself ─────────────────────────────────


def test_the_document_states_the_limits_it_must():
    for phrase in ("on stable storage", "`Durability.OS`", "A disk that lies",
                   "That a stop was clean", "One writer per chain",
                   "experimental until 1.0", "Metadata only"):
        assert phrase in DOC, phrase
