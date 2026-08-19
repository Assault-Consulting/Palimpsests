# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""r3 reader advisories: tool references and span pairing.

Same design line as WS3, pinned again here: every check is an advisory,
never a violation — chains with dangling tool references or unpaired
spans stay ``chain_ok`` throughout. The span checks are the resolution
of independent run #5's finding: §3.1 promises a crash leaves a visibly
unclosed span, and the advisory channel is where a reader is now
instructed to look.
"""
from __future__ import annotations

import json
from hashlib import sha256
from palimpsests.audit.pala_writer import (
    OUTCOME_OK,
    PalaWriter,
    canonical_tool_args_digest,
)
from palimpsests.audit.reader import AuditReader
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)

TOOL_CODES = {"reference_unresolved", "reference_hash_mismatch", "tool_target_not_a_call"}
SPAN_CODES = {"span_unclosed", "span_unopened"}


def _codes(path, wanted):
    with AuditReader.open(path) as reader:
        v = reader.verify()
    assert v.chain.chain_ok is True  # advisories never touch the verdict
    return [i.code for i in v.advisory.items if i.code in wanted]


def test_correct_tool_loop_is_referentially_clean(tmp_path):
    log = tmp_path / "a.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        span = w.session_start("s1")
        call = w.tool_call(
            "web.search",
            args_digest=canonical_tool_args_digest({"q": 1}),
            span_id=span,
        )
        w.tool_result(
            w.seq - 1, call, OUTCOME_OK,
            result_digest=sha256(b"r").digest(), span_id=span,
        )
        w.guard_tool_loop_limit(3, call_seq=w.seq - 2, call_hash=call, span_id=span)
        w.session_end(span)
    assert _codes(log, TOOL_CODES | SPAN_CODES) == []


def test_dangling_tool_result_is_an_advisory_not_a_violation(tmp_path):
    log = tmp_path / "b.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.tool_result(99, b"\x11" * 32, OUTCOME_OK)
    assert _codes(log, TOOL_CODES) == ["reference_unresolved"]


def test_tool_result_hash_mismatch_is_the_stronger_signal(tmp_path):
    log = tmp_path / "c.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.tool_call("t")
        w.tool_result(w.seq - 1, b"\x22" * 32, OUTCOME_OK)  # right seq, wrong hash
    assert _codes(log, TOOL_CODES) == ["reference_hash_mismatch"]


def test_tool_result_bound_to_a_non_call_is_flagged(tmp_path):
    log = tmp_path / "d.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        other = w.prefix_warm(token_count=3)  # a resolvable non-call target
        w.tool_result(w.seq - 1, other, OUTCOME_OK)
    assert _codes(log, TOOL_CODES) == ["tool_target_not_a_call"]


def test_unclosed_span_is_surfaced_as_crash_evidence(tmp_path):
    log = tmp_path / "e.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.session_start("crashed")  # never ended — §3.1's promise, surfaced
    codes = _codes(log, SPAN_CODES)
    assert codes == ["span_unclosed"]


def test_span_referenced_without_endpoints_is_distinct(tmp_path):
    log = tmp_path / "f.pala"
    span = bytes(range(16))
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        w.tool_call("t", span_id=span)  # references a span nobody opened
    codes = _codes(log, SPAN_CODES)
    assert codes == ["span_unopened"]


def test_companion_vectors_show_the_run5_observation():
    """The published chain carries span references with no endpoints —
    exactly what run #5 reported on the core vectors. The reader now
    surfaces it, and the chain stays green: advisory, never a verdict."""
    v = json.loads(VECTORS.read_text())
    blob_path = None  # build the container in-memory via a temp file
    import tempfile

    blob = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )
    with tempfile.NamedTemporaryFile(suffix=".pala", delete=False) as fh:
        fh.write(blob)
        blob_path = fh.name
    with AuditReader.open(blob_path) as reader:
        ver = reader.verify()
    assert ver.chain.chain_ok is True
    assert "span_unopened" in {i.code for i in ver.advisory.items}
