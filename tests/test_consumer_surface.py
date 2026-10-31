# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The consumer surface, pinned by name (docs/CONSUMER-SURFACE.md, U20).

Every symbol, field, method, frozen number and vocabulary member a
reader-side consumer may rely on is asserted here. A change that removes
or renames one fails this file; a change that *adds* one fails it too
where the rules say additions must be deliberate (``__all__``, the
vocabularies) — the test is then updated in the same PR, in sight of the
reviewer, with a CHANGELOG line. Fields may grow (rule 3), so they are
checked as "at least these".
"""
from __future__ import annotations

import dataclasses
import pytest
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "palimpsests" / "audit"


# ── rule 1: one place to import from ───────────────────────────────────────

READER_ALL = {
    "AuditReader", "Verification", "Diagnosis", "ManifestReading", "ContainerCheck",
    "VerifyResult",
    "Advisory", "AdvisoryItem",
    "DecodedRecord", "Header", "decode_record",
    "SpanView", "BootView", "OriginView", "OriginState", "ContinuationView",
    "decode_continuation",
    "boot_statistics", "BootStats", "AnchorCadence", "SpanStats", "step_catalog", "TimeStep",
    "NO_SPAN", "NO_PREDECESSOR",
    "FORMAT_VERSION",
    "RT_GENESIS", "RT_BOOT", "RT_SPAN_START", "RT_SPAN_END", "RT_EVENT", "RT_MERKLE",
    "RT_AGGREGATE", "RT_SHED", "RT_SAFETY", "RT_ANCHOR", "RT_WITNESS", "RT_KEY_SHRED",
    "TIER_A", "TIER_B", "TIER_BPLUS",
    "TIME_UNKNOWN", "TIME_UNSYNCED", "TIME_HW_RTC", "TIME_NTP_SYNCED",
    "KIND_MODEL_LOAD", "KIND_MODEL_UNLOAD", "KIND_KV_SAVE", "KIND_KV_RESTORE",
    "KIND_PREFIX_COPY", "KIND_PREFIX_WARM", "KIND_RECOVERY_TRUNCATED_TAIL",
    "KIND_TOOL_CALL", "KIND_TOOL_RESULT", "KIND_TOOLS_OFFERED_NO_CALL",
    "KIND_SEGMENT_CONTINUATION", "KIND_GUARD_PREFIX_RELEASE", "KIND_GUARD_STATE_REJECT",
    "KIND_INCIDENT_CANDIDATE", "KIND_OVERSIGHT_ACK", "KIND_GUARD_TOOL_LOOP_LIMIT",
    "OUTCOME_OK", "OUTCOME_ERROR", "OUTCOME_TIMEOUT", "OUTCOME_CANCELLED",
    "OUTCOME_UNOBSERVED",
    "SOURCE_PARSED_FROM_WIRE", "SOURCE_REPORTED_BY_CLIENT",
    "DISP_ACKNOWLEDGED", "DISP_DISMISSED", "DISP_ESCALATED",
}

#: The reading names of ``audit.anchors``. Its ``__all__`` also lists the
#: writer-side stores (``AnchorStore``, ``FileAnchorStore``), which are outside
#: the reading surface until the writer has its own contract (U27).
ANCHORS_READING = {
    "AnchorSource", "AnchorReading", "AnchorSourceError", "AnchorAttempt",
    "ManualAnchor", "FileAnchor", "ChainedAnchorSource",
}


def test_reader_all_is_exactly_the_surface():
    import palimpsests.audit.reader as r

    assert set(r.__all__) == READER_ALL
    assert len(r.__all__) == len(READER_ALL)  # no duplicates
    assert [n for n in r.__all__ if not hasattr(r, n)] == []


def test_anchors_carry_the_reading_names():
    import palimpsests.audit.anchors as a
    import palimpsests.audit.anchors_pkcs11 as p

    assert ANCHORS_READING <= set(a.__all__)
    assert {"Pkcs11Anchor", "Pkcs11Unavailable", "DEFAULT_OBJECT_LABEL"} <= set(p.__all__)


def test_re_exports_are_the_same_objects_on_both_paths():
    import palimpsests.audit.bootstats as b
    import palimpsests.audit.pala.codec as c
    import palimpsests.audit.pala.incremental as inc
    import palimpsests.audit.pala.verify as v
    import palimpsests.audit.profiles.inference as inf
    import palimpsests.audit.reader as r
    import palimpsests.audit.timehealth as t

    assert r.VerifyResult is v.VerifyResult
    assert r.Header is c.Header
    assert r.Advisory is inc.Advisory and r.AdvisoryItem is inc.AdvisoryItem
    for name in ("boot_statistics", "BootStats", "AnchorCadence", "SpanStats"):
        assert getattr(r, name) is getattr(b, name), name
    for name in ("step_catalog", "TimeStep"):
        assert getattr(r, name) is getattr(t, name), name
    for name in r.__all__:
        if name.startswith(("KIND_", "OUTCOME_", "SOURCE_", "DISP_")):
            assert getattr(r, name) == getattr(inf, name), name
        if name.startswith(("RT_", "TIER_", "TIME_")) or name == "FORMAT_VERSION":
            assert getattr(r, name) == getattr(c, name), name
    assert r.NO_SPAN == c.ZERO16 == b"\x00" * 16
    assert r.NO_PREDECESSOR == c.ZERO32 == b"\x00" * 32


def test_the_writer_still_exports_every_profile_name():
    """The table moved to audit.profiles.inference; the writer re-exports it,
    so an existing ``from palimpsests.audit.pala_writer import KIND_…`` works."""
    import palimpsests.audit.pala_writer as w
    import palimpsests.audit.profiles.inference as inf

    for name in inf.__all__:
        assert getattr(w, name) is getattr(inf, name), name


@pytest.mark.parametrize(
    "first",
    ["palimpsests.audit.reader", "palimpsests.audit.bootstats", "palimpsests.audit.timehealth"],
)
def test_no_import_order_is_circular(first):
    """bootstats and timehealth import the reader, and the reader re-exports
    them lazily — each may be imported first, in a fresh interpreter."""
    code = (
        f"import {first}\n"
        "from palimpsests.audit.reader import *\n"
        "import palimpsests.audit.reader as r\n"
        "assert r.boot_statistics.__module__ == 'palimpsests.audit.bootstats'\n"
        "assert r.step_catalog.__module__ == 'palimpsests.audit.timehealth'\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_an_unknown_reader_attribute_still_raises():
    import palimpsests.audit.reader as r

    with pytest.raises(AttributeError):
        r.no_such_name  # noqa: B018


# ── rule 5: numbers are frozen ─────────────────────────────────────────────

CORE_NUMBERS = {
    "FORMAT_VERSION": 1,
    "RT_GENESIS": 0x0001, "RT_BOOT": 0x0002, "RT_SPAN_START": 0x0010, "RT_SPAN_END": 0x0011,
    "RT_EVENT": 0x0012, "RT_MERKLE": 0x0020, "RT_AGGREGATE": 0x0021, "RT_SHED": 0x0030,
    "RT_SAFETY": 0x0040, "RT_ANCHOR": 0x0050, "RT_WITNESS": 0x0051, "RT_KEY_SHRED": 0x0060,
    "TIER_A": 0, "TIER_B": 1, "TIER_BPLUS": 2,
    "TIME_UNKNOWN": 0, "TIME_UNSYNCED": 1, "TIME_HW_RTC": 2, "TIME_NTP_SYNCED": 3,
}

PROFILE_NUMBERS = {
    "ROLE_OLLAMA": "engine.ollama", "ROLE_LLAMACPP": "engine.llamacpp",
    "ROLE_NATIVE": "engine.native", "ROLE_SCHEDULER": "scheduler", "ROLE_KV_STORE": "kv_store",
    "ROLE_CONTEXT_MEMORY": "context_memory",
    "EVT_KIND": 0x0001, "EVT_BLOB_DIGEST": 0x0002, "EVT_TOKEN_COUNT": 0x0003,
    "EVT_DETAIL": 0x0004, "EVT_CATEGORY": 0x0005, "EVT_SEVERITY": 0x0006,
    "EVT_RECOVERABLE": 0x0007, "EVT_REF_SEQ": 0x0008, "EVT_REF_HASH": 0x0009,
    "EVT_OPERATOR_ID": 0x000A, "EVT_DISPOSITION": 0x000B, "EVT_TOOL_NAME": 0x000C,
    "EVT_PAYLOAD_DIGEST": 0x000D, "EVT_OUTCOME": 0x000E, "EVT_TOOLS_OFFERED": 0x000F,
    "EVT_TOOLS_DIGEST": 0x0010, "EVT_SOURCE": 0x0011,
    "SEG_PREDECESSOR_HEAD": 0x0012, "SEG_INDEX": 0x0013, "SEG_RETENTION_S": 0x0014,
    "SEG_PRIOR_ROOT": 0x0015,
    "KIND_MODEL_LOAD": 1, "KIND_MODEL_UNLOAD": 2, "KIND_KV_SAVE": 3, "KIND_KV_RESTORE": 4,
    "KIND_PREFIX_COPY": 5, "KIND_PREFIX_WARM": 6, "KIND_RECOVERY_TRUNCATED_TAIL": 7,
    "KIND_TOOL_CALL": 8, "KIND_TOOL_RESULT": 9, "KIND_TOOLS_OFFERED_NO_CALL": 10,
    "KIND_SEGMENT_CONTINUATION": 11,
    "KIND_GUARD_PREFIX_RELEASE": 100, "KIND_GUARD_STATE_REJECT": 101,
    "KIND_INCIDENT_CANDIDATE": 102, "KIND_OVERSIGHT_ACK": 103, "KIND_GUARD_TOOL_LOOP_LIMIT": 104,
    "CAT_GUARD_ESCALATION": 1, "CAT_SELF_CHECK_FAILED": 2, "CAT_ANCHOR_ANOMALY": 3,
    "DISP_ACKNOWLEDGED": 0, "DISP_DISMISSED": 1, "DISP_ESCALATED": 2,
    "OUTCOME_OK": 0, "OUTCOME_ERROR": 1, "OUTCOME_TIMEOUT": 2, "OUTCOME_CANCELLED": 3,
    "OUTCOME_UNOBSERVED": 4,
    "SOURCE_PARSED_FROM_WIRE": 0, "SOURCE_REPORTED_BY_CLIENT": 1,
    "SHRED_REASON": 0x0001, "SHRED_TARGET_SEQS": 0x0002, "SHRED_DETAIL": 0x0003,
    "REASON_UNSPECIFIED": 0, "REASON_LEGAL_ERASURE": 1, "REASON_RETENTION_EXPIRY": 2,
    "REASON_POLICY": 3,
    "AGG_WINDOW_NS": 0x0001, "AGG_SAMPLE_COUNT": 0x0002, "AGG_REQUESTS": 0x0003,
    "AGG_TOKENS_PREFILL": 0x0004, "AGG_TOKENS_DECODE": 0x0005, "AGG_PREFILL_SAVED": 0x0006,
    "AGG_SESSIONS_OPEN": 0x0007,
}


def test_core_numbers_never_change():
    import palimpsests.audit.pala.codec as c

    assert {n: getattr(c, n) for n in CORE_NUMBERS} == CORE_NUMBERS


def test_profile_numbers_never_change():
    """A revision only adds: a new allocation fails here until it is listed."""
    import palimpsests.audit.profiles.inference as inf

    assert {n: getattr(inf, n) for n in inf.__all__} == PROFILE_NUMBERS


# ── rule 3: fields may grow, never disappear ───────────────────────────────

FIELDS = {
    "Verification": ["chain", "anchor", "anchor_attempts", "complete_to_anchor",
                     "anchor_lag", "diagnosis", "advisory", "manifest"],
    "Diagnosis": ["pattern", "at_seq", "expected", "narrative", "code"],
    "ManifestReading": ["path", "status", "sha256", "detail"],
    "ContainerCheck": ["well_formed", "malformed", "bytes_parsed", "bytes_total",
                       "body_digest_mismatches"],
    "DecodedRecord": ["seq", "index", "record_type", "type_name", "header", "body_tlvs",
                      "kind", "kind_name", "record_hash", "detail", "operator_id",
                      "disposition", "disposition_name", "source", "source_name",
                      "outcome", "outcome_name"],
    "SpanView": ["span_id", "parent_span_id", "start_seq", "end_seq", "record_seqs"],
    "BootView": ["boot_id", "first_seq", "last_seq", "record_count", "time_trust_values",
                 "recovery_seq"],
    "OriginView": ["role", "model_digest", "config_digest", "since_seq", "detail"],
    "OriginState": ["origin", "unloaded"],
    "ContinuationView": ["seq", "segment_index", "predecessor_head", "retention_s",
                         "prior_root", "detail"],
    "VerifyResult": ["chain_ok", "count", "head", "breaks", "gaps", "violations",
                     "uninterpretable", "complete_to_anchor", "anchor_lag", "anchor_reason",
                     "violation_codes"],
    "AdvisoryItem": ["code", "at_seq", "boot_id", "detail"],
    "Advisory": ["items"],
    "Header": ["record_type", "seq", "boot_id", "prev_hash", "assurance_tier", "time_trust",
               "span_id", "parent_span_id", "monotonic_ns", "wall_clock_ns", "key_id",
               "body_len", "body_digest", "tlvs"],
}


@pytest.mark.parametrize("name", sorted(FIELDS))
def test_result_type_fields_are_kept(name):
    import palimpsests.audit.reader as r

    cls = getattr(r, name)
    assert dataclasses.is_dataclass(cls), name
    have = [f.name for f in dataclasses.fields(cls)]
    assert set(FIELDS[name]) <= set(have), sorted(set(FIELDS[name]) - set(have))


READER_METHODS = {
    "open", "from_bytes", "close", "verify", "container_check", "head", "records",
    "safety_records",
    "record_count", "record_at", "record_by_seq", "header_at",
    "boots", "spans", "structure",
    "origin_at", "unloaded_at", "origin_state_at",
    "acknowledged_candidates", "shredded_targets",
}


def test_audit_reader_keeps_its_methods():
    from palimpsests.audit.reader import AuditReader

    assert READER_METHODS <= {n for n in dir(AuditReader) if not n.startswith("_")}


# ── rules 4 and 6: None semantics and open vocabularies ────────────────────


def _table_row(doc: str, label: str) -> set[str]:
    """The backticked members in the Vocabularies table row starting with ``label``."""
    row = next(line for line in doc.splitlines() if line.startswith(f"| {label}"))
    return set(re.findall(r"`([^`]+)`", row.split("|")[2]))


def _emitted(pattern: str) -> set[str]:
    found: set[str] = set()
    for path in SRC.rglob("*.py"):
        found |= set(re.findall(pattern, path.read_text(encoding="utf-8")))
    return found


@pytest.fixture(scope="module")
def surface_doc() -> str:
    return (REPO / "docs" / "INTEGRATION-SURFACE.md").read_text(encoding="utf-8")


def test_diagnosis_patterns_in_code_are_the_documented_ones(surface_doc):
    emitted = _emitted(r'Diagnosis\(\s*"([a-z_]+)"')
    assert emitted == _table_row(surface_doc, "Diagnosis `pattern`")


def test_advisory_codes_in_code_are_the_documented_ones(surface_doc):
    emitted = _emitted(r'AdvisoryItem\(\s*"([a-z_]+)"') | _emitted(r'code="([a-z_]+)"')
    assert emitted == _table_row(surface_doc, "Advisory `code`")


def test_violation_codes_are_the_documented_ones(surface_doc):
    from palimpsests.audit.pala.incremental import VIOLATION_CODES

    assert set(VIOLATION_CODES) == _table_row(surface_doc, "Violation `code`")


def test_names_and_statuses_are_the_documented_ones(surface_doc):
    import palimpsests.audit.reader as r

    assert set(r._OUTCOME_NAMES.values()) == _table_row(surface_doc, "`outcome_name`")
    assert set(r._SOURCE_NAMES.values()) == _table_row(surface_doc, "`source_name`")
    statuses = _emitted(r'"(matches|contradicts|declared_only)"')
    assert statuses == _table_row(surface_doc, "`ManifestReading.status`")


def test_kind_and_kind_name_tell_their_two_nones_apart(tmp_path):
    """kind is None: the record carries no kind. kind set, kind_name None:
    a kind this build does not know."""
    import struct
    from palimpsests.audit.pala.codec import RT_EVENT, encode_tlvs
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.profiles.inference import EVT_KIND
    from palimpsests.audit.reader import RT_BOOT, AuditReader

    p = tmp_path / "k.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w._emit(RT_EVENT, tlvs=w._origin("engine.native"),
                body=encode_tlvs([(EVT_KIND, struct.pack("<H", 4242))]))
    with AuditReader.open(p) as reader:
        recs = list(reader.records())
    boot = next(d for d in recs if d.record_type == RT_BOOT)
    unknown = recs[-1]
    assert boot.kind is None and boot.kind_name is None
    assert unknown.kind == 4242 and unknown.kind_name is None


# ── the other channels stay where INTEGRATION-SURFACE.md says ──────────────

CHANNELS = {
    "palimpsests.audit.report": ["build_report", "derive_verdict"],
    "palimpsests.audit.pala.proofs": ["inclusion_proof", "range_proofs", "chain_root",
                                      "consistency_proof", "ConsistencyProof"],
    "palimpsests.audit.pala.bundle": ["assemble_bundle"],
    "palimpsests.audit.timehealth": ["step_catalog", "drift_series"],
    "palimpsests.audit.bootstats": ["boot_statistics"],
    "palimpsests.audit.pala.vectors": ["load"],
    "palimpsests.audit.pala.selftest": ["run_selftest"],
}


@pytest.mark.parametrize("module", sorted(CHANNELS))
def test_channel_symbols_resolve(module):
    import importlib

    mod = importlib.import_module(module)
    assert [n for n in CHANNELS[module] if not hasattr(mod, n)] == []
