# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""The inference profile's allocations — one table for writer and reader.

Every number here is fixed by ``docs/specs/pala-1/profiles/inference.md``:
the ``ORIGIN_ROLE`` vocabulary, the ``EVENT`` body tags (``EVT_*``, and the
segment tags ``SEG_*`` of r6), the ``EVT_KIND`` values, the incident
categories, dispositions, tool outcomes and evidence sources, the
``KEY_SHRED`` erasure body (``SHRED_*``, its own namespace) and the
``AGGREGATE`` tags. They are the *profile's*, not the core's — the core's
record types, tiers and time-trust values stay in ``audit.pala.codec`` —
and a second profile gets its own module beside this one.

They used to live in the writer, so a reader-side consumer that needed a
kind number had to import the writer. Both now import this module; the
writer re-exports every name, so existing imports keep working.

A number never changes meaning (rule 5 of ``docs/CONSUMER-SURFACE.md``);
a revision only adds.
"""

# ─── profile §1: ORIGIN_ROLE vocabulary (component names, not a taxonomy) ────

ROLE_OLLAMA = "engine.ollama"
ROLE_LLAMACPP = "engine.llamacpp"
ROLE_NATIVE = "engine.native"
ROLE_SCHEDULER = "scheduler"
ROLE_KV_STORE = "kv_store"
ROLE_CONTEXT_MEMORY = "context_memory"

# ─── profile §3: EVENT body tags (own namespace) ────────────────────────────

EVT_KIND = 0x0001  # u16, MUST be present, first
EVT_BLOB_DIGEST = 0x0002  # 32 bytes — KV state blob digest
EVT_TOKEN_COUNT = 0x0003  # u32 — tokens involved (e.g. prefix length)
EVT_DETAIL = 0x0004  # UTF-8, <= 200 bytes, metadata only
EVT_CATEGORY = 0x0005  # u16 — incident category (profile r2)
EVT_SEVERITY = 0x0006  # u16 — 1 low, 2 medium, 3 high (r2)
EVT_RECOVERABLE = 0x0007  # u8 — 0 no, 1 yes (r2)
EVT_REF_SEQ = 0x0008  # u64 — seq of the referenced record (r2)
EVT_REF_HASH = 0x0009  # 32 bytes — record_hash of the referenced record (r2)
EVT_OPERATOR_ID = 0x000A  # 16 bytes — pseudonymous operator id (r2)
EVT_DISPOSITION = 0x000B  # u16 — 0 ack, 1 dismissed, 2 escalated (r2)
EVT_TOOL_NAME = 0x000C  # UTF-8 <= 64 bytes — registered tool identifier (r3)
EVT_PAYLOAD_DIGEST = 0x000D  # 32 bytes — digest of canonical args / result (r3)
EVT_OUTCOME = 0x000E  # u16 — 0 ok, 1 error, 2 timeout, 3 cancelled (r3)
EVT_TOOLS_OFFERED = 0x000F  # u16 — structured tools offered in the request (kind 10, r4)
EVT_TOOLS_DIGEST = 0x0010  # 32 bytes — canonical offered-name list digest (kind 10, r4)
EVT_SOURCE = 0x0011  # u16 — 0 parsed-from-wire (default, absent), 1 reported-by-client (r5)
SEG_PREDECESSOR_HEAD = 0x0012  # 32 bytes — head of the previous segment (kind 11, r6)
SEG_INDEX = 0x0013  # u32 — ordinal of the segment the record opens (kind 11, r6)
SEG_RETENTION_S = 0x0014  # u64 — retention floor at the cut, 0 = none declared (kind 11, r6)
SEG_PRIOR_ROOT = 0x0015  # 32 bytes — derived root of [0, seq), from record 0 (kind 11, r6)

# EVT_KIND values — operations (profile §3)
KIND_MODEL_LOAD = 1
KIND_MODEL_UNLOAD = 2
KIND_KV_SAVE = 3
KIND_KV_RESTORE = 4
KIND_PREFIX_COPY = 5
KIND_PREFIX_WARM = 6
KIND_RECOVERY_TRUNCATED_TAIL = 7
KIND_TOOL_CALL = 8  # r3 — the loop dispatched a tool invocation
KIND_TOOL_RESULT = 9  # r3 — the invocation returned / failed / was abandoned
KIND_TOOLS_OFFERED_NO_CALL = 10  # r4 — tools offered, no structured call produced
KIND_SEGMENT_CONTINUATION = 11  # r6 — first record of a segment opened after a cut
# EVT_KIND values — guard refusals (profile §4), from 100 upward
KIND_GUARD_PREFIX_RELEASE = 100
KIND_GUARD_STATE_REJECT = 101
KIND_INCIDENT_CANDIDATE = 102  # r2 — never-shed observation, not a determination
KIND_OVERSIGHT_ACK = 103  # r2 — the oversight loop's closing record
KIND_GUARD_TOOL_LOOP_LIMIT = 104  # r3 — the loop cap refused further dispatches

# r2 incident categories (profile §4, kind 102) — grows additively
CAT_GUARD_ESCALATION = 1
CAT_SELF_CHECK_FAILED = 2
CAT_ANCHOR_ANOMALY = 3

# r2 dispositions (profile §4, kind 103)
DISP_ACKNOWLEDGED = 0
DISP_DISMISSED = 1
DISP_ESCALATED = 2

# r3 — TOOL_RESULT outcomes (profile §3.1)
OUTCOME_OK = 0
OUTCOME_ERROR = 1
OUTCOME_TIMEOUT = 2
OUTCOME_CANCELLED = 3
OUTCOME_UNOBSERVED = 4  # r6 — returned; the vantage could not observe failure

# r5 — kind 8/9 evidence-source values (EVT_SOURCE; absent tag == 0)
SOURCE_PARSED_FROM_WIRE = 0
SOURCE_REPORTED_BY_CLIENT = 1


# r2 KEY_SHRED body — its OWN namespace (profile §8), not EVT tags
SHRED_REASON = 0x0001  # u16
SHRED_TARGET_SEQS = 0x0002  # concatenated u64 LE array
SHRED_DETAIL = 0x0003  # UTF-8, <= 200 bytes

# r2 shred reasons (profile §8)
REASON_UNSPECIFIED = 0
REASON_LEGAL_ERASURE = 1
REASON_RETENTION_EXPIRY = 2
REASON_POLICY = 3

# ─── profile §5: AGGREGATE body tags (0x0001–0x0002 are the core's) ─────────

AGG_WINDOW_NS = 0x0001  # u64 — core
AGG_SAMPLE_COUNT = 0x0002  # u32 — core
AGG_REQUESTS = 0x0003  # u32
AGG_TOKENS_PREFILL = 0x0004  # u64
AGG_TOKENS_DECODE = 0x0005  # u64
AGG_PREFILL_SAVED = 0x0006  # u64 — the measured value proposition, as a series
AGG_SESSIONS_OPEN = 0x0007  # u32

__all__ = [
    "ROLE_OLLAMA",
    "ROLE_LLAMACPP",
    "ROLE_NATIVE",
    "ROLE_SCHEDULER",
    "ROLE_KV_STORE",
    "ROLE_CONTEXT_MEMORY",
    "EVT_KIND",
    "EVT_BLOB_DIGEST",
    "EVT_TOKEN_COUNT",
    "EVT_DETAIL",
    "EVT_CATEGORY",
    "EVT_SEVERITY",
    "EVT_RECOVERABLE",
    "EVT_REF_SEQ",
    "EVT_REF_HASH",
    "EVT_OPERATOR_ID",
    "EVT_DISPOSITION",
    "EVT_TOOL_NAME",
    "EVT_PAYLOAD_DIGEST",
    "EVT_OUTCOME",
    "EVT_TOOLS_OFFERED",
    "EVT_TOOLS_DIGEST",
    "EVT_SOURCE",
    "SEG_PREDECESSOR_HEAD",
    "SEG_INDEX",
    "SEG_RETENTION_S",
    "SEG_PRIOR_ROOT",
    "KIND_MODEL_LOAD",
    "KIND_MODEL_UNLOAD",
    "KIND_KV_SAVE",
    "KIND_KV_RESTORE",
    "KIND_PREFIX_COPY",
    "KIND_PREFIX_WARM",
    "KIND_RECOVERY_TRUNCATED_TAIL",
    "KIND_TOOL_CALL",
    "KIND_TOOL_RESULT",
    "KIND_TOOLS_OFFERED_NO_CALL",
    "KIND_SEGMENT_CONTINUATION",
    "KIND_GUARD_PREFIX_RELEASE",
    "KIND_GUARD_STATE_REJECT",
    "KIND_INCIDENT_CANDIDATE",
    "KIND_OVERSIGHT_ACK",
    "KIND_GUARD_TOOL_LOOP_LIMIT",
    "CAT_GUARD_ESCALATION",
    "CAT_SELF_CHECK_FAILED",
    "CAT_ANCHOR_ANOMALY",
    "DISP_ACKNOWLEDGED",
    "DISP_DISMISSED",
    "DISP_ESCALATED",
    "OUTCOME_OK",
    "OUTCOME_ERROR",
    "OUTCOME_TIMEOUT",
    "OUTCOME_CANCELLED",
    "OUTCOME_UNOBSERVED",
    "SOURCE_PARSED_FROM_WIRE",
    "SOURCE_REPORTED_BY_CLIENT",
    "SHRED_REASON",
    "SHRED_TARGET_SEQS",
    "SHRED_DETAIL",
    "REASON_UNSPECIFIED",
    "REASON_LEGAL_ERASURE",
    "REASON_RETENTION_EXPIRY",
    "REASON_POLICY",
    "AGG_WINDOW_NS",
    "AGG_SAMPLE_COUNT",
    "AGG_REQUESTS",
    "AGG_TOKENS_PREFILL",
    "AGG_TOKENS_DECODE",
    "AGG_PREFILL_SAVED",
    "AGG_SESSIONS_OPEN",
]
