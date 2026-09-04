# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the inference-profile companion vectors (r2–r5 semantics).

Deterministic: fixed key, seq-derived nonces, fixed ids and clocks —
real crypto, fake entropy. Never do this outside a test vector.

These vectors are the byte-exact examples for the r2 additions —
INCIDENT_CANDIDATE (SAFETY kind 102), OVERSIGHT_ACK (SAFETY kind 103)
and the KEY_SHRED erasure body (profile §8) — plus one encrypted
deployment-content EVENT so the shred has a real target — and, from r3,
the tool-loop records: TOOL_CALL (kind 8), TOOL_RESULT (kind 9) with its
hash-bound reference, and GUARD_TOOL_LOOP_LIMIT (SAFETY kind 104) —
and, from r4, TOOLS_OFFERED_NO_CALL (kind 10): the offer/absence
boundary record — and, from r5, a client-reported TOOL_CALL/TOOL_RESULT
pair carrying EVT_SOURCE = 1 (absent means parsed-from-wire).
Prior-revision records are appended-to, never edited:
their bytes are identical to the revision that introduced them. They are a
**companion** artifact: `../test-vectors.json` is frozen with the core
and is not touched by this script or any future one; a byte of it
changing would invalidate four recorded verification runs. This file
carries its own regeneration gate in CI instead.

The envelope properties demonstrated here are the core's; what these
vectors add is the profile-body layer: a reader that resolves the r2
tags and kinds can check its decoding against `semantics` below.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import palaudit_ref as R  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

OUT = Path(__file__).resolve().parent / "inference-vectors.json"

# ─── fixed inputs (deterministic) ───────────────────────────────────────

BOOT_ID = bytes.fromhex("b0071d000000000000000000000000a2")
SPAN_S1 = bytes.fromhex("31313131313131313131313131313131")
OPERATOR = bytes.fromhex("0e5a70120e5a70120e5a70120e5a7012")  # pseudonymous
KEY = bytes.fromhex("00" * 31 + "09")  # 32-byte AES key, addressed as key_id = 9
KEY_ID = 9
WALL0 = 1_784_000_100_000_000_000  # ns since epoch, NTP-trusted region
MONO0 = 9_000_000_000

# r2 profile allocations (profile §3 / §4 / §8)
EVT_KIND = 0x0001
EVT_DETAIL = 0x0004
EVT_CATEGORY = 0x0005
EVT_SEVERITY = 0x0006
EVT_RECOVERABLE = 0x0007
EVT_REF_SEQ = 0x0008
EVT_REF_HASH = 0x0009
EVT_OPERATOR_ID = 0x000A
EVT_DISPOSITION = 0x000B
KIND_GUARD_PREFIX_RELEASE = 100
KIND_INCIDENT_CANDIDATE = 102
KIND_OVERSIGHT_ACK = 103
CAT_GUARD_ESCALATION = 1
DISP_ACKNOWLEDGED = 0
SHRED_REASON = 0x0001
SHRED_TARGET_SEQS = 0x0002
SHRED_DETAIL = 0x0003
REASON_LEGAL_ERASURE = 1

# r3 profile allocations (profile §3.1 / §4)
EVT_TOKEN_COUNT = 0x0003
EVT_TOOL_NAME = 0x000C
EVT_PAYLOAD_DIGEST = 0x000D
EVT_OUTCOME = 0x000E
KIND_TOOL_CALL = 8
KIND_TOOL_RESULT = 9
KIND_GUARD_TOOL_LOOP_LIMIT = 104
OUTCOME_OK = 0

# r4 profile allocations (profile §3.1, kind 10)
EVT_TOOLS_OFFERED = 0x000F
EVT_TOOLS_DIGEST = 0x0010
KIND_TOOLS_OFFERED_NO_CALL = 10

# r5 profile allocations (profile §3.1, source marking on kinds 8/9)
EVT_SOURCE = 0x0011
SOURCE_PARSED_FROM_WIRE = 0  # the default — the tag is absent
SOURCE_REPORTED_BY_CLIENT = 1


def h(b: bytes) -> str:
    return b.hex()


def u16(v: int) -> bytes:
    return struct.pack("<H", v)


def u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


records: list[dict] = []
chain: list[bytes] = []
bodies: dict[int, bytes] = {}


def emit(label: str, hdr: R.Header, note: str, body: bytes | None = None) -> bytes:
    hb = hdr.encode()
    chain.append(hb)
    entry = {
        "label": label,
        "note": note,
        "seq": hdr.seq,
        "record_type": f"0x{hdr.record_type:04x}",
        "header_len": len(hb),
        "header_hex": h(hb),
        "record_hash": h(R.record_hash(hb)),
    }
    if body is not None:
        entry["body_len"] = len(body)
        entry["body_hex"] = h(body)
        bodies[hdr.seq] = body
    records.append(entry)
    return R.record_hash(hb)


def header(
    *,
    record_type: int,
    seq: int,
    prev: bytes,
    body: bytes = b"",
    tlvs: list[tuple[int, bytes]] | None = None,
    span_id: bytes = R.ZERO16,
    key_id: int = 0,
    time_trust: int = R.TIME_NTP_SYNCED,
    wall: int | None = None,
) -> R.Header:
    return R.Header(
        record_type=record_type,
        seq=seq,
        boot_id=BOOT_ID,
        prev_hash=prev,
        assurance_tier=R.TIER_A,
        time_trust=time_trust,
        span_id=span_id,
        parent_span_id=R.ZERO16,
        monotonic_ns=MONO0 + seq * 1_000_000,
        wall_clock_ns=(WALL0 + seq * 1_000_000) if wall is None else wall,
        key_id=key_id,
        body_len=len(body),
        body_digest=R.body_digest_of(body) if body else R.ZERO32,
        tlvs=tlvs or [],
    )


# 0 — GENESIS (time UNKNOWN, wall MUST be 0 — core §5)
prev = emit(
    "genesis",
    header(record_type=R.RT_GENESIS, seq=0, prev=R.ZERO32,
           time_trust=R.TIME_UNKNOWN, wall=0),
    "Chain origin. Envelope rules are the core's; nothing r2 changes them.",
)

# 1 — BOOT
prev = emit(
    "boot",
    header(record_type=R.RT_BOOT, seq=1, prev=prev,
           time_trust=R.TIME_UNSYNCED),
    "Boot; prev_hash is the cross-boot link (core §4.2).",
)

# 2 — SAFETY kind 100: the source guard refusal the candidate will cite
guard_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_GUARD_PREFIX_RELEASE)),
    R.tlv(EVT_DETAIL, b"holder 5: 2 live consumer(s)"),
])
guard_hash = emit(
    "guard_refusal",
    header(record_type=R.RT_SAFETY, seq=2, prev=prev, body=guard_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"scheduler")], span_id=SPAN_S1),
    "A guard refusal (kind 100, r1) — the source record the incident "
    "candidate references.",
    body=guard_body,
)
prev = guard_hash

# 3 — EVENT with an encrypted deployment-content body (key_id = 9):
# the record whose body the erasure at seq 6 will make unreadable.
plaintext = b"deployment-content example: session checkpoint note"
nonce3 = R.nonce_for(3)
ct3 = AESGCM(KEY).encrypt(nonce3, plaintext, R.aad_for(3, BOOT_ID, R.RT_EVENT))
enc_body = nonce3 + ct3
prev = emit(
    "encrypted_content_event",
    header(record_type=R.RT_EVENT, seq=3, prev=prev, body=enc_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1, key_id=KEY_ID),
    "A deployment that logs content MUST encrypt it (profile header note); "
    "this is such a body, under key_id 9 — the shred target.",
    body=enc_body,
)

# 4 — SAFETY kind 102: INCIDENT_CANDIDATE (r2)
candidate_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_INCIDENT_CANDIDATE)),
    R.tlv(EVT_CATEGORY, u16(CAT_GUARD_ESCALATION)),
    R.tlv(EVT_SEVERITY, u16(2)),
    R.tlv(EVT_RECOVERABLE, b"\x01"),
    R.tlv(EVT_REF_SEQ, u64(2)),
    R.tlv(EVT_REF_HASH, guard_hash),
    R.tlv(EVT_DETAIL, b"guard refusals exceeded threshold in window"),
])
candidate_hash = emit(
    "incident_candidate",
    header(record_type=R.RT_SAFETY, seq=4, prev=prev, body=candidate_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")]),
    "INCIDENT_CANDIDATE (kind 102): a documented trigger fired — an "
    "observation for a human, never an incident determination. Never shed.",
    body=candidate_body,
)
prev = candidate_hash

# 5 — SAFETY kind 103: OVERSIGHT_ACK (r2), binding to the candidate by
# seq AND record_hash
ack_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_OVERSIGHT_ACK)),
    R.tlv(EVT_REF_SEQ, u64(4)),
    R.tlv(EVT_REF_HASH, candidate_hash),
    R.tlv(EVT_DISPOSITION, u16(DISP_ACKNOWLEDGED)),
    R.tlv(EVT_OPERATOR_ID, OPERATOR),
])
prev = emit(
    "oversight_ack",
    header(record_type=R.RT_SAFETY, seq=5, prev=prev, body=ack_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")]),
    "OVERSIGHT_ACK (kind 103): disposition 0 (acknowledged) by a "
    "pseudonymous operator; the hash binds the reference.",
    body=ack_body,
)

# 6 — KEY_SHRED with the r2 erasure body (profile §8), cleartext by MUST
shred_body = R.encode_tlvs([
    R.tlv(SHRED_REASON, u16(REASON_LEGAL_ERASURE)),
    R.tlv(SHRED_TARGET_SEQS, u64(3)),
    R.tlv(SHRED_DETAIL, b"erasure request E-17"),
])
prev = emit(
    "key_shred_documented",
    header(record_type=R.RT_KEY_SHRED, seq=6, prev=prev, body=shred_body,
           tlvs=[R.tlv(R.TLV_SHRED_KEY_ID, struct.pack("<I", KEY_ID))]),
    "KEY_SHRED with the §8 erasure body: reason, targets, ticket — one "
    "record, one operation. The seq-3 body is noise from here; the chain "
    "is untouched (core §4.4).",
    body=shred_body,
)

# 7 — ANCHOR noting the head as of seq 6
anchored = prev
prev = emit(
    "anchor",
    header(record_type=R.RT_ANCHOR, seq=7, prev=prev,
           tlvs=[R.tlv(R.TLV_ANCHOR_HEAD, anchored)]),
    "Anchor; the completeness anchor below is the store's current head "
    "(the tip), per core §7.2.",
)

# ─── r3: tool-loop records (profile §3.1 / §4, kind 104) ────────────────

# 8 — EVENT kind 8: TOOL_CALL. Arguments never enter the log: the body
# carries the registered tool name and a digest of the canonical
# argument encoding (open issue 4 fixes the canonicalization; the
# vector just needs deterministic bytes).
tool_args = b'{"query":"pala-1 verification"}'
call_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_TOOL_CALL)),
    R.tlv(EVT_TOOL_NAME, b"web.search"),
    R.tlv(EVT_PAYLOAD_DIGEST, hashlib.sha256(tool_args).digest()),
])
call_hash = emit(
    "tool_call",
    header(record_type=R.RT_EVENT, seq=8, prev=prev, body=call_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "TOOL_CALL (kind 8, r3): the loop dispatched an invocation — tool "
    "name plus argument digest, never the arguments.",
    body=call_body,
)
prev = call_hash

# 9 — EVENT kind 9: TOOL_RESULT, hash-bound to its call, outcome ok.
tool_result = b'{"hits":3}'
result_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_TOOL_RESULT)),
    R.tlv(EVT_REF_SEQ, u64(8)),
    R.tlv(EVT_REF_HASH, call_hash),
    R.tlv(EVT_OUTCOME, u16(OUTCOME_OK)),
    R.tlv(EVT_PAYLOAD_DIGEST, hashlib.sha256(tool_result).digest()),
])
prev = emit(
    "tool_result",
    header(record_type=R.RT_EVENT, seq=9, prev=prev, body=result_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "TOOL_RESULT (kind 9, r3): outcome 0 (ok); the ref pair binds it to "
    "seq 8 past any seq ambiguity — the OVERSIGHT_ACK rule reused. "
    "Latency is the monotonic_ns delta between the two records.",
    body=result_body,
)

# 10 — SAFETY kind 104: GUARD_TOOL_LOOP_LIMIT — the cap refused further
# dispatches; iteration count in EVT_TOKEN_COUNT, ref to the last call.
limit_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_GUARD_TOOL_LOOP_LIMIT)),
    R.tlv(EVT_TOKEN_COUNT, u32(8)),
    R.tlv(EVT_REF_SEQ, u64(8)),
    R.tlv(EVT_REF_HASH, call_hash),
])
prev = emit(
    "guard_tool_loop_limit",
    header(record_type=R.RT_SAFETY, seq=10, prev=prev, body=limit_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "GUARD_TOOL_LOOP_LIMIT (kind 104, r3): the loop cap fired after 8 "
    "iterations — a guard refusal on the record, never shed; feeds the "
    "existing category-1 escalation counter.",
    body=limit_body,
)

# 11 — ANCHOR noting the new head
anchored_r3 = prev
prev = emit(
    "anchor_r3",
    header(record_type=R.RT_ANCHOR, seq=11, prev=prev,
           tlvs=[R.tlv(R.TLV_ANCHOR_HEAD, anchored_r3)]),
    "Anchor over the r3-extended chain.",
)

# ─── r4: the offer/absence boundary record (profile §3.1, kind 10) ──────

# 12 — EVENT kind 10: TOOLS_OFFERED_NO_CALL. The completion a text-mode
# loop leaves indistinguishable from no tool use at all: structured
# tools offered, no structured call produced, no structured tool traffic
# in the request either. The digest is the §6.2 discipline applied to
# names — the *sorted* name list as a compact JSON array, UTF-8 — so it
# is order-independent: the offer is a set.
offered_names = ["web.search", "calc.multiply"]
names_canonical = json.dumps(
    sorted(offered_names), sort_keys=True, separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
offered_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_TOOLS_OFFERED_NO_CALL)),
    R.tlv(EVT_TOOLS_OFFERED, u16(len(offered_names))),
    R.tlv(EVT_TOOLS_DIGEST, hashlib.sha256(names_canonical).digest()),
])
prev = emit(
    "tools_offered_no_call",
    header(record_type=R.RT_EVENT, seq=12, prev=prev, body=offered_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "TOOLS_OFFERED_NO_CALL (kind 10, r4): the visibility boundary made "
    "visible — an observation of offer and absence, never an inference "
    "about what the reply text did. Count in EVT_TOOLS_OFFERED; the "
    "order-independent canonical name digest in EVT_TOOLS_DIGEST.",
    body=offered_body,
)

# 13 — ANCHOR noting the new head
anchored_r4 = prev
prev = emit(
    "anchor_r4",
    header(record_type=R.RT_ANCHOR, seq=13, prev=prev,
           tlvs=[R.tlv(R.TLV_ANCHOR_HEAD, anchored_r4)]),
    "Anchor over the r4-extended chain.",
)

# ─── r5: the client-reported pair (profile §3.1, EVT_SOURCE) ────────────

# 14 — EVENT kind 8: TOOL_CALL *reported by the client*. Same body
# shape as seq 8, plus EVT_SOURCE = 1. The tag is present only for the
# non-default value: seq 8/9 above carry no EVT_SOURCE and mean
# parsed-from-wire — every r3/r4 record's bytes and meaning are
# unchanged. Tag order follows the writer: kind, name, digest, source.
reported_args = b'{"path":"README.md"}'
reported_call_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_TOOL_CALL)),
    R.tlv(EVT_TOOL_NAME, b"fs.read"),
    R.tlv(EVT_PAYLOAD_DIGEST, hashlib.sha256(reported_args).digest()),
    R.tlv(EVT_SOURCE, u16(SOURCE_REPORTED_BY_CLIENT)),
])
reported_call_hash = emit(
    "tool_call_reported",
    header(record_type=R.RT_EVENT, seq=14, prev=prev, body=reported_call_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "TOOL_CALL (kind 8) with EVT_SOURCE = 1 (r5): the client ran its "
    "loop in text and reported the call through the ingestion surface. "
    "The chain proves the report and its digest, never that the tool ran "
    "— an evidence-quality mark, not a trust upgrade.",
    body=reported_call_body,
)
prev = reported_call_hash

# 15 — EVENT kind 9: TOOL_RESULT reported by the client, bound to seq 14
# by the same seq+hash rule as wire-parsed pairs (the reader's
# referential advisory does not care about source).
reported_result = b'# Palimpsests'
reported_result_body = R.encode_tlvs([
    R.tlv(EVT_KIND, u16(KIND_TOOL_RESULT)),
    R.tlv(EVT_REF_SEQ, u64(14)),
    R.tlv(EVT_REF_HASH, reported_call_hash),
    R.tlv(EVT_OUTCOME, u16(OUTCOME_OK)),
    R.tlv(EVT_PAYLOAD_DIGEST, hashlib.sha256(reported_result).digest()),
    R.tlv(EVT_SOURCE, u16(SOURCE_REPORTED_BY_CLIENT)),
])
prev = emit(
    "tool_result_reported",
    header(record_type=R.RT_EVENT, seq=15, prev=prev, body=reported_result_body,
           tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"engine.native")],
           span_id=SPAN_S1),
    "TOOL_RESULT (kind 9) with EVT_SOURCE = 1 (r5): binds to seq 14 by "
    "seq and hash exactly as a wire-parsed pair does; the source mark "
    "travels with each record of the pair, not with the pair.",
    body=reported_result_body,
)

# 16 — ANCHOR noting the new head
anchored_r5 = prev
prev = emit(
    "anchor_r5",
    header(record_type=R.RT_ANCHOR, seq=16, prev=prev,
           tlvs=[R.tlv(R.TLV_ANCHOR_HEAD, anchored_r5)]),
    "Anchor over the extended chain; anchor_head below tracks this tip.",
)

chain_head = prev

# ─── self-verify before writing anything ────────────────────────────────

res = R.verify_chain(chain)
assert res.chain_ok, f"generated chain does not verify: {res}"
assert res.count == 17
assert not res.breaks and not res.gaps and not res.violations
# the encrypted body round-trips under the spec'd nonce/AAD derivation
back = AESGCM(KEY).decrypt(R.nonce_for(3), bodies[3][12:],
                           R.aad_for(3, BOOT_ID, R.RT_EVENT))
assert back == plaintext

out = {
    "$comment": (
        "Inference-profile companion vectors (r2-r5). Deterministic; real "
        "crypto, fake entropy — never derive keys or ids like this outside "
        "a test vector. ../test-vectors.json is frozen with the core and "
        "is deliberately untouched by these."
    ),
    "profile": "inference",
    "profile_revision": "r5",
    "generator": "gen_inference_vectors.py",
    "boot_id": h(BOOT_ID),
    "encryption": {
        "key_id": KEY_ID,
        "key_hex": h(KEY),
        "nonce_rule": "4 zero bytes || seq (u64 LE), per core §4.4",
        "seq3_plaintext": plaintext.decode(),
    },
    "records": records,
    "chain_head": h(chain_head),
    "anchor_head": h(chain_head),
    "semantics": {
        "$comment": (
            "Decoded r2/r3 body expectations, so a profile-aware reader can "
            "check its tag/kind resolution — the envelope answers above "
            "are checkable with any core verifier."
        ),
        "4": {
            "kind": 102, "kind_name": "INCIDENT_CANDIDATE",
            "category": 1, "severity": 2, "recoverable": 1,
            "ref_seq": 2, "ref_hash": h(guard_hash),
            "detail": "guard refusals exceeded threshold in window",
        },
        "5": {
            "kind": 103, "kind_name": "OVERSIGHT_ACK",
            "ref_seq": 4, "ref_hash": h(candidate_hash),
            "disposition": 0, "operator_id": h(OPERATOR),
        },
        "6": {
            "record_type": "KEY_SHRED", "reason": 1,
            "target_seqs": [3], "detail": "erasure request E-17",
        },
        "8": {
            "kind": 8, "kind_name": "TOOL_CALL",
            "tool_name": "web.search",
            "payload_digest": hashlib.sha256(tool_args).digest().hex(),
        },
        "9": {
            "kind": 9, "kind_name": "TOOL_RESULT",
            "ref_seq": 8, "ref_hash": h(call_hash), "outcome": 0,
            "payload_digest": hashlib.sha256(tool_result).digest().hex(),
        },
        "10": {
            "kind": 104, "kind_name": "GUARD_TOOL_LOOP_LIMIT",
            "iterations": 8, "ref_seq": 8, "ref_hash": h(call_hash),
        },
        "12": {
            "kind": 10, "kind_name": "TOOLS_OFFERED_NO_CALL",
            "tools_offered": len(offered_names),
            "tools_digest": hashlib.sha256(names_canonical).digest().hex(),
            "names_canonicalization": (
                "sorted names as a JSON array, compact separators, "
                "non-ASCII preserved, UTF-8, then SHA-256 — "
                "order-independent: the offer is a set"
            ),
        },
        "14": {
            "kind": 8, "kind_name": "TOOL_CALL",
            "tool_name": "fs.read",
            "payload_digest": hashlib.sha256(reported_args).digest().hex(),
            "source": 1, "source_name": "reported-by-client",
        },
        "15": {
            "kind": 9, "kind_name": "TOOL_RESULT",
            "ref_seq": 14, "ref_hash": h(reported_call_hash), "outcome": 0,
            "payload_digest": hashlib.sha256(reported_result).digest().hex(),
            "source": 1, "source_name": "reported-by-client",
        },
        "source_rule": (
            "EVT_SOURCE (0x0011) is present only for the non-default value 1 "
            "(reported-by-client); absent means 0 (parsed-from-wire). Seq 8/9 "
            "carry no EVT_SOURCE and are byte-identical to their r3 form."
        ),
    },
}

OUT.write_text(json.dumps(out, indent=2) + "\n")
print(f"wrote {OUT.name}: {len(records)} records, head {h(chain_head)[:16]}…")
