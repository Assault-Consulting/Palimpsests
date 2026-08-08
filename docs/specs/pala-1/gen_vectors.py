# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0

"""Generate the test vectors alongside PALA-1.md.

Everything is deterministic: fixed key, derived nonces, fixed IDs. Real crypto,
fake entropy. Never do this outside a test vector.

The chain is a plausible ten seconds of a robot: genesis, a boot with no clock,
a brain span, a c' write with an encrypted body, a second of frame digests, a
second of Tier 0 statistics, a divergence, a shed notice, span close, a local
anchor, an external witness, and a GDPR erasure.

Run:  python gen_vectors.py   ->  test-vectors.json
"""

from __future__ import annotations

import hashlib
import json
import palaudit_ref as R
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def h(b: bytes) -> str:
    return b.hex()


BOOT_ID = bytes.fromhex("b0071d00000000000000000000000001")
SPAN_BRAIN = bytes.fromhex("11111111111111111111111111111111")
SPAN_CALL = bytes.fromhex("22222222222222222222222222222222")
MODEL_D = hashlib.sha256(b"SmolVLM2-500M-Instruct@fake-weights").digest()
CONFIG_D = hashlib.sha256(b"tier1.yaml@fake-config").digest()
KEY = bytes.fromhex("00" * 31 + "2a")  # 32-byte AES key, addressed as key_id=7
KEY_ID = 7

records: list[dict] = []
chain: list[bytes] = []


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
    records.append(entry)
    return R.record_hash(hb)


origin_tlvs = [
    R.tlv(R.TLV_ORIGIN_ROLE, b"eyes.tier1"),
    R.tlv(R.TLV_ORIGIN_MODEL_DIGEST, MODEL_D),
    R.tlv(R.TLV_ORIGIN_CONFIG_DIGEST, CONFIG_D),
]

# 0 — GENESIS. prev_hash is all-zero AND the type is distinguished, so
# "no predecessor" and "predecessor removed" are distinguishable.
prev = emit(
    "genesis",
    R.Header(
        record_type=R.RT_GENESIS,
        seq=0,
        boot_id=BOOT_ID,
        prev_hash=R.ZERO32,
        assurance_tier=R.TIER_A,
        time_trust=R.TIME_UNKNOWN,
        monotonic_ns=0,
    ),
    "Distinguished type at position 0. prev_hash=0 is necessary but not sufficient.",
)

# 1 — BOOT. Its prev_hash IS the cross-boot link.
prev = emit(
    "boot",
    R.Header(
        record_type=R.RT_BOOT,
        seq=1,
        boot_id=BOOT_ID,
        prev_hash=prev,
        assurance_tier=R.TIER_A,
        time_trust=R.TIME_UNSYNCED,
        monotonic_ns=1_200_000,
        wall_clock_ns=0,
    ),
    "wall_clock_ns=0 with time_trust=UNSYNCED: an honest 'I do not know the time'.",
)

# 2 — SPAN_START
prev = emit(
    "span_start",
    R.Header(
        record_type=R.RT_SPAN_START,
        seq=2,
        boot_id=BOOT_ID,
        prev_hash=prev,
        span_id=SPAN_BRAIN,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=5_000_000_000,
        wall_clock_ns=1_784_000_000_000_000_000,
        tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"brain")],
    ),
    "Open span. If the process dies now, the unclosed span is the evidence.",
)

# 3 — EVENT with a real encrypted body (a c' write).
plaintext = b"clear path ahead, one pedestrian at 12m, static"
nonce3 = R.nonce_for(3)
ct3 = AESGCM(KEY).encrypt(nonce3, plaintext, R.aad_for(3, BOOT_ID, R.RT_EVENT))
body3 = nonce3 + ct3  # nonce || ciphertext || tag — body_len covers all of it
prev = emit(
    "event_cprime",
    R.Header(
        record_type=R.RT_EVENT,
        seq=3,
        boot_id=BOOT_ID,
        prev_hash=prev,
        span_id=SPAN_CALL,
        parent_span_id=SPAN_BRAIN,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=5_010_000_000,
        wall_clock_ns=1_784_000_010_000_000_000,
        key_id=KEY_ID,
        body_len=len(body3),
        body_digest=R.body_digest_of(body3),
        tlvs=origin_tlvs,
    ),
    "AES-256-GCM body. The chain hash never touches it — only body_digest does.",
    body=body3,
)

# 4 — MERKLE over one second of frame digests.
frames = [hashlib.sha256(f"frame-{i}".encode()).digest() for i in range(30)]
root = R.merkle_root(frames)
prev = emit(
    "merkle",
    R.Header(
        record_type=R.RT_MERKLE,
        seq=4,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_000_000_000,
        wall_clock_ns=1_784_000_011_000_000_000,
        tlvs=[
            R.tlv(R.TLV_MERKLE_TREE_HASH, root),
            R.tlv(R.TLV_MERKLE_LEAF_COUNT, struct.pack("<I", len(frames))),
            R.tlv(R.TLV_ORIGIN_ROLE, b"eyes.tier0"),
        ],
    ),
    "30 frame digests -> 1 record. Selective disclosure via proof, not bulk reveal.",
)

# 5 — AGGREGATE with a CLEARTEXT body (key_id=0). Tier 0 statistics are not
# personal data, so encrypting them would only make the PMM export useless.
agg_body = R.encode_tlvs(
    [
        R.tlv(R.AGG_WINDOW_NS, struct.pack("<Q", 1_000_000_000)),
        R.tlv(R.AGG_SAMPLE_COUNT, struct.pack("<I", 30)),
        R.tlv(R.AGG_FLOW_MIN_MILLI, struct.pack("<I", 120)),
        R.tlv(R.AGG_FLOW_MAX_MILLI, struct.pack("<I", 4_310)),
        R.tlv(R.AGG_FLOW_MEAN_MILLI, struct.pack("<I", 890)),
    ]
)
prev = emit(
    "aggregate",
    R.Header(
        record_type=R.RT_AGGREGATE,
        seq=5,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_000_000_000,
        wall_clock_ns=1_784_000_011_000_000_000,
        key_id=0,
        body_len=len(agg_body),
        body_digest=R.body_digest_of(agg_body),
        tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"eyes.tier0")],
    ),
    "Cleartext TLV body (key_id=0). Integers only — no float to disagree about.",
    body=agg_body,
)

# 6 — SAFETY: divergence. Never-shed class.
prev = emit(
    "safety_divergence",
    R.Header(
        record_type=R.RT_SAFETY,
        seq=6,
        boot_id=BOOT_ID,
        prev_hash=prev,
        span_id=SPAN_CALL,
        parent_span_id=SPAN_BRAIN,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_100_000_000,
        wall_clock_ns=1_784_000_011_100_000_000,
        tlvs=[R.tlv(R.TLV_ORIGIN_ROLE, b"perception_health")],
    ),
    "Written by the safety path, not the audit. The audit only observes it.",
)

# 7 — SHED notice, itself never shed.
prev = emit(
    "shed_notice",
    R.Header(
        record_type=R.RT_SHED,
        seq=7,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_200_000_000,
        wall_clock_ns=1_784_000_011_200_000_000,
        tlvs=[
            R.tlv(R.TLV_SHED_CLASS, struct.pack("<H", 1)),
            R.tlv(R.TLV_SHED_COUNT, struct.pack("<I", 400)),
            R.tlv(R.TLV_SHED_WINDOW_NS, struct.pack("<Q", 12_000_000_000)),
        ],
    ),
    "The gap is bounded, visible and in the chain. Fail-open, not fail-silent.",
)

# 8 — SPAN_END
prev = emit(
    "span_end",
    R.Header(
        record_type=R.RT_SPAN_END,
        seq=8,
        boot_id=BOOT_ID,
        prev_hash=prev,
        span_id=SPAN_BRAIN,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_500_000_000,
        wall_clock_ns=1_784_000_011_500_000_000,
    ),
    "Close is a separate record. Duration is derived at read time.",
)

# 9 — ANCHOR: notes a head that was written to the local anchor store at this
# point. Per §7.2 a completeness check compares against the store's CURRENT head
# (here the tip, published as anchor_head); this in-chain note records an earlier
# store write and may lag — the stale_anchor demo below exercises that lag.
anchored_head = prev
prev = emit(
    "anchor",
    R.Header(
        record_type=R.RT_ANCHOR,
        seq=9,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=6_600_000_000,
        wall_clock_ns=1_784_000_011_600_000_000,
        tlvs=[R.tlv(R.TLV_ANCHOR_HEAD, anchored_head)],
    ),
    "Notes which head went to the anchor store. The store holds it out of band.",
)

# 10 — WITNESS: tier C asserted post-hoc over a seq range.
receipt = hashlib.sha256(b"fake-rekor-receipt-for-head-" + prev).digest()
prev = emit(
    "witness",
    R.Header(
        record_type=R.RT_WITNESS,
        seq=10,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=9_000_000_000,
        wall_clock_ns=1_784_000_014_000_000_000,
        tlvs=[
            R.tlv(R.TLV_WITNESS_KIND, struct.pack("<H", 1)),
            R.tlv(R.TLV_WITNESS_RANGE_LO, struct.pack("<Q", 0)),
            R.tlv(R.TLV_WITNESS_RANGE_HI, struct.pack("<Q", 9)),
            R.tlv(R.TLV_WITNESS_RECEIPT, receipt),
        ],
    ),
    "Tier C is claimed HERE, after the fact — never in the headers it covers.",
)

# 11 — KEY_SHRED: erase the body of seq=3; the chain survives.
prev = emit(
    "key_shred",
    R.Header(
        record_type=R.RT_KEY_SHRED,
        seq=11,
        boot_id=BOOT_ID,
        prev_hash=prev,
        time_trust=R.TIME_NTP_SYNCED,
        monotonic_ns=90_000_000_000,
        wall_clock_ns=1_784_000_095_000_000_000,
        tlvs=[R.tlv(R.TLV_SHRED_KEY_ID, struct.pack("<I", KEY_ID))],
    ),
    "GDPR Art. 17. Key 7 destroyed; seq=3 body unreadable forever; chain intact.",
)

FINAL_HEAD = prev

# --- verification -------------------------------------------------------------
res = R.verify_chain(chain, expected_head=FINAL_HEAD)

# --- demo: body bitflip -> digest mismatch, chain untouched
ct_bad = bytearray(body3)
ct_bad[-1] ^= 0x01
tamper_detected = R.body_digest_of(bytes(ct_bad)) != R.body_digest_of(body3)

# --- demo: merkle inclusion proof for frame 7
proof = R.merkle_proof(frames, 7)
proof_ok = R.verify_proof(frames[7], proof, root)

# --- demo: unknown record type is chain-checked, never rejected (§7.3)
future = R.Header(
    record_type=0x7FFF,
    seq=12,
    boot_id=BOOT_ID,
    prev_hash=FINAL_HEAD,
    time_trust=R.TIME_NTP_SYNCED,
    tlvs=[R.tlv(0x7000, b"from the future")],
)
res_future = R.verify_chain(chain + [future.encode()])

# --- demo: tail truncation is invisible to the chain, visible to the anchor
res_trunc_no_anchor = R.verify_chain(chain[:-1])
res_trunc_anchor = R.verify_chain(chain[:-1], expected_head=FINAL_HEAD)

# --- demo: a stale anchor is an unanchored tail, NOT a replacement. Same
# verdict (not complete), different diagnosis — which is what an auditor acts on.
res_lag = R.verify_chain(chain, expected_head=anchored_head)

# --- demo: a seq gap with valid hashes is still a break (§4.1)
gap_hdr = R.Header(
    record_type=R.RT_EVENT, seq=99, boot_id=BOOT_ID, prev_hash=FINAL_HEAD,
    time_trust=R.TIME_NTP_SYNCED,
)
res_gap = R.verify_chain(chain + [gap_hdr.encode()])

# --- demo: the chain with its GENESIS removed (§4.2)
# The discriminating input (freeze-candidate run, run #4): the real chain
# minus record 0, so the first record carries a non-zero prev_hash. The
# earlier synthetic input (a single seq-0, zero-prev record) sat in the
# zone where the literal §7.1 pseudocode and the §4.2 prose agree, and
# masked their divergence. The published outputs are unchanged: exactly
# one violation at position 0, no breaks.
res_no_gen = R.verify_chain(chain[1:])

# --- demo: UNKNOWN time trust with a confident timestamp (§5)
bad_time = R.Header(
    record_type=R.RT_EVENT, seq=12, boot_id=BOOT_ID, prev_hash=FINAL_HEAD,
    time_trust=R.TIME_UNKNOWN, wall_clock_ns=1_784_000_000_000_000_000,
)
res_bad_time = R.verify_chain(chain + [bad_time.encode()])

out = {
    "format": "PALA-1",
    "note": "Deterministic. Fixed key and derived nonces ON PURPOSE — never outside vectors.",
    "aes_key_hex": h(KEY),
    "key_id": KEY_ID,
    "nonce_rule": "nonce = 4 zero bytes || seq (u64 LE); seq=3 -> " + h(R.nonce_for(3)),
    "plaintext_utf8": plaintext.decode(),
    "records": records,
    "chain_head": h(FINAL_HEAD),
    "anchor_head": h(FINAL_HEAD),
    "verify": {
        "chain_ok": res.chain_ok,
        "count": res.count,
        "breaks": res.breaks,
        "gaps": res.gaps,
        "violations": res.violations,
        "complete_to_anchor": res.complete_to_anchor,
    },
    "merkle": {
        "leaves": [h(x) for x in frames],
        "tree_hash": h(root),
        "leaf_count": len(frames),
        "proof_index": 7,
        "proof": [[s, h(x)] for s, x in proof],
        "proof_verifies": proof_ok,
    },
    "demos": {
        "body_bitflip": {
            "detected": tamper_detected,
            "chain_still_verifies": R.verify_chain(chain).chain_ok,
        },
        "unknown_record_type": {
            "type": "0x7fff",
            "chain_ok": res_future.chain_ok,
            "count": res_future.count,
            "uninterpretable_seqs": res_future.uninterpretable,
        },
        "tail_truncation": {
            "dropped_seq": 11,
            "chain_ok_without_anchor": res_trunc_no_anchor.chain_ok,
            "complete_to_anchor": res_trunc_anchor.complete_to_anchor,
            "anchor_reason": res_trunc_anchor.anchor_reason,
        },
        "stale_anchor": {
            "anchor_names_seq": 8,
            "chain_ok": res_lag.chain_ok,
            "complete_to_anchor": res_lag.complete_to_anchor,
            "anchor_lag": res_lag.anchor_lag,
            "anchor_reason": res_lag.anchor_reason,
        },
        "seq_gap": {
            "chain_ok": res_gap.chain_ok,
            "gaps": res_gap.gaps,
        },
        "missing_genesis": {
            "chain_ok": res_no_gen.chain_ok,
            "breaks": res_no_gen.breaks,
            "violations": res_no_gen.violations,
        },
        "unknown_time_with_clock": {
            "chain_ok": res_bad_time.chain_ok,
            "violations": res_bad_time.violations,
        },
    },
}

with open("test-vectors.json", "w") as f:
    f.write(json.dumps(out, indent=2))
    f.write("\n")

print("records:", len(records))
print("chain head:", h(FINAL_HEAD))
print("anchor head (in-chain ANCHOR note, may lag):", h(anchored_head))
print("published anchor_head (current store, = tip):", h(FINAL_HEAD))
print("merkle tree hash:", h(root))
print("chain_ok:", res.chain_ok, "| complete_to_anchor:", res.complete_to_anchor)
print("proof len:", len(proof), "verifies:", proof_ok)
