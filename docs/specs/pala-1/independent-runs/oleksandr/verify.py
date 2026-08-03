#!/usr/bin/env python3
"""Independent PALA-1 verifier — written from the PALA-1 specification and its
test vectors ALONE, without reading any reference implementation. This is the
§11 exit test: if the published §8 results are reproduced from the spec text
plus the vectors, the specification is self-sufficient.

stdlib + hashlib only. No code from the reference implementation.

Categories of verdict (kept strictly separate, per the exit-test discipline):
  REPRODUCED   — computed independently from vector data, matches published.
  TAUTOLOGY    — value only echoes a field embedded in the container itself
                 (NOT a verification; reported as such, never as PASS).
  UNVERIFIABLE — cannot be recomputed nor checked from the allowed files.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# In-repo location: docs/specs/pala-1/independent-runs/oleksandr/verify.py
# The vectors live two levels up at docs/specs/pala-1/test-vectors.json.
# (Authored in isolation outside the tree; the standalone copy used a local
# spec/ dir. Only the vectors path differs — the logic is byte-identical.)
SPEC = Path(__file__).resolve().parent.parent.parent / "test-vectors.json"

ZERO32 = b"\x00" * 32

# Record types (spec §3). format_version known set: {1} (§2.1).
KNOWN_TYPES = {
    0x0001, 0x0002, 0x0010, 0x0011, 0x0012, 0x0020,
    0x0021, 0x0030, 0x0040, 0x0050, 0x0051, 0x0060,
}
GENESIS = 0x0001
KNOWN_VERSIONS = {1}

# TLV types referenced by verification (§2.2).
TLV_MERKLE_TREE_HASH = 0x0011
TLV_MERKLE_LEAF_COUNT = 0x0012
TLV_ANCHOR_HEAD = 0x0050


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ── header parse (§2.1 fixed 156-byte layout, then §2.2 TLV) ────────────────


def u(b: bytes, off: int, size: int) -> int:
    return int.from_bytes(b[off : off + size], "little")


def parse_header(hb: bytes) -> dict:
    h = {
        "magic": hb[0:4],
        "format_version": u(hb, 4, 2),
        "header_len": u(hb, 6, 2),
        "record_type": u(hb, 8, 2),
        "assurance_tier": hb[10],
        "time_trust": hb[11],
        "seq": u(hb, 12, 8),
        "boot_id": hb[20:36],
        "prev_hash": hb[36:68],
        "span_id": hb[68:84],
        "parent_span_id": hb[84:100],
        "monotonic_ns": u(hb, 100, 8),
        "wall_clock_ns": int.from_bytes(hb[108:116], "little", signed=True),
        "key_id": u(hb, 116, 4),
        "body_len": u(hb, 120, 4),
        "body_digest": hb[124:156],
        "raw": hb,
    }
    return h


def parse_tlvs(hb: bytes) -> tuple[list[tuple[int, bytes]], str | None]:
    """Parse TLVs from offset 156 to header_len (§2.2). Returns (items, error)
    where error is a §7.4 TLV-framing violation message or None."""
    hl = u(hb, 6, 2)
    off = 156
    items: list[tuple[int, bytes]] = []
    while off < hl:
        if off + 4 > hl:
            return items, "TLV header overruns header_len"
        t = u(hb, off, 2)
        length = u(hb, off + 2, 2)
        vstart = off + 4
        vend = vstart + length
        if vend > hl:
            return items, "TLV value overruns header_len"
        items.append((t, hb[vstart:vend]))
        off = vend
    if off != hl:
        return items, "TLV items do not end exactly at header_len"
    return items, None


def tlv_get(items: list[tuple[int, bytes]], t: int) -> bytes | None:
    for tt, v in items:
        if tt == t:
            return v
    return None


# ── §7.4 semantic checks (only on known version+type records) ───────────────


def semantic_violations(h: dict) -> list[str]:
    v = []
    # header_len must equal actual header bytes (§2.1)
    if h["header_len"] != len(h["raw"]):
        v.append("header_len != actual header bytes")
    # TLV framing (§2.2)
    _items, tlv_err = parse_tlvs(h["raw"])
    if tlv_err:
        v.append(tlv_err)
    # time_trust == UNKNOWN => wall_clock_ns == 0 (§5)
    if h["time_trust"] == 0 and h["wall_clock_ns"] != 0:
        v.append("time_trust=UNKNOWN requires wall_clock_ns=0")
    # time_trust <= 3 (§5)
    if h["time_trust"] > 3:
        v.append("time_trust > 3 is undefined in version 1")
    # body_len == 0 <=> body_digest == 32 zero bytes (§2.1)
    if (h["body_len"] == 0) != (h["body_digest"] == ZERO32):
        v.append("body_len==0 must iff body_digest==32 zero bytes")
    # key_id != 0 and body_len > 0 => body_len >= 28 (nonce+tag) (§4.4/§7.4)
    if h["key_id"] != 0 and h["body_len"] > 0 and h["body_len"] < 28:
        v.append("encrypted body must be >= 28 bytes (nonce+tag)")
    return v


# ── §7.1 header-only chain verification ─────────────────────────────────────


def chain_verify(headers: list[bytes]) -> dict:
    """Follows the §7.1 pseudocode. NOTE on the first-record-not-GENESIS case:
    §7.1/§4.2 prose say 'break', but §8 (and test-vectors demos.missing_genesis)
    require a 'violation' with a specific message. Per the exit test, §8 is the
    source of truth; the prose is flagged in the ambiguity log. Implemented to
    match §8: reported as a VIOLATION."""
    prev = ZERO32
    expected = None
    breaks, gaps, violations, uninterpretable = [], [], [], []
    count = 0
    for index, hb in enumerate(headers):
        h = parse_header(hb)
        if h["magic"] != b"PALA":
            breaks.append((h["seq"], "magic != PALA — stop"))
            break
        count += 1
        if h["header_len"] != len(hb):
            violations.append((h["seq"], "header_len != actual header bytes"))
        if index == 0:
            if h["record_type"] != GENESIS:
                # §8/vectors: violation (prose §7.1/§4.2 say 'break' — see log)
                violations.append((h["seq"], "chain does not start with a GENESIS record"))
            if h["prev_hash"] != ZERO32:
                violations.append((h["seq"], "genesis prev_hash must be 32 zero bytes"))
        else:
            if h["record_type"] == GENESIS:
                violations.append((h["seq"], "GENESIS record at non-first position"))
        if h["prev_hash"] != prev:
            breaks.append((h["seq"], "prev_hash does not link"))
        if expected is not None and h["seq"] != expected:
            gaps.append(h["seq"])
        expected = h["seq"] + 1
        if h["format_version"] not in KNOWN_VERSIONS or h["record_type"] not in KNOWN_TYPES:
            uninterpretable.append(h["seq"])  # §7.6 — NOT a break, NO §7.4
        else:
            for msg in semantic_violations(h):
                violations.append((h["seq"], msg))
        prev = sha256(hb)
    chain_ok = not breaks and not gaps and not violations
    return {
        "chain_ok": chain_ok,
        "count": count,
        "breaks": breaks,
        "gaps": gaps,
        "violations": violations,
        "uninterpretable": uninterpretable,
        "head": prev,
    }


# ── §7.2 completeness against an anchor ─────────────────────────────────────


def completeness(anchor: bytes, headers: list[bytes]) -> dict:
    hashes = [sha256(hb) for hb in headers]
    head = hashes[-1] if hashes else ZERO32
    if anchor == head:
        return {"result": "complete", "complete_to_anchor": True}
    for i, rh in enumerate(hashes):
        if rh == anchor:
            lag = len(hashes) - 1 - i
            return {
                "result": "unanchored_tail",
                "complete_to_anchor": False,
                "anchor_lag": lag,
            }
    return {"result": "replaced_or_truncated", "complete_to_anchor": False}


# ── §4.3 Merkle (RFC 6962, promotion of unpaired node) ──────────────────────
# Implemented so that IF leaf digests are available they can be used. The tree
# is computed from the LEAVES (frame digests), which the profile (robotics §3)
# defines but the vectors do NOT provide (see Finding 1).


def mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over a list of leaf *data* digests. Recursive
    split at the largest power of two below n; unpaired handled by the split
    (never duplicated)."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")  # empty (§4.3)
    if n == 1:
        return sha256(b"\x00" + leaves[0])  # leaf(d)
    k = 1
    while k * 2 < n:
        k *= 2
    return sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))  # node(l,r)


def verify_inclusion(leaf_data: bytes, index: int, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    cur = sha256(b"\x00" + leaf_data)
    for side, sib in proof:
        if side == "L":
            cur = sha256(b"\x01" + sib + cur)
        else:
            cur = sha256(b"\x01" + cur + sib)
    return cur == root


# ── synthetic header builder (for the mutation demos) ───────────────────────


def build_header(record_type, seq, prev_hash, *, time_trust=1, wall_clock_ns=0,
                 boot_id=b"\x00" * 16, tlvs=b""):
    fixed = bytearray(156)
    fixed[0:4] = b"PALA"
    fixed[4:6] = (1).to_bytes(2, "little")
    fixed[6:8] = (156 + len(tlvs)).to_bytes(2, "little")
    fixed[8:10] = record_type.to_bytes(2, "little")
    fixed[10] = 0
    fixed[11] = time_trust
    fixed[12:20] = seq.to_bytes(8, "little")
    fixed[20:36] = boot_id
    fixed[36:68] = prev_hash
    fixed[100:108] = (0).to_bytes(8, "little")
    fixed[108:116] = wall_clock_ns.to_bytes(8, "little", signed=True)
    fixed[116:120] = (0).to_bytes(4, "little")
    fixed[120:124] = (0).to_bytes(4, "little")
    fixed[124:156] = ZERO32
    return bytes(fixed) + tlvs


# ── driver ──────────────────────────────────────────────────────────────────


def main():
    data = json.loads(SPEC.read_text(encoding="utf-8"))
    recs = data["records"]
    headers = [bytes.fromhex(r["header_hex"]) for r in recs]
    bodies = {r["seq"]: bytes.fromhex(r["body_hex"]) for r in recs if "body_hex" in r}

    out = []
    def line(s=""):
        out.append(s)
        print(s)

    line("=" * 72)
    line("PALA-1 INDEPENDENT VERIFIER — §8 reproduction")
    line("=" * 72)

    # ── record_hash per record (§4.1) ──────────────────────────────────────
    rh_ok = True
    computed_hashes = []
    for r in recs:
        hb = bytes.fromhex(r["header_hex"])
        rh = sha256(hb).hex()
        computed_hashes.append(rh)
        match = rh == r["record_hash"]
        rh_ok = rh_ok and match
        if not match:
            line(f"  record_hash MISMATCH seq {r['seq']}: computed {rh} vs published {r['record_hash']}")
    line(f"[REPRODUCED] record_hash for all {len(recs)} records: "
         f"{'ALL MATCH' if rh_ok else 'MISMATCH — see above'}")

    # ── §7.1 chain verification on the main chain ──────────────────────────
    cv = chain_verify(headers)
    line("")
    line("§7.1 chain verification (main chain):")
    def cat(name, computed, published):
        ok = computed == published
        line(f"  [REPRODUCED] {name}: computed={computed}  published={published}  "
             f"{'MATCH' if ok else 'MISMATCH'}")
        return ok
    v = data["verify"]
    a1 = cat("chain_ok", cv["chain_ok"], v["chain_ok"])
    a2 = cat("record_count", cv["count"], v["count"])
    a3 = cat("breaks", cv["breaks"], v["breaks"])
    a4 = cat("gaps", cv["gaps"], v["gaps"])
    a5 = cat("violations", cv["violations"], v["violations"])
    ch = cv["head"].hex()
    a6 = cat("chain_head", ch, data["chain_head"])

    # ── §7.2 completeness (anchor = chain_head, per §8) ────────────────────
    line("")
    line("§7.2 completeness against anchor:")
    comp = completeness(bytes.fromhex(data["chain_head"]), headers)
    a7 = cat("complete_to_anchor (anchor=chain_head)", comp["complete_to_anchor"],
             v["complete_to_anchor"])

    # ── anchor_head (record_hash of seq-8 record) + ANCHOR_HEAD TLV echo ────
    line("")
    line("anchor_head (§7.2):")
    seq8_hash = computed_hashes[8]
    a8 = cat("anchor_head = record_hash(seq 8)", seq8_hash, data["anchor_head"])
    # cross-check: ANCHOR record (seq 9) ANCHOR_HEAD TLV == anchor_head
    seq9_tlvs, _ = parse_tlvs(headers[9])
    anchor_tlv = tlv_get(seq9_tlvs, TLV_ANCHOR_HEAD)
    line(f"  [cross-check] seq-9 ANCHOR_HEAD TLV == anchor_head: "
         f"{anchor_tlv is not None and anchor_tlv.hex() == data['anchor_head']}")

    # ── Merkle (§4.3) — honest category split (Finding 1) ──────────────────
    line("")
    line("Merkle (§4.3) — Finding 1 category check:")
    seq4 = parse_header(headers[4])
    seq4_tlvs, _ = parse_tlvs(headers[4])
    line(f"  MERKLE record (seq 4) body_len = {seq4['body_len']}  "
         f"(has body_hex in vectors: {4 in bodies})")
    leaf_count_tlv = tlv_get(seq4_tlvs, TLV_MERKLE_LEAF_COUNT)
    tree_hash_tlv = tlv_get(seq4_tlvs, TLV_MERKLE_TREE_HASH)
    lc = int.from_bytes(leaf_count_tlv, "little") if leaf_count_tlv else None
    a9 = cat("merkle_leaf_count (from LEAF_COUNT TLV)", lc, data["merkle"]["leaf_count"])
    # Do the leaves exist anywhere in the container?
    leaves_present = (seq4["body_len"] > 0) or (4 in bodies)
    line(f"  30 leaf digests present in container?  {leaves_present}")
    if leaves_present:
        line("  -> leaves available: could recompute tree_hash from them (weaker "
             "than 'from frames' but NOT tautology).")
    else:
        line("  -> LEAVES ABSENT. merkle_tree_hash can only be echoed from the "
             "embedded MERKLE_TREE_HASH TLV, which is TAUTOLOGY, not verification.")
    # tautology echo (reported as TAUTOLOGY, never PASS):
    echo = tree_hash_tlv.hex() if tree_hash_tlv else None
    tautology_match = echo == data["merkle"]["tree_hash"]
    line(f"  [TAUTOLOGY] tree_hash TLV embedded in record == published tree_hash: "
         f"{tautology_match}  (NOT a verification — the record carries its own claimed root)")
    # inclusion proof:
    proof = [(s, bytes.fromhex(hx)) for s, hx in data["merkle"]["proof"]]
    line(f"  [REPRODUCED] proof_len == 5: {len(proof) == 5}  (structural: "
         f"consistent with a 30-leaf tree)")
    line("  [UNVERIFIABLE] inclusion proof for leaf 7: leaf-7 frame digest is "
         "NOT in the allowed files, so the fold-to-root cannot be checked. "
         "Any 'PASS' here would assume the leaf that makes it work (circular).")

    # ── mutation demos (§8) ────────────────────────────────────────────────
    line("")
    line("Mutation demos (§8):")
    demos = data["demos"]

    # body_bitflip: flip one bit in seq-3 body, digest mismatch, chain unchanged
    b3 = bytearray(bodies[3])
    b3[0] ^= 0x01
    flip_digest = sha256(bytes(b3))
    orig_digest = parse_header(headers[3])["body_digest"]
    detected = flip_digest != orig_digest
    chain_unchanged = chain_verify(headers)["chain_ok"]
    line(f"  [REPRODUCED] body_bitflip: digest mismatch detected={detected} "
         f"(expected {demos['body_bitflip']['detected']}); chain still verifies="
         f"{chain_unchanged} (expected {demos['body_bitflip']['chain_still_verifies']})")

    # unknown_record_type: append synthetic record type 0x7fff, seq 12
    synth = build_header(0x7FFF, 12, sha256(headers[-1]))
    cv2 = chain_verify(headers + [synth])
    d = demos["unknown_record_type"]
    line(f"  [REPRODUCED] unknown_record_type: chain_ok={cv2['chain_ok']} "
         f"(exp {d['chain_ok']}), count={cv2['count']} (exp {d['count']}), "
         f"uninterpretable={cv2['uninterpretable']} (exp {d['uninterpretable_seqs']})")

    # tail_truncation: drop last record; chain_ok true; anchor=chain_head names nothing
    trunc = headers[:-1]
    cvt = chain_verify(trunc)
    compt = completeness(bytes.fromhex(data["chain_head"]), trunc)
    d = demos["tail_truncation"]
    line(f"  [REPRODUCED] tail_truncation: chain_ok_without_anchor={cvt['chain_ok']} "
         f"(exp {d['chain_ok_without_anchor']}), complete_to_anchor="
         f"{compt['complete_to_anchor']} (exp {d['complete_to_anchor']}), "
         f"result={compt['result']}")

    # stale_anchor: anchor = record_hash(seq 8), full chain -> lag 3
    comps = completeness(bytes.fromhex(data["anchor_head"]), headers)
    d = demos["stale_anchor"]
    line(f"  [REPRODUCED] stale_anchor: complete_to_anchor={comps['complete_to_anchor']} "
         f"(exp {d['complete_to_anchor']}), anchor_lag={comps.get('anchor_lag')} "
         f"(exp {d['anchor_lag']}), result={comps['result']}")

    # seq_gap: synthetic seq-99 record linked to chain_head -> gap [99]
    gaprec = build_header(0x0012, 99, sha256(headers[-1]))
    cvg = chain_verify(headers + [gaprec])
    d = demos["seq_gap"]
    line(f"  [REPRODUCED] seq_gap: chain_ok={cvg['chain_ok']} (exp {d['chain_ok']}), "
         f"gaps={cvg['gaps']} (exp {d['gaps']})")

    # missing_genesis: verify records[1:] -> violation (per §8; prose says break)
    cvm = chain_verify(headers[1:])
    d = demos["missing_genesis"]
    got_msg = [list(x) for x in cvm["violations"] if x[1] == "chain does not start with a GENESIS record"]
    line(f"  [REPRODUCED*] missing_genesis: chain_ok={cvm['chain_ok']} (exp {d['chain_ok']}), "
         f"violation present={bool(got_msg)} (exp {d['violations']}) "
         f"[*categorised as violation to match §8; §7.1/§4.2 prose say 'break' — see log]")

    # unknown_time_with_clock: synthetic record time_trust=0, wall_clock!=0
    badtime = build_header(0x0012, 12, sha256(headers[-1]), time_trust=0, wall_clock_ns=123456789)
    cvu = chain_verify(headers + [badtime])
    d = demos["unknown_time_with_clock"]
    has_v = any(m == "time_trust=UNKNOWN requires wall_clock_ns=0" for _, m in cvu["violations"])
    line(f"  [REPRODUCED] unknown_time_with_clock: chain_ok={cvu['chain_ok']} "
         f"(exp {d['chain_ok']}), violation present={has_v} (exp {d['violations']})")

    line("")
    line("=" * 72)
    core_ok = all([a1, a2, a3, a4, a5, a6, a7, a8, a9])
    line(f"CORE §8 REPRODUCED (chain_head, chain_ok, count, breaks, gaps, "
         f"violations, completeness, anchor_head, leaf_count): {core_ok}")
    line("merkle_tree_hash: NOT independently reproduced (leaves absent) — "
         "TAUTOLOGY echo only. inclusion proof: UNVERIFIABLE. See ambiguity-log.")
    line("=" * 72)


if __name__ == "__main__":
    sys.exit(main())
