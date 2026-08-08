# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0

"""Reference encoder/verifier for the PALA-1 audit wire format.

This is NOT production code. It exists to generate the test vectors in the
specification, so that the specification is falsifiable.

The relationship to the prose is deliberate and one-directional: **the prose is
normative, this file is subordinate.** Where they disagree, this file is wrong.
Every check below cites the section of PALA-1.md it implements; a
check with no citation does not belong here.

Deliberately dependency-free and boring. An independent implementer should be
able to read it in one sitting — and should not need to.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

MAGIC = b"PALA"
FORMAT_VERSION = 1
FIXED_HEADER_LEN = 156
ZERO32 = b"\x00" * 32
ZERO16 = b"\x00" * 16

NONCE_LEN = 12
GCM_TAG_LEN = 16

# --- record types (§3) -------------------------------------------------------
RT_GENESIS = 0x0001
RT_BOOT = 0x0002
RT_SPAN_START = 0x0010
RT_SPAN_END = 0x0011
RT_EVENT = 0x0012
RT_MERKLE = 0x0020
RT_AGGREGATE = 0x0021
RT_SHED = 0x0030
RT_SAFETY = 0x0040
RT_ANCHOR = 0x0050
RT_WITNESS = 0x0051
RT_KEY_SHRED = 0x0060

KNOWN_RECORD_TYPES = frozenset(
    {
        RT_GENESIS,
        RT_BOOT,
        RT_SPAN_START,
        RT_SPAN_END,
        RT_EVENT,
        RT_MERKLE,
        RT_AGGREGATE,
        RT_SHED,
        RT_SAFETY,
        RT_ANCHOR,
        RT_WITNESS,
        RT_KEY_SHRED,
    }
)

# --- assurance tier (§6) — platform capability at write time -----------------
TIER_A = 0  # chain + local anchor only
TIER_B = 1  # + hardware root of trust: device identity
TIER_BPLUS = 2  # + monotonic NV counter: fresh genesis detectable
# Tier C is NOT a header value. It is asserted post-hoc by RT_WITNESS records
# covering a seq range. A header cannot honestly claim to have been witnessed
# before the witness exists.

# --- wall clock trust (§5) ---------------------------------------------------
TIME_UNKNOWN = 0
TIME_UNSYNCED = 1
TIME_HW_RTC = 2
TIME_NTP_SYNCED = 3

# --- header TLV types (§2.2) -------------------------------------------------
# Names are distinct from record-type names on purpose: TLV 0x0011 and record
# type 0x0020 both concern Merkle aggregation and both used to be called
# MERKLE_ROOT, in different namespaces, with different numbers.
TLV_ORIGIN_ROLE = 0x0001  # utf-8
TLV_ORIGIN_MODEL_DIGEST = 0x0002  # 32 bytes
TLV_ORIGIN_CONFIG_DIGEST = 0x0003  # 32 bytes
TLV_MERKLE_TREE_HASH = 0x0011  # 32 bytes
TLV_MERKLE_LEAF_COUNT = 0x0012  # u32
TLV_SHED_CLASS = 0x0020  # u16
TLV_SHED_COUNT = 0x0021  # u32
TLV_SHED_WINDOW_NS = 0x0022  # u64
TLV_WITNESS_KIND = 0x0030  # u16
TLV_WITNESS_RANGE_LO = 0x0031  # u64
TLV_WITNESS_RANGE_HI = 0x0032  # u64
TLV_WITNESS_RECEIPT = 0x0033  # opaque
TLV_SHRED_KEY_ID = 0x0040  # u32
TLV_ANCHOR_HEAD = 0x0050  # 32 bytes

# --- AGGREGATE body TLV types (§3.2) -----------------------------------------
# Separate namespace from header TLVs. Integers only: a float would reintroduce
# exactly the cross-implementation disagreement §1.1 rejects JSON for.
AGG_WINDOW_NS = 0x0001  # u64
AGG_SAMPLE_COUNT = 0x0002  # u32
AGG_FLOW_MIN_MILLI = 0x0003  # u32, milli-pixels/frame
AGG_FLOW_MAX_MILLI = 0x0004  # u32
AGG_FLOW_MEAN_MILLI = 0x0005  # u32


def tlv(t: int, v: bytes) -> tuple[int, bytes]:
    return (t, v)


def encode_tlvs(tlvs: list[tuple[int, bytes]]) -> bytes:
    return b"".join(struct.pack("<HH", t, len(v)) + v for t, v in tlvs)


def decode_tlvs(buf: bytes) -> list[tuple[int, bytes]]:
    """Parse a TLV sequence. Raises on a truncated or overrunning item (§2.2)."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(buf):
        if off + 4 > len(buf):
            raise ValueError("truncated TLV header")
        t, ln = struct.unpack_from("<HH", buf, off)
        off += 4
        if off + ln > len(buf):
            raise ValueError("TLV value overruns its container")
        out.append((t, buf[off : off + ln]))
        off += ln
    return out


def nonce_for(seq: int) -> bytes:
    """Deterministic per-record nonce (§4.4).

    Random 96-bit nonces are not safe past ~2**32 records under one key. A
    deterministic nonce derived from seq is unique for every record in a chain
    by construction, and leaks only the position — which the cleartext header
    states anyway.
    """
    return b"\x00" * 4 + struct.pack("<Q", seq)


@dataclass
class Header:
    record_type: int
    seq: int
    boot_id: bytes
    prev_hash: bytes
    assurance_tier: int = TIER_A
    time_trust: int = TIME_UNKNOWN
    span_id: bytes = ZERO16
    parent_span_id: bytes = ZERO16
    monotonic_ns: int = 0
    wall_clock_ns: int = 0
    key_id: int = 0
    body_len: int = 0
    body_digest: bytes = ZERO32
    tlvs: list[tuple[int, bytes]] = field(default_factory=list)

    def encode(self) -> bytes:
        tlv_bytes = encode_tlvs(self.tlvs)
        header_len = FIXED_HEADER_LEN + len(tlv_bytes)
        fixed = struct.pack(
            "<4sHHHBBQ16s32s16s16sQqII32s",
            MAGIC,
            FORMAT_VERSION,
            header_len,
            self.record_type,
            self.assurance_tier,
            self.time_trust,
            self.seq,
            self.boot_id,
            self.prev_hash,
            self.span_id,
            self.parent_span_id,
            self.monotonic_ns,
            self.wall_clock_ns,
            self.key_id,
            self.body_len,
            self.body_digest,
        )
        assert len(fixed) == FIXED_HEADER_LEN, len(fixed)
        return fixed + tlv_bytes


def record_hash(header_bytes: bytes) -> bytes:
    """The chain hash covers the header ONLY (§1.2).

    The body is bound in via body_digest, which lives inside the header. This is
    the whole trick: a verifier checks chain integrity by reading headers alone —
    no key, no bodies, no personal data. It is also what lets a crypto-shredded
    body leave the chain intact.
    """
    return hashlib.sha256(header_bytes).digest()


def body_digest_of(body: bytes) -> bytes:
    """SHA-256 over the body exactly as stored (§4.4).

    Uniform for both shapes: an encrypted body is nonce || ciphertext || tag; a
    cleartext body is its raw bytes. The digest never knows the difference.
    """
    return hashlib.sha256(body).digest()


def aad_for(seq: int, boot_id: bytes, record_type: int) -> bytes:
    """AEAD associated data (§4.4): binds a ciphertext to its chain position."""
    return struct.pack("<Q", seq) + boot_id + struct.pack("<H", record_type)


# --- Merkle (RFC 6962, domain-separated) -------------------------------------
def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 tree hash. Unpaired node is PROMOTED, never duplicated.

    Duplicating the last node is the CVE-2012-2459 mistake: two distinct leaf
    sets collapse to the same root.

    The iterative promotion below is equivalent to RFC 6962's recursive split at
    the largest power of two below n — verified for every n in 1..599. It is
    written iteratively because that is the shape an implementer will reach for.
    """
    if not leaves:
        return hashlib.sha256(b"").digest()
    layer = [leaf_hash(x) for x in leaves]
    while len(layer) > 1:
        nxt = [node_hash(layer[i], layer[i + 1]) for i in range(0, len(layer) - 1, 2)]
        if len(layer) % 2:
            nxt.append(layer[-1])  # promote, do not duplicate
        layer = nxt
    return layer[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """Inclusion proof for leaves[index]. Each step names the sibling's side."""
    layer = [leaf_hash(x) for x in leaves]
    proof: list[tuple[str, bytes]] = []
    idx = index
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer) - 1, 2):
            if i == idx:
                proof.append(("R", layer[i + 1]))
            elif i + 1 == idx:
                proof.append(("L", layer[i]))
            nxt.append(node_hash(layer[i], layer[i + 1]))
        if len(layer) % 2:
            nxt.append(layer[-1])
        idx //= 2
        layer = nxt
    return proof


def verify_proof(leaf: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    h = leaf_hash(leaf)
    for side, sib in proof:
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == root


# --- chain verification (§7) --------------------------------------------------
@dataclass
class VerifyResult:
    """The three questions are answered separately, never collapsed into one bool.

    ``chain_ok`` is *internal consistency only* — it does not mean "nothing is
    missing". Truncation of the tail leaves a perfectly linked chain (§7.1), so
    completeness is a different question with a different answer field.
    """

    chain_ok: bool
    count: int
    head: bytes
    breaks: list[int] = field(default_factory=list)
    gaps: list[int] = field(default_factory=list)
    violations: list[tuple[int, str]] = field(default_factory=list)
    uninterpretable: list[int] = field(default_factory=list)
    #: None = not checked (no anchor supplied). True/False = checked.
    complete_to_anchor: bool | None = None
    #: Records between the anchored head and the chain head, when the anchor
    #: names a record inside the chain. Distinguishes an unanchored tail from a
    #: replacement — the same diagnosis Palimpsests' AuditLog.verify() makes.
    anchor_lag: int | None = None
    anchor_reason: str | None = None


def _semantic_checks(hb: bytes, seq: int, rtype: int, index: int) -> list[tuple[int, str]]:
    """Normative MUSTs a verifier can check on a record type it understands.

    Deliberately does NOT touch unknown types or versions: §7.3 forbids
    rejecting what we cannot interpret. A violation here is a defect in a
    record we *do* claim to understand.
    """
    out: list[tuple[int, str]] = []
    time_trust = hb[11]
    (wall_clock_ns,) = struct.unpack_from("<q", hb, 108)
    (key_id,) = struct.unpack_from("<I", hb, 116)
    (body_len,) = struct.unpack_from("<I", hb, 120)
    body_digest = hb[124:156]

    # §5: an honest "I do not know the time" is a hard requirement, not a hint.
    if time_trust == TIME_UNKNOWN and wall_clock_ns != 0:
        out.append((seq, "time_trust=UNKNOWN requires wall_clock_ns=0"))
    if time_trust > TIME_NTP_SYNCED:
        out.append((seq, f"time_trust={time_trust} is not a defined value"))

    # §2.1: an empty body has a zero digest; a non-empty body does not.
    if body_len == 0 and body_digest != ZERO32:
        out.append((seq, "body_len=0 requires body_digest = 32 zero bytes"))
    if body_len != 0 and body_digest == ZERO32:
        out.append((seq, "non-empty body with an all-zero body_digest"))

    # §4.4: an encrypted body carries a nonce and a tag; it cannot be shorter.
    if key_id != 0 and 0 < body_len < NONCE_LEN + GCM_TAG_LEN:
        out.append((seq, f"encrypted body_len={body_len} is shorter than nonce+tag"))

    # §4.2: genesis is a position, not just a type.
    if rtype == RT_GENESIS and index != 0:
        out.append((seq, "GENESIS record at a non-initial position"))

    return out


def verify_chain(
    headers: Iterable[bytes],
    known_types: frozenset[int] | set[int] = KNOWN_RECORD_TYPES,
    *,
    expected_head: bytes | None = None,
) -> VerifyResult:
    """Header-only verification (§7.1). No key required. No bodies touched.

    A record of an unknown type or unknown format version is still chain-checked:
    the hash covers raw bytes, so integrity does not require comprehension.

    ``expected_head`` is the anchor (§7.2): the head this chain is supposed to
    have, obtained from outside the log — a local keychain anchor, or the value
    covered by the newest WITNESS receipt. Without it, truncation of the tail is
    undetectable and ``complete_to_anchor`` stays None. That is not a limitation
    of this function; it is the reason anchors exist.
    """
    prev = ZERO32
    breaks: list[int] = []
    gaps: list[int] = []
    violations: list[tuple[int, str]] = []
    uninterpretable: list[int] = []
    seen: list[bytes] = []
    expected_seq: int | None = None
    count = 0

    for index, hb in enumerate(headers):
        if len(hb) < FIXED_HEADER_LEN:
            breaks.append(count)
            break
        magic, ver, hlen, rtype = struct.unpack_from("<4sHHH", hb, 0)
        if magic != MAGIC:
            breaks.append(count)
            break
        if hlen != len(hb):
            # header_len is frozen for all versions (§7.3): a verifier that
            # cannot trust it cannot find the next record.
            violations.append((count, f"header_len={hlen} but {len(hb)} bytes supplied"))
        (seq,) = struct.unpack_from("<Q", hb, 12)

        # §4.2 — "no predecessor" and "predecessor removed" must be
        # distinguishable, which is the entire reason GENESIS is a type.
        if index == 0:
            if rtype != RT_GENESIS:
                # §4.2 / §8: exactly ONE violation, keyed at position 0 (a
                # property of the chain, not of the record's seq); no break
                # and no zero-prev demand — the links around it may be
                # perfectly sound. Aligned at the freeze-candidate run
                # (run #4): the literal §7.1 pseudocode had produced two
                # violations and a spurious break here.
                violations.append((0, "chain does not start with a GENESIS record"))
            elif hb[36:68] != ZERO32:
                violations.append((seq, "GENESIS must have prev_hash = 32 zero bytes"))
        elif hb[36:68] != prev:
            # Only records with a predecessor in the file are link-checked.
            breaks.append(seq)
        # §4.1 — a gap in seq is a break, whether or not the hashes link.
        if expected_seq is not None and seq != expected_seq:
            gaps.append(seq)
        expected_seq = seq + 1

        if ver != FORMAT_VERSION or rtype not in known_types:
            uninterpretable.append(seq)
        else:
            violations.extend(_semantic_checks(hb, seq, rtype, index))
            try:
                decode_tlvs(hb[FIXED_HEADER_LEN:hlen])
            except ValueError as e:
                violations.append((seq, f"malformed TLV: {e}"))

        prev = record_hash(hb)
        seen.append(prev)
        count += 1

    chain_ok = not breaks and not gaps and not violations
    result = VerifyResult(
        chain_ok=chain_ok,
        count=count,
        head=prev,
        breaks=breaks,
        gaps=gaps,
        violations=violations,
        uninterpretable=uninterpretable,
    )

    if expected_head is not None:
        result.complete_to_anchor = expected_head == prev
        if not result.complete_to_anchor:
            if expected_head in seen:
                # The anchored head is inside the chain: rows exist past it.
                result.anchor_lag = len(seen) - seen.index(expected_head) - 1
                result.anchor_reason = (
                    f"chain extends {result.anchor_lag} record(s) beyond the anchored "
                    "head — an unanchored tail, not a replacement"
                )
            else:
                # The anchored head is nowhere: this is not that history. A
                # truncated tail lands here too, which is the point.
                result.anchor_reason = (
                    "the anchored head names no record in this chain — the log was "
                    "replaced, rolled back, or truncated"
                )

    return result
