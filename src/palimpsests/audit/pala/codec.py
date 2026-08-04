# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""PALA-1 wire codec: header layout, TLV extensions, and the file container.

This module and its siblings (``merkle``, ``verify``) are deliberately
**stdlib-only** — ``hashlib`` and ``struct`` and nothing else. That is not
frugality but a property of the format itself: chain verification reads
headers alone and needs no key, so a verifier must be constructible on a
bare Python install. Everything that touches record *bodies* (AES-GCM, and
therefore the ``cryptography`` package) lives in ``bodies`` behind the
``[pala]`` extra, imported lazily.

The normative source is ``docs/specs/pala-1/PALA-1.md``. Where this code
and that prose disagree, the prose wins and this code is wrong; every
constant and rule below cites the section it implements. The specification
is a **draft**: the field set is not yet frozen, and this codec makes no
stability promise until it is.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

MAGIC = b"PALA"
FORMAT_VERSION = 1
FIXED_HEADER_LEN = 156  # §2.1
ZERO32 = b"\x00" * 32
ZERO16 = b"\x00" * 16

NONCE_LEN = 12  # §4.4
GCM_TAG_LEN = 16

_FIXED = "<4sHHHBBQ16s32s16s16sQqII32s"  # §2.1, little-endian, packed
assert struct.calcsize(_FIXED) == FIXED_HEADER_LEN

# ─── record types (§3) ───────────────────────────────────────────────────
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

# ─── assurance tier (§6) — platform capability at write time ─────────────
TIER_A = 0
TIER_B = 1
TIER_BPLUS = 2
# Tier C is not a header value: a header cannot honestly claim to have been
# witnessed before the witness exists. It is asserted post-hoc by an
# RT_WITNESS record covering a seq range.

# ─── wall-clock trust (§5) ───────────────────────────────────────────────
TIME_UNKNOWN = 0
TIME_UNSYNCED = 1
TIME_HW_RTC = 2
TIME_NTP_SYNCED = 3

# ─── header TLV types (§2.2) — a separate namespace from record types ────
TLV_ORIGIN_ROLE = 0x0001
TLV_ORIGIN_MODEL_DIGEST = 0x0002
TLV_ORIGIN_CONFIG_DIGEST = 0x0003
TLV_MERKLE_TREE_HASH = 0x0011
TLV_MERKLE_LEAF_COUNT = 0x0012
TLV_SHED_CLASS = 0x0020
TLV_SHED_COUNT = 0x0021
TLV_SHED_WINDOW_NS = 0x0022
TLV_WITNESS_KIND = 0x0030
TLV_WITNESS_RANGE_LO = 0x0031
TLV_WITNESS_RANGE_HI = 0x0032
TLV_WITNESS_RECEIPT = 0x0033
TLV_SHRED_KEY_ID = 0x0040
TLV_ANCHOR_HEAD = 0x0050

# ─── AGGREGATE body TLV types (§3.2) — their own namespace again ─────────
AGG_WINDOW_NS = 0x0001
AGG_SAMPLE_COUNT = 0x0002
AGG_FLOW_MIN_MILLI = 0x0003
AGG_FLOW_MAX_MILLI = 0x0004
AGG_FLOW_MEAN_MILLI = 0x0005


class MalformedRecord(ValueError):
    """A record that cannot be parsed at all (bad magic, truncated fixed
    header, TLV overrun). Distinct from a chain *break*: this is a parsing
    failure, not a verification verdict."""


def encode_tlvs(tlvs: list[tuple[int, bytes]]) -> bytes:
    """Serialize a TLV sequence exactly as §2.2 lays it out."""
    return b"".join(struct.pack("<HH", t, len(v)) + v for t, v in tlvs)


def decode_tlvs(buf: bytes) -> list[tuple[int, bytes]]:
    """Parse a TLV sequence.

    Raises ``MalformedRecord`` on a truncated item or one that overruns the
    container — §2.2 requires the last item to end exactly at
    ``header_len``. Unknown TLV *types* are returned as-is, never rejected:
    they are opaque bytes to a verifier that does not know them (§7.6).
    """
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(buf):
        if off + 4 > len(buf):
            raise MalformedRecord("truncated TLV header")
        t, ln = struct.unpack_from("<HH", buf, off)
        off += 4
        if off + ln > len(buf):
            raise MalformedRecord("TLV value overruns its container")
        out.append((t, buf[off : off + ln]))
        off += ln
    return out


def nonce_for(seq: int) -> bytes:
    """Deterministic per-record nonce (§4.4): 4 zero bytes ‖ seq (u64 LE).

    Unique per record by construction, because ``seq`` never repeats within
    a chain (§4.1). Leaks only the record's position, which the cleartext
    header states anyway. The corollary in §4.4 is binding: a key MUST NOT
    be reused across chains with independent seq spaces.
    """
    return b"\x00" * 4 + struct.pack("<Q", seq)


def aad_for(seq: int, boot_id: bytes, record_type: int) -> bytes:
    """AEAD associated data (§4.4): binds a ciphertext to its chain slot,
    so bodies cannot be swapped between records."""
    return struct.pack("<Q", seq) + boot_id + struct.pack("<H", record_type)


@dataclass
class Header:
    """One record header — the unit the chain hash covers (§1.2).

    Field order, widths and offsets follow §2.1 exactly; ``encode`` is the
    canonical serialization, and there is deliberately no other one.
    """

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
        return (
            struct.pack(
                _FIXED,
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
            + tlv_bytes
        )

    @classmethod
    def decode(cls, hb: bytes) -> Header:
        """Parse a complete header (fixed part + TLVs).

        ``hb`` must be exactly the header bytes — §2.1 requires
        ``header_len`` to equal the actual byte count, and a mismatch here
        is ``MalformedRecord`` because a reader that cannot trust
        ``header_len`` cannot find the next record (§7.6 freezes it for
        that reason).
        """
        if len(hb) < FIXED_HEADER_LEN:
            raise MalformedRecord("header shorter than the fixed 156 bytes")
        (
            magic,
            ver,
            hlen,
            rtype,
            tier,
            time_trust,
            seq,
            boot_id,
            prev_hash,
            span_id,
            parent_span_id,
            monotonic_ns,
            wall_clock_ns,
            key_id,
            body_len,
            body_digest,
        ) = struct.unpack_from(_FIXED, hb, 0)
        if magic != MAGIC:
            raise MalformedRecord("bad magic")
        if hlen != len(hb):
            raise MalformedRecord(f"header_len={hlen} but {len(hb)} bytes supplied")
        if ver != FORMAT_VERSION:
            # Frozen fields only (§7.6): the caller may still chain-verify
            # the raw bytes, but this dataclass claims full interpretation.
            raise MalformedRecord(f"format_version={ver} is not version 1")
        hdr = cls(
            record_type=rtype,
            seq=seq,
            boot_id=boot_id,
            prev_hash=prev_hash,
            assurance_tier=tier,
            time_trust=time_trust,
            span_id=span_id,
            parent_span_id=parent_span_id,
            monotonic_ns=monotonic_ns,
            wall_clock_ns=wall_clock_ns,
            key_id=key_id,
            body_len=body_len,
            body_digest=body_digest,
            tlvs=decode_tlvs(hb[FIXED_HEADER_LEN:hlen]),
        )
        return hdr


def record_hash(header_bytes: bytes) -> bytes:
    """SHA-256 over the header bytes — and nothing else (§1.2).

    The body is bound in through ``body_digest`` *inside* the header, which
    is what lets chain verification proceed without keys or bodies, and
    lets a crypto-shredded body leave the chain intact.
    """
    import hashlib

    return hashlib.sha256(header_bytes).digest()


def body_digest_of(body: bytes) -> bytes:
    """SHA-256 over the body exactly as stored (§4.4), both shapes alike:
    the digest never knows whether it covered ciphertext or cleartext."""
    import hashlib

    return hashlib.sha256(body).digest()


def iter_records(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Walk a file container (§2.4): records concatenated back-to-back.

    Yields ``(header_bytes, body_bytes)`` per record, using only the frozen
    fields (``magic``, ``header_len``, ``body_len``) to find boundaries —
    so records of unknown versions and types are yielded, not rejected
    (§7.6). Raises ``MalformedRecord`` on a truncated tail, naming the
    offset: §2.4 requires the final record to end exactly at end-of-file,
    and a truncated tail is a file-level defect, not a chain break at some
    earlier record.
    """
    off = 0
    n = len(data)
    while off < n:
        if off + FIXED_HEADER_LEN > n:
            raise MalformedRecord(f"truncated tail: fixed header cut at offset {off}")
        if data[off : off + 4] != MAGIC:
            raise MalformedRecord(f"bad magic at offset {off}")
        (hlen,) = struct.unpack_from("<H", data, off + 6)
        if hlen < FIXED_HEADER_LEN:
            raise MalformedRecord(f"header_len={hlen} below fixed size at offset {off}")
        (blen,) = struct.unpack_from("<I", data, off + 120)
        end = off + hlen + blen
        if end > n:
            raise MalformedRecord(f"truncated tail: record at offset {off} cut short")
        yield data[off : off + hlen], data[off + hlen : end]
        off = end
