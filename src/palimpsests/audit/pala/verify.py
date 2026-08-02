"""PALA-1 chain verification — the three questions of §7, kept separate.

Verification answers three different questions with three different inputs,
and this module refuses to collapse them into one boolean:

1. *Is what I hold internally consistent?* — needs nothing (§7.1)
2. *Is what I hold all of it?* — needs an anchor from outside the log (§7.2)
3. *Did this history exist at time T?* — needs a witness receipt (§7.3;
   out of scope here, the receipt follows the witness's own protocol)

``chain_ok`` means **internally consistent, nothing more**: §7.1 cannot see
a truncated tail, because dropping the last N records leaves a perfectly
linked chain with a different head and no other trace. Completeness is a
separate field with a separate answer, including "not checked" — never
silently "passed".

Stdlib-only, header-only, key-free by design.
"""
from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    GCM_TAG_LEN,
    KNOWN_RECORD_TYPES,
    MAGIC,
    NONCE_LEN,
    RT_GENESIS,
    TIME_NTP_SYNCED,
    TIME_UNKNOWN,
    ZERO32,
    MalformedRecord,
    decode_tlvs,
    record_hash,
)

__all__ = ["VerifyResult", "verify_headers"]


@dataclass
class VerifyResult:
    """The three answers, plus the diagnostics an auditor acts on."""

    #: True iff breaks, gaps and violations are all empty. Internal
    #: consistency only — see the module docstring.
    chain_ok: bool
    count: int
    head: bytes
    #: Seqs where prev_hash does not name the preceding record (§4.1), or
    #: where the chain's start rule is violated (§4.2).
    breaks: list[int] = field(default_factory=list)
    #: Seqs where the sequence number jumped. A gap is a break whether or
    #: not the hashes link (§4.1) — a keyholder can rebuild a shorter,
    #: perfectly linked chain, and only the gap betrays it.
    gaps: list[int] = field(default_factory=list)
    #: (seq, reason) for normative MUSTs violated on records we claim to
    #: understand (§7.4). Defective record, possibly sound chain around it.
    violations: list[tuple[int, str]] = field(default_factory=list)
    #: Seqs of records with an unknown format_version or record_type —
    #: chain-checked, reported, never rejected (§7.6).
    uninterpretable: list[int] = field(default_factory=list)
    #: None = no anchor supplied, completeness NOT checked (§7.2). This is
    #: reported as "not checked", never as passing.
    complete_to_anchor: bool | None = None
    #: When the anchor names a record inside the chain but not the head:
    #: how many records sit past the anchored head. An *unanchored tail*
    #: (a crash between write and anchoring, an anchor-store outage, or a
    #: writer without anchor access) — a different diagnosis from a
    #: replacement, and the difference is what the operator investigates.
    anchor_lag: int | None = None
    anchor_reason: str | None = None


def _semantic_checks(hb: bytes, seq: int, rtype: int, index: int) -> list[tuple[int, str]]:
    """The §7.4 MUSTs, checkable on a record whose type we understand.

    Never applied to unknown versions or types (§7.6): those checks belong
    to a version this verifier does not claim.
    """
    out: list[tuple[int, str]] = []
    time_trust = hb[11]
    (wall_clock_ns,) = struct.unpack_from("<q", hb, 108)
    (key_id,) = struct.unpack_from("<I", hb, 116)
    (body_len,) = struct.unpack_from("<I", hb, 120)
    body_digest = hb[124:156]

    # §5: "I do not know the time" must not carry a confident timestamp.
    if time_trust == TIME_UNKNOWN and wall_clock_ns != 0:
        out.append((seq, "time_trust=UNKNOWN requires wall_clock_ns=0"))
    if time_trust > TIME_NTP_SYNCED:
        out.append((seq, f"time_trust={time_trust} is not a defined value"))

    # §2.1: empty body ⟺ zero digest.
    if body_len == 0 and body_digest != ZERO32:
        out.append((seq, "body_len=0 requires body_digest = 32 zero bytes"))
    if body_len != 0 and body_digest == ZERO32:
        out.append((seq, "non-empty body with an all-zero body_digest"))

    # §4.4: an encrypted body carries a nonce and a tag inside body_len.
    if key_id != 0 and 0 < body_len < NONCE_LEN + GCM_TAG_LEN:
        out.append((seq, f"encrypted body_len={body_len} is shorter than nonce+tag"))

    # §4.2: genesis is a position, not just a type.
    if rtype == RT_GENESIS and index != 0:
        out.append((seq, "GENESIS record at a non-initial position"))

    return out


def verify_headers(
    headers: Iterable[bytes],
    *,
    known_types: frozenset[int] = KNOWN_RECORD_TYPES,
    expected_head: bytes | None = None,
) -> VerifyResult:
    """Header-only verification per §7.1, with §7.2 when an anchor is given.

    ``expected_head`` is the anchor: the head this chain is supposed to
    have, obtained from **outside** the log — a local anchor store, or the
    head covered by the newest witness receipt. Without it, tail
    truncation is undetectable and ``complete_to_anchor`` stays ``None``;
    that is not a limitation of this function, it is why anchors exist.
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
        if len(hb) < FIXED_HEADER_LEN or hb[:4] != MAGIC:
            # Unparseable at all: report the position and stop — nothing
            # after an unfindable boundary can be attributed to a seq.
            breaks.append(count)
            break
        ver, hlen, rtype = struct.unpack_from("<HHH", hb, 4)
        if hlen != len(hb):
            violations.append((count, f"header_len={hlen} but {len(hb)} bytes supplied"))
        (seq,) = struct.unpack_from("<Q", hb, 12)

        # §4.2 — "no predecessor" and "predecessor removed" must be
        # distinguishable; that is the entire reason GENESIS is a type,
        # and a rule that is not checked buys nothing.
        if index == 0:
            if rtype != RT_GENESIS:
                breaks.append(seq)
                violations.append((seq, "chain does not start with a GENESIS record"))
            if hb[36:68] != ZERO32:
                violations.append((seq, "GENESIS must have prev_hash = 32 zero bytes"))

        if hb[36:68] != prev:
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
            except MalformedRecord as e:
                violations.append((seq, f"malformed TLV: {e}"))

        prev = record_hash(hb)
        seen.append(prev)
        count += 1

    result = VerifyResult(
        chain_ok=not breaks and not gaps and not violations,
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
                result.anchor_lag = len(seen) - seen.index(expected_head) - 1
                result.anchor_reason = (
                    f"chain extends {result.anchor_lag} record(s) beyond the anchored "
                    "head — an unanchored tail, not a replacement"
                )
            else:
                result.anchor_reason = (
                    "the anchored head names no record in this chain — the log was "
                    "replaced, rolled back, or truncated"
                )

    return result
