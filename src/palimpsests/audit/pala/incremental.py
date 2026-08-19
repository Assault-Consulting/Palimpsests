# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The single implementation of the §7.1 per-record rules.

``verify_headers`` (batch) and ``TailingReader`` (live) both drive one
``IncrementalVerifier``: the §7.1 chain rules live in exactly one place, so
a chain verified after the fact and the same chain verified record by
record produce byte-identical answers. The property test
``batch(N) ≡ N × incremental`` enforces that, and the existing differential
test against ``palaudit_ref.py`` plus the §8 vectors guard the refactor.

The same pass accumulates the **advisory** channel — cheap, header-only
signals (clock and monotonic regressions within a boot, mid-boot
time-trust changes, a chain with no ANCHOR). Advisory items are never a
verdict: they do not touch ``chain_ok``, ``complete_to_anchor``, or exit
codes. 0.8 (WS3) adds items to this same channel; its shape is fixed here.

Stdlib-only, header-only, key-free — the same discipline as the codec.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    GCM_TAG_LEN,
    MAGIC,
    NONCE_LEN,
    RT_ANCHOR,
    RT_GENESIS,
    RT_SPAN_END,
    RT_SPAN_START,
    TIME_NTP_SYNCED,
    TIME_UNKNOWN,
    ZERO32,
    MalformedRecord,
    decode_tlvs,
    record_hash,
)

__all__ = ["Advisory", "AdvisoryItem", "IncrementalVerifier"]

# Header field offsets used by the advisory pass (fixed part, §2.1). The
# fixed header is frozen (§7.6), so these are valid for any FORMAT_VERSION 1
# record regardless of its record_type.
_OFF_TIME_TRUST = 11
_OFF_BOOT_ID = slice(20, 36)
_OFF_PREV_HASH = slice(36, 68)
_OFF_MONOTONIC = 100
_OFF_WALL = 108
_OFF_SPAN_ID = slice(68, 84)
_ZERO16 = b"\x00" * 16


@dataclass(frozen=True)
class AdvisoryItem:
    """One non-verdict observation about the chain."""

    code: str
    at_seq: int | None
    boot_id: bytes | None
    detail: str


@dataclass(frozen=True)
class Advisory:
    """The advisory channel: signals, never a verdict.

    Advisory items never affect ``chain_ok``, ``complete_to_anchor``, or
    exit codes. The in-band limit is inherent: a writer that lies
    *consistently* with both its clocks is undetectable from inside the
    log — advisory reports what the record stream shows, not ground truth.
    """

    items: list[AdvisoryItem] = field(default_factory=list)


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


class _AdvisoryAccumulator:
    """Header-only advisory signals, gathered in the one verification pass.

    Boot-scoped: monotonic and wall clocks are compared only within a single
    ``boot_id`` run. A clock reset at a BOOT boundary is normal (§4.2) and is
    never reported — the resume chains from PR #105 are the fixture for
    exactly this distinction.
    """

    def __init__(self) -> None:
        self._items: list[AdvisoryItem] = []
        self._observed = 0
        self._any_anchor = False
        self._boot: bytes | None = None
        self._boot_time_trust: int | None = None
        self._last_mono: int | None = None
        self._last_wall: int | None = None  # last *non-zero* wall in this boot
        # Span pairing (independent run #5 finding): §3.1 promises a crash
        # leaves a visibly unclosed span, and this channel is where that
        # visibility is operationalized — as advisories, never a verdict.
        self._span_started: dict[bytes, int] = {}
        self._span_ended: set[bytes] = set()
        self._span_referenced: dict[bytes, int] = {}

    def observe(self, hb: bytes) -> None:
        rtype = struct.unpack_from("<H", hb, 8)[0]
        time_trust = hb[_OFF_TIME_TRUST]
        boot_id = bytes(hb[_OFF_BOOT_ID])
        (seq,) = struct.unpack_from("<Q", hb, 12)
        (mono,) = struct.unpack_from("<Q", hb, _OFF_MONOTONIC)
        (wall,) = struct.unpack_from("<q", hb, _OFF_WALL)

        self._observed += 1
        if rtype == RT_ANCHOR:
            self._any_anchor = True

        span_id = bytes(hb[_OFF_SPAN_ID])
        if span_id != _ZERO16:
            if rtype == RT_SPAN_START:
                self._span_started.setdefault(span_id, seq)
            elif rtype == RT_SPAN_END:
                self._span_ended.add(span_id)
            else:
                self._span_referenced.setdefault(span_id, seq)

        if boot_id != self._boot:
            # New boot: reset the per-boot baselines. Clocks reset at a
            # boot boundary are expected and never compared across it.
            self._boot = boot_id
            self._boot_time_trust = time_trust
            self._last_mono = mono
            self._last_wall = wall if wall != 0 else None
            return

        if time_trust != self._boot_time_trust:
            self._items.append(
                AdvisoryItem(
                    code="mid_boot_time_trust_change",
                    at_seq=seq,
                    boot_id=boot_id,
                    detail=f"time_trust {self._boot_time_trust} → {time_trust} within a boot",
                )
            )
            self._boot_time_trust = time_trust

        if self._last_mono is not None and mono < self._last_mono:
            self._items.append(
                AdvisoryItem(
                    code="mono_regression_in_boot",
                    at_seq=seq,
                    boot_id=boot_id,
                    detail=f"monotonic_ns {self._last_mono} → {mono} within a boot",
                )
            )
        self._last_mono = mono

        if wall != 0:
            if self._last_wall is not None and wall < self._last_wall:
                self._items.append(
                    AdvisoryItem(
                        code="wall_regression_in_boot",
                        at_seq=seq,
                        boot_id=boot_id,
                        detail=f"wall_clock_ns {self._last_wall} → {wall} within a boot",
                    )
                )
            self._last_wall = wall

    def finish(self) -> Advisory:
        for span_id, seq in sorted(
            self._span_started.items(), key=lambda kv: kv[1]
        ):
            if span_id not in self._span_ended:
                self._items.append(
                    AdvisoryItem(
                        code="span_unclosed",
                        at_seq=seq,
                        boot_id=None,
                        detail=(
                            f"SPAN_START {span_id.hex()[:16]}… at seq {seq} "
                            "has no SPAN_END — §3.1's crash evidence, surfaced"
                        ),
                    )
                )
        for span_id, seq in sorted(
            self._span_referenced.items(), key=lambda kv: kv[1]
        ):
            if span_id not in self._span_started:
                self._items.append(
                    AdvisoryItem(
                        code="span_unopened",
                        at_seq=seq,
                        boot_id=None,
                        detail=(
                            f"span {span_id.hex()[:16]}… is referenced from "
                            f"seq {seq} but no SPAN_START exists for it"
                        ),
                    )
                )
        if self._observed and not self._any_anchor:
            self._items.append(
                AdvisoryItem(
                    code="anchor_never_written",
                    at_seq=None,
                    boot_id=None,
                    detail="the chain carries no ANCHOR record",
                )
            )
        return Advisory(items=list(self._items))


class IncrementalVerifier:
    """Fold the §7.1 rules over headers, one record at a time.

    ``AuditReader.verify()`` constructs one, feeds N headers, and reads the
    result; ``TailingReader`` holds one long-lived instance and steps it as
    records arrive. There is no second implementation of these rules to keep
    in agreement — the point of the refactor.

    An unparseable record boundary (bad magic or a short fixed header) is a
    break at the current position and *halts* the verifier: nothing past an
    unfindable boundary can be attributed to a seq. The driver checks
    ``halted`` and stops feeding.
    """

    def __init__(self, *, known_types) -> None:
        self._known_types = known_types
        self._prev = ZERO32
        self._expected_seq: int | None = None
        self._count = 0
        self._halted = False
        self._breaks: list[int] = []
        self._gaps: list[int] = []
        self._violations: list[tuple[int, str]] = []
        self._uninterpretable: list[int] = []
        self._seen: list[bytes] = []
        self._advisory = _AdvisoryAccumulator()

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def head(self) -> bytes:
        return self._prev

    @property
    def count(self) -> int:
        return self._count

    @property
    def seen(self) -> list[bytes]:
        return self._seen

    def step(self, hb: bytes) -> None:
        """Apply the frozen §7.1 pseudocode to one record header."""
        if self._halted:
            return
        index = self._count  # container position == records processed so far

        if len(hb) < FIXED_HEADER_LEN or hb[:4] != MAGIC:
            # Unparseable at all: report the position and halt — nothing
            # after an unfindable boundary can be attributed to a seq.
            self._breaks.append(self._count)
            self._halted = True
            return

        ver, hlen, rtype = struct.unpack_from("<HHH", hb, 4)
        if hlen != len(hb):
            self._violations.append(
                (self._count, f"header_len={hlen} but {len(hb)} bytes supplied")
            )
        (seq,) = struct.unpack_from("<Q", hb, 12)

        # §4.2 — "no predecessor" and "predecessor removed" must be
        # distinguishable; that is the entire reason GENESIS is a type.
        if index == 0:
            if rtype != RT_GENESIS:
                # §4.2 / §8: a first record that is not GENESIS is exactly ONE
                # violation at position 0 — a property of the chain, not of
                # the record's seq — with no break and no zero-prev demand on
                # a non-GENESIS record (freeze-candidate run #4).
                self._violations.append(
                    (0, "chain does not start with a GENESIS record")
                )
            elif hb[_OFF_PREV_HASH] != ZERO32:
                self._violations.append(
                    (seq, "GENESIS must have prev_hash = 32 zero bytes")
                )
        elif hb[_OFF_PREV_HASH] != self._prev:
            # The link check compares only records that have a predecessor
            # in the file (§7.1 as aligned at the freeze-candidate run).
            self._breaks.append(seq)

        # §4.1 — a gap in seq is a break, whether or not the hashes link.
        if self._expected_seq is not None and seq != self._expected_seq:
            self._gaps.append(seq)
        self._expected_seq = seq + 1

        if ver != FORMAT_VERSION or rtype not in self._known_types:
            self._uninterpretable.append(seq)
        else:
            self._violations.extend(_semantic_checks(hb, seq, rtype, index))
            try:
                decode_tlvs(hb[FIXED_HEADER_LEN:hlen])
            except MalformedRecord as e:
                self._violations.append((seq, f"malformed TLV: {e}"))

        # Advisory: header-only signals, only for records we can interpret.
        if ver == FORMAT_VERSION:
            self._advisory.observe(hb)

        self._prev = record_hash(hb)
        self._seen.append(self._prev)
        self._count += 1

    def result(self):
        """The §7.1 verdict — identical shape to the pre-refactor result."""
        from palimpsests.audit.pala.verify import VerifyResult

        return VerifyResult(
            chain_ok=not self._breaks and not self._gaps and not self._violations,
            count=self._count,
            head=self._prev,
            breaks=list(self._breaks),
            gaps=list(self._gaps),
            violations=list(self._violations),
            uninterpretable=list(self._uninterpretable),
        )

    def advisory(self) -> Advisory:
        return self._advisory.finish()
