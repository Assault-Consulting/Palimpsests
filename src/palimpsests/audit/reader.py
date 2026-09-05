# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The reading-side facade of the audit package.

Every fact a shell renders — the Auditor, the CLI, a deployment script —
comes from ``AuditReader``; shells never parse wire bytes. The facade's one
external dependency is the trusted head, and it arrives only through the
``AnchorSource`` protocol (``anchors``): the verifier never knows where
anchors live.

One walk, shared. The container is scanned once on construction; record
*bodies* are decoded when a caller asks for records or origins — and,
today, also by ``verify()``. ``spans()``, ``boots()`` and the safety
section read headers only (SAFETY bodies alone for the latter) and use
``verify()``'s cache when it exists (U14). A truncated tail (the file
ends mid-record) is reported as exactly that (``Diagnosis`` pattern
``truncated_tail``, §2.4), never as a chain break at an earlier record.

``verify()`` is not header-only. Two of the three things it does are:
the §7.1 chain check and the ``IncrementalVerifier`` advisory come from
one pass over ``self._headers`` and touch no body. The third is not.
``_referential_advisories()`` resolves an ack to its candidate and a
shred to its targets, which needs a record's ``kind`` — a body-decoded
field carrying inference-profile values (``profiles/inference.md`` §3,
§4). That pass is bounded (U14): it decodes the records that carry a
reference and the records they name, found by an in-place probe of
each body's first TLV, so its cost follows the number of references
rather than the length of the chain — and it never materialises the
chain into the decode cache.

The checks themselves belong in this layer: ``inference.md`` §4 asks for
exactly them, as reader advisories, never chain violations. What is open
is their placement inside the method that answers the core's three
questions — ``PALA-1.md`` §3.4 describes that answer as
profile-independent, and ``inference.md`` §3.1 says the envelope
verifier never reads kinds at all. The advisory channel is this
package's own addition above §7 rather than something §7 specifies, so
this is a question about where the boundary is drawn in *this* API, not
a conformance defect. Moving the pass would change what
``Verification.advisory`` contains, so it is a decision for the
maintainers rather than something to do quietly. Tracked as U14.

The module path is chosen so extraction into ``palimpsests-audit`` renames
nothing: this facade sits above ``pala`` (the wire codec) and consumes only
its public surface, plus the writer's EVT_KIND constant table as the single
source for kind names (§10.5 — the ints are imported, never re-typed).
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from palimpsests.audit.anchors import (
    AnchorAttempt,
    AnchorReading,
    AnchorSource,
    AnchorSourceError,
)
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    MAGIC,
    RT_AGGREGATE,
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_KEY_SHRED,
    RT_MERKLE,
    RT_SAFETY,
    RT_SHED,
    RT_SPAN_END,
    RT_SPAN_START,
    RT_WITNESS,
    TLV_ORIGIN_CONFIG_DIGEST,
    TLV_ORIGIN_MODEL_DIGEST,
    TLV_ORIGIN_ROLE,
    TLV_SHRED_KEY_ID,
    ZERO16,
    Header,
    MalformedRecord,
    decode_tlvs,
)
from palimpsests.audit.pala.codec import record_hash as _record_hash
from palimpsests.audit.pala.incremental import Advisory, AdvisoryItem
from palimpsests.audit.pala.verify import VerifyResult, verify_headers_with_advisory
from palimpsests.audit.pala_writer import (
    DISP_ACKNOWLEDGED,
    DISP_DISMISSED,
    DISP_ESCALATED,
    EVT_DETAIL,
    EVT_DISPOSITION,
    EVT_KIND,
    EVT_OPERATOR_ID,
    EVT_REF_HASH,
    EVT_REF_SEQ,
    KIND_GUARD_PREFIX_RELEASE,
    KIND_GUARD_STATE_REJECT,
    KIND_GUARD_TOOL_LOOP_LIMIT,
    KIND_INCIDENT_CANDIDATE,
    KIND_KV_RESTORE,
    KIND_KV_SAVE,
    KIND_MODEL_LOAD,
    KIND_MODEL_UNLOAD,
    KIND_OVERSIGHT_ACK,
    KIND_PREFIX_COPY,
    KIND_PREFIX_WARM,
    KIND_RECOVERY_TRUNCATED_TAIL,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
    KIND_TOOLS_OFFERED_NO_CALL,
    SHRED_TARGET_SEQS,
)

__all__ = [
    "AuditReader",
    "Verification",
    "Diagnosis",
    "DecodedRecord",
    "SpanView",
    "BootView",
    "OriginView",
    "decode_record",
]

_TYPE_NAMES = {
    RT_GENESIS: "GENESIS",
    RT_BOOT: "BOOT",
    RT_SPAN_START: "SPAN_START",
    RT_SPAN_END: "SPAN_END",
    RT_EVENT: "EVENT",
    RT_MERKLE: "MERKLE",
    RT_AGGREGATE: "AGGREGATE",
    RT_SHED: "SHED",
    RT_SAFETY: "SAFETY",
    RT_ANCHOR: "ANCHOR",
    RT_WITNESS: "WITNESS",
    RT_KEY_SHRED: "KEY_SHRED",
}

# §10.5: single source for kind names — the values come from the writer's
# table (imported), the labels are this layer's presentation.
_KIND_NAMES = {
    KIND_MODEL_LOAD: "MODEL_LOAD",
    KIND_MODEL_UNLOAD: "MODEL_UNLOAD",
    KIND_KV_SAVE: "KV_SAVE",
    KIND_KV_RESTORE: "KV_RESTORE",
    KIND_PREFIX_COPY: "PREFIX_COPY",
    KIND_PREFIX_WARM: "PREFIX_WARM",
    KIND_RECOVERY_TRUNCATED_TAIL: "RECOVERY_TRUNCATED_TAIL",
    KIND_GUARD_PREFIX_RELEASE: "GUARD_PREFIX_RELEASE",
    KIND_GUARD_STATE_REJECT: "GUARD_STATE_REJECT",
    KIND_INCIDENT_CANDIDATE: "INCIDENT_CANDIDATE",
    KIND_OVERSIGHT_ACK: "OVERSIGHT_ACK",
    KIND_TOOL_CALL: "TOOL_CALL",
    KIND_TOOLS_OFFERED_NO_CALL: "TOOLS_OFFERED_NO_CALL",
    KIND_TOOL_RESULT: "TOOL_RESULT",
    KIND_GUARD_TOOL_LOOP_LIMIT: "GUARD_TOOL_LOOP_LIMIT",
}

# Only these record types carry the profile EVT_KIND scheme in their body;
# other bodies (e.g. AGGREGATE) reuse tag 0x0001 for a different field, so
# kind resolution must never be applied to them (§10.5).
_KIND_BEARING = frozenset({RT_EVENT, RT_SAFETY})

# EVT_DISPOSITION's own three values (an OVERSIGHT_ACK's body), named the
# same way kind is — the number is what a caller checks against, the name
# is what a person reads.
_DISP_NAMES = {
    DISP_ACKNOWLEDGED: "ACKNOWLEDGED",
    DISP_DISMISSED: "DISMISSED",
    DISP_ESCALATED: "ESCALATED",
}

_PREFIX_ABSENT = "chain does not start with a GENESIS record"

# The kinds whose bodies carry an EVT_REF_SEQ/EVT_REF_HASH pair the
# referential pass resolves (profile §4, r2/r3). KEY_SHRED references by
# record type, not kind, and is handled beside these.
_REFERENCING_KINDS = frozenset(
    {KIND_INCIDENT_CANDIDATE, KIND_OVERSIGHT_ACK, KIND_TOOL_RESULT, KIND_GUARD_TOOL_LOOP_LIMIT}
)


class _HeaderFields:
    """The header fields the structural views read, unpacked in place."""

    __slots__ = ("record_type", "time_trust", "seq", "boot_id", "span_id", "parent_span_id")

    def __init__(self, record_type, time_trust, seq, boot_id, span_id, parent_span_id):
        self.record_type = record_type
        self.time_trust = time_trust
        self.seq = seq
        self.boot_id = boot_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id


_VIEW_FIELDS = struct.Struct("<4sHHHBBQ16s32s16s16s")  # §2.1 prefix, through parent_span_id


def _header_fields(hb: bytes) -> _HeaderFields | None:
    """``Header.decode``'s accept/reject decision and the view fields,
    without constructing the ``Header``: same magic, ``header_len`` and
    ``format_version`` checks, and the same TLV bounds walk (§2.2 — a
    truncated item or one overrunning ``header_len`` rejects), so the
    set of records the views skip is exactly the set whose ``Header``
    would not decode."""
    if len(hb) < FIXED_HEADER_LEN:
        return None
    magic, ver, hlen, rtype, _tier, tt, seq, boot_id, _prev, span_id, parent = (
        _VIEW_FIELDS.unpack_from(hb, 0)
    )
    if magic != MAGIC or hlen != len(hb) or ver != 1:
        return None
    off, end = FIXED_HEADER_LEN, len(hb)
    while off < end:
        if off + 4 > end:
            return None
        ln = struct.unpack_from("<H", hb, off + 2)[0]
        off += 4 + ln
        if off > end:
            return None
    return _HeaderFields(rtype, tt, seq, boot_id, span_id, parent)


class _LazyRecords:
    """A seq-keyed view over the chain that decodes a record the first
    time it is asked for — the ``by_seq`` mapping the referential checks
    consume, without the whole-chain decode that used to build it.

    Only ``get`` and ``at`` exist, because those are the two things the
    checks do: resolve a referenced seq, and read the referencing record.
    When the reader's full cache is warm, entries come from it.
    """

    __slots__ = ("_reader", "_pos", "_cache")

    def __init__(self, reader: AuditReader, pos_by_seq: dict[int, int]) -> None:
        self._reader = reader
        self._pos = pos_by_seq
        self._cache: dict[int, tuple[DecodedRecord, bytes]] = {}

    def at(self, index: int) -> DecodedRecord:
        entry = self._cache.get(index)
        if entry is None:
            entry = (self._reader._record_at(index), self._reader._headers[index])
            self._cache[index] = entry
        return entry[0]

    def get(self, seq: int) -> tuple[DecodedRecord, bytes] | None:
        index = self._pos.get(seq)
        if index is None:
            return None
        self.at(index)
        return self._cache[index]


@dataclass(frozen=True)
class DecodedRecord:
    """One record, decoded to the extent this layer understands it."""

    seq: int
    index: int
    record_type: int
    type_name: str | None  # None → record_type outside the known set (§7.6)
    header: Header | None  # None → header did not decode (unknown version)
    body_tlvs: list[tuple[int, bytes]] | None  # None: no body / encrypted / opaque
    kind: int | None  # EVT_KIND for an EVENT/SAFETY body, else None
    kind_name: str | None  # resolved per §10.5; None = unknown kind, reported
    record_hash: bytes  # SHA-256 over hb (§1.2) — always present, even
    # when header did not decode: the hash is over the raw header bytes,
    # which chain verification itself hashes regardless of whether this
    # layer could interpret their fields.
    detail: str | None  # EVT_DETAIL, UTF-8, on an EVENT/SAFETY body only
    # (§10.5, the same scope kind/kind_name use) — a record type outside
    # that set may carry its own, differently-tagged detail field (e.g.
    # KEY_SHRED's SHRED_DETAIL = 0x0003, a different tag under a
    # different body schema), which this field does not read.
    operator_id: bytes | None  # EVT_OPERATOR_ID, 16 opaque bytes, an
    # OVERSIGHT_ACK's own pseudonymous operator — the mapping to a
    # person lives with the deployer, outside the log (§ writer
    # docstring). Same kind-bearing scope as detail.
    disposition: int | None  # EVT_DISPOSITION, 0/1/2 — an OVERSIGHT_ACK's
    # own disposition. Same scope as operator_id.
    disposition_name: str | None  # resolved via _DISP_NAMES; None when
    # disposition is None, or is present but not one of the three
    # known values (a record this build cannot fully interpret).


@dataclass(frozen=True)
class SpanView:
    span_id: bytes
    parent_span_id: bytes
    start_seq: int
    end_seq: int | None  # None → visibly unclosed (§3.1), evidence not error
    record_seqs: list[int]


@dataclass(frozen=True)
class BootView:
    boot_id: bytes
    first_seq: int
    last_seq: int
    record_count: int
    time_trust_values: set[int]  # >1 element → mid-boot change, flagged
    recovery_seq: int | None  # RECOVERY_TRUNCATED_TAIL right after this BOOT


@dataclass(frozen=True)
class OriginView:
    role: str | None
    model_digest: bytes | None
    config_digest: bytes | None
    since_seq: int  # the MODEL_LOAD that made it active
    detail: str | None


@dataclass(frozen=True)
class Diagnosis:
    """One primary diagnosis, derived from chain + anchor (first match wins).

    ``narrative`` states *consistency* ("the evidence is consistent with…"),
    never intent; a consumer may override the sentence, never the pattern.
    """

    pattern: str
    at_seq: int | None
    expected: str | None
    narrative: str


@dataclass(frozen=True)
class Verification:
    chain: VerifyResult
    anchor: AnchorReading | None
    anchor_attempts: list[AnchorAttempt]
    complete_to_anchor: bool | None  # tri-state; None = not checked
    anchor_lag: int | None
    diagnosis: Diagnosis | None  # only when something failed
    advisory: Advisory  # always present, never a verdict


class AuditReader:
    """Read a PALA-1 container: verify it, and view its structure."""

    def __init__(self, data, *, anchor: AnchorSource | None = None) -> None:
        self._data = data
        self._anchor = anchor
        self._file = None
        self._mmap = None
        self._verification: Verification | None = None
        self._decoded: list[DecodedRecord] | None = None
        # Sparse decode cache for the bounded paths (verify()'s
        # referential pass, the safety section, the kind probe's
        # fallback): a record decoded once on demand is not decoded
        # again by the next caller. The full cache above supersedes it.
        self._partial: dict[int, DecodedRecord] = {}
        self._headers: list[bytes] = []
        self._body_spans: list[tuple[int, int]] = []
        self._truncated = False
        self._truncated_detail: str | None = None
        self._walk()

    # ── construction ────────────────────────────────────────────────────
    @classmethod
    def from_bytes(cls, data: bytes, *, anchor: AnchorSource | None = None) -> AuditReader:
        return cls(data, anchor=anchor)

    @classmethod
    def open(cls, path, *, anchor: AnchorSource | None = None) -> AuditReader:
        import mmap
        import os

        fh = open(path, "rb")
        size = os.fstat(fh.fileno()).st_size
        if size == 0:
            fh.close()
            return cls(b"", anchor=anchor)
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        obj = cls(mm, anchor=anchor)
        obj._file = fh
        obj._mmap = mm
        return obj

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> AuditReader:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── the one shared walk ─────────────────────────────────────────────
    def _walk(self) -> None:
        data = self._data
        n = len(data)
        off = 0
        while off < n:
            if off + FIXED_HEADER_LEN > n:
                self._truncated = True
                self._truncated_detail = f"fixed header cut at offset {off}"
                break
            if bytes(data[off : off + 4]) != MAGIC:
                self._truncated = True
                self._truncated_detail = f"bad magic at offset {off}"
                break
            (hlen,) = struct.unpack_from("<H", data, off + 6)
            if hlen < FIXED_HEADER_LEN:
                self._truncated = True
                self._truncated_detail = f"header_len={hlen} below fixed size at offset {off}"
                break
            (blen,) = struct.unpack_from("<I", data, off + 120)
            end = off + hlen + blen
            if end > n:
                self._truncated = True
                self._truncated_detail = f"record at offset {off} cut short"
                break
            self._headers.append(bytes(data[off : off + hlen]))
            self._body_spans.append((off + hlen, end))
            off = end

    # ── verification ────────────────────────────────────────────────────
    def verify(self) -> Verification:
        """The core's three questions, plus the advisory channel.

        The chain check (§7.1) and the ``IncrementalVerifier`` advisory
        come from one header pass. ``advisory`` additionally carries the
        referential items from :meth:`_referential_advisories`, a
        bounded body pass over the records that carry references and
        the records they name — see the module docstring and U14. The
        whole chain is never decoded here; the sparse cache keeps what
        was decoded for the report path.

        Cached: the first call pays, every call after it is free.

        Not thread-safe. Two callers arriving on a cold reader each run
        the passes and each hold their own transient state while they
        do — N callers, N runs. A caller serving concurrent requests
        should hold its own lock around this reader.
        """
        if self._verification is not None:
            return self._verification

        anchor_reading: AnchorReading | None = None
        anchor_attempts: list[AnchorAttempt] = []
        if self._anchor is not None:
            anchor_reading, anchor_attempts = self._resolve_anchor()

        expected = anchor_reading.head if anchor_reading is not None else None
        chain, header_advisory = verify_headers_with_advisory(
            self._headers, expected_head=expected
        )
        advisory = Advisory(items=header_advisory.items + self._referential_advisories())
        diagnosis = self._derive_diagnosis(chain)

        self._verification = Verification(
            chain=chain,
            anchor=anchor_reading,
            anchor_attempts=anchor_attempts,
            complete_to_anchor=chain.complete_to_anchor,
            anchor_lag=chain.anchor_lag,
            diagnosis=diagnosis,
            advisory=advisory,
        )
        return self._verification

    def head(self) -> bytes:
        return self.verify().chain.head

    def _resolve_anchor(self) -> tuple[AnchorReading | None, list[AnchorAttempt]]:
        src = self._anchor
        kind = getattr(src, "source_kind", "unknown")
        detail = getattr(src, "source_detail", "")
        try:
            reading = src.current_head()
        except AnchorSourceError as exc:
            return None, [
                AnchorAttempt(
                    source_kind=getattr(exc, "source_kind", kind),
                    source_detail=getattr(exc, "source_detail", detail),
                    outcome="error",
                    error=str(exc),
                )
            ]
        attempts = getattr(src, "last_attempts", None)
        if attempts is not None:
            return reading, list(attempts)
        outcome = "answered" if reading is not None else "absent"
        return reading, [AnchorAttempt(kind, detail, outcome, None)]

    def _referential_advisories(self) -> list[AdvisoryItem]:
        """Body-level referential integrity — advisory, never a violation.

        The r2 semantics reference other records (an ack names its
        candidate, an erasure note names its targets); whether those
        references resolve is *semantic* integrity, so a failure is an
        :class:`AdvisoryItem`, never a chain violation — the chain is
        sound either way (profile r2). Header-only verification (§7.1)
        cannot see any of this by design; it lives here, in the reader.

        Cross-boot references resolve naturally: the map is seq-indexed
        over the whole chain, and the r2 loop is explicitly allowed to
        close across a resume.

        Bounded (U14, PR-7): the pass decodes the records that *carry* a
        reference and the records they *name* — nothing else. Three
        phases: the seq→position map comes from header bytes; which
        records carry a reference comes from the in-place kind probe
        (a body's first TLV, no copy) and the record type; only those,
        and the targets they resolve to, are decoded. Cost scales with
        the number of references, not the length of the chain. If the
        whole chain is already decoded (a caller asked for ``records()``)
        that cache is used and nothing is decoded twice.

        The seq map keeps the same semantics as the dict of decoded
        records it replaces — position of a seq's first occurrence,
        record of its last — so a chain with duplicated seqs (a broken
        one) yields the same items in the same order as before.
        """
        headers = self._headers
        # phase 1 — seq → position, from header offset 12 (§2.1)
        pos_by_seq: dict[int, int] = {}
        for i, hb in enumerate(headers):
            pos_by_seq[struct.unpack_from("<Q", hb, 12)[0]] = i
        by_seq = _LazyRecords(self, pos_by_seq)

        # phase 2 — which records carry a reference: kind probe + record type
        items: list[AdvisoryItem] = []
        for i in pos_by_seq.values():
            hb = headers[i]
            rtype = struct.unpack_from("<H", hb, 8)[0]
            if rtype == RT_KEY_SHRED:
                dr = by_seq.at(i)
                if dr.body_tlvs is not None:
                    items.extend(self._check_shred_targets(dr, by_seq))
                continue
            if rtype not in _KIND_BEARING:
                continue
            if self._kind_probe(i, hb) not in _REFERENCING_KINDS:
                continue
            # phase 3 — decode the referencing record; its target is
            # decoded on demand inside the check, through ``by_seq``
            items.extend(self._check_reference(by_seq.at(i), by_seq))
        return items

    def _hash_verified_target(
        self,
        dr: DecodedRecord,
        by_seq: dict[int, tuple[DecodedRecord, bytes]],
    ) -> DecodedRecord | None:
        """``dr``'s own ``EVT_REF_SEQ`` / ``EVT_REF_HASH`` resolved to a
        record in the chain whose own hash matches — or ``None`` for
        every other case: no reference present, an unresolved seq, or a
        hash that does not match.

        The one check r2 resolution rests on, shared by
        :meth:`_check_reference` (which reports *why* a reference failed,
        so it still does its own extraction to build that message) and
        :meth:`acknowledged_candidates` (which only needs whether
        resolution succeeded). One definition of "resolves", not two —
        a second one is how a report could once call a candidate
        acknowledged by an ack whose hash the advisory channel was
        already flagging as wrong.
        """
        tlvs = dict(dr.body_tlvs or [])
        raw_seq = tlvs.get(EVT_REF_SEQ)
        raw_hash = tlvs.get(EVT_REF_HASH)
        if raw_seq is None or len(raw_seq) != 8 or raw_hash is None:
            return None
        (ref_seq,) = struct.unpack("<Q", raw_seq)
        target = by_seq.get(ref_seq)
        if target is None:
            return None
        target_dr, target_hb = target
        if _record_hash(target_hb) != raw_hash:
            return None
        return target_dr

    def _check_reference(
        self,
        dr: DecodedRecord,
        by_seq: dict[int, tuple[DecodedRecord, bytes]],
    ) -> list[AdvisoryItem]:
        tlvs = dict(dr.body_tlvs or [])
        raw_seq = tlvs.get(EVT_REF_SEQ)
        raw_hash = tlvs.get(EVT_REF_HASH)
        if raw_seq is None or len(raw_seq) != 8 or raw_hash is None:
            return []  # a candidate MAY omit the reference; nothing to resolve
        (ref_seq,) = struct.unpack("<Q", raw_seq)
        boot = dr.header.boot_id if dr.header is not None else None
        who = dr.kind_name or f"kind {dr.kind}"
        target = by_seq.get(ref_seq)
        if target is None:
            return [
                AdvisoryItem(
                    "reference_unresolved",
                    dr.seq,
                    boot,
                    f"{who} at seq {dr.seq} references seq {ref_seq}, "
                    "which is not in the chain",
                )
            ]
        target_dr = self._hash_verified_target(dr, by_seq)
        if target_dr is None:
            return [
                AdvisoryItem(
                    "reference_hash_mismatch",
                    dr.seq,
                    boot,
                    f"{who} at seq {dr.seq} references seq {ref_seq}, but the "
                    "referenced record's hash differs from the bound EVT_REF_HASH",
                )
            ]
        if dr.kind == KIND_OVERSIGHT_ACK and target_dr.kind != KIND_INCIDENT_CANDIDATE:
            return [
                AdvisoryItem(
                    "ack_target_not_a_candidate",
                    dr.seq,
                    boot,
                    f"OVERSIGHT_ACK at seq {dr.seq} resolves (hash-bound) to seq "
                    f"{ref_seq}, which is not an INCIDENT_CANDIDATE",
                )
            ]
        if (
            dr.kind in (KIND_TOOL_RESULT, KIND_GUARD_TOOL_LOOP_LIMIT)
            and target_dr.kind != KIND_TOOL_CALL
        ):
            # r3: a result MUST bind to its call, and the loop guard MAY
            # name the last call — either way, a resolved reference whose
            # target is not a TOOL_CALL is semantic drift worth surfacing.
            return [
                AdvisoryItem(
                    "tool_target_not_a_call",
                    dr.seq,
                    boot,
                    f"{who} at seq {dr.seq} resolves (hash-bound) to seq "
                    f"{ref_seq}, which is not a TOOL_CALL",
                )
            ]
        return []

    def _check_shred_targets(
        self,
        dr: DecodedRecord,
        by_seq: dict[int, tuple[DecodedRecord, bytes]],
    ) -> list[AdvisoryItem]:
        tlvs = dict(dr.body_tlvs or [])
        raw = tlvs.get(SHRED_TARGET_SEQS)
        if raw is None or len(raw) % 8 != 0:
            return []  # targets are optional (profile §8)
        shred_key = None
        if dr.header is not None:
            kid = _origin_tlv(dr.header, TLV_SHRED_KEY_ID)
            if kid is not None and len(kid) == 4:
                (shred_key,) = struct.unpack("<I", kid)
        boot = dr.header.boot_id if dr.header is not None else None
        items: list[AdvisoryItem] = []
        for i in range(0, len(raw), 8):
            (t_seq,) = struct.unpack_from("<Q", raw, i)
            target = by_seq.get(t_seq)
            if target is None:
                items.append(
                    AdvisoryItem(
                        "shred_target_unresolved",
                        dr.seq,
                        boot,
                        f"KEY_SHRED at seq {dr.seq} names target seq {t_seq}, "
                        "which is not in the chain",
                    )
                )
                continue
            target_dr, _ = target
            target_key = target_dr.header.key_id if target_dr.header is not None else None
            if shred_key is not None and target_key != shred_key:
                items.append(
                    AdvisoryItem(
                        "shred_target_key_mismatch",
                        dr.seq,
                        boot,
                        f"KEY_SHRED at seq {dr.seq} shreds key {shred_key}, but "
                        f"target seq {t_seq} carries key_id "
                        f"{target_key if target_key is not None else '?'} — that "
                        "body was not protected by the destroyed key",
                    )
                )
        return items

    def _derive_diagnosis(self, chain: VerifyResult) -> Diagnosis | None:
        if self._truncated:
            return Diagnosis(
                "truncated_tail",
                None,
                "a record ending exactly at end-of-file",
                "The container ends in the middle of a record; the evidence is "
                "consistent with a writer interrupted mid-write.",
            )
        if (0, _PREFIX_ABSENT) in chain.violations:
            return Diagnosis(
                "prefix_absent",
                0,
                "a GENESIS record at position 0",
                "The chain's prefix is absent — its first record is not a "
                "GENESIS; the evidence is consistent with an earlier segment "
                "having been removed.",
            )
        if chain.gaps:
            return Diagnosis(
                "seq_gap",
                chain.gaps[0],
                "contiguous sequence numbers",
                "A sequence number is skipped; the evidence is consistent with "
                "one or more records having been dropped.",
            )
        if chain.breaks:
            return Diagnosis(
                "chain_break",
                chain.breaks[0],
                "prev_hash naming the preceding record",
                "A record's prev_hash does not name its predecessor; the "
                "evidence is consistent with the history having been altered "
                "at this point.",
            )
        if chain.violations:
            seq, reason = chain.violations[0]
            return Diagnosis(
                "record_violation",
                seq,
                reason,
                "A record violates a normative MUST; the evidence is consistent "
                "with a defective writer or a tampered record.",
            )
        if chain.complete_to_anchor is False:
            if chain.anchor_lag is not None:
                return Diagnosis(
                    "unanchored_tail",
                    None,
                    "the head equal to the anchored head",
                    f"The chain extends {chain.anchor_lag} record(s) past the "
                    "anchored head; the evidence is consistent with an "
                    "unanchored tail (a crash between write and anchoring), "
                    "not a replacement.",
                )
            return Diagnosis(
                "replaced_or_rolled_back",
                None,
                "the anchored head present somewhere in the chain",
                "The anchored head names no record in this chain; the evidence "
                "is consistent with the log having been replaced or rolled back.",
            )
        return None

    # ── record & body decoding (lazy, cached) ───────────────────────────
    def _decoded_records(self) -> list[DecodedRecord]:
        if self._decoded is None:
            self._decoded = [self._decode(i, hb) for i, hb in enumerate(self._headers)]
        return self._decoded

    def _decode(self, index: int, hb: bytes) -> DecodedRecord:
        start, end = self._body_spans[index]
        body = bytes(self._data[start:end]) if end > start else b""
        return decode_record(index, hb, body)

    def _record_at(self, index: int) -> DecodedRecord:
        """One record, decoded at most once — from the full cache when a
        caller has materialised the chain, else from the sparse one."""
        cached = self._decoded
        if cached is not None:
            return cached[index]
        dr = self._partial.get(index)
        if dr is None:
            dr = self._decode(index, self._headers[index])
            self._partial[index] = dr
        return dr

    def records(self) -> Iterator[DecodedRecord]:
        yield from self._decoded_records()

    # ── header-only access (U14 PR-6) ───────────────────────────────────
    #
    # The structural views below read header fields only. Before this,
    # they went through ``_decoded_records()`` and so materialised every
    # record — body copy, TLV parse, ``DecodedRecord`` — to read
    # ``boot_id``, ``span_id`` and ``record_type`` out of the header.
    # When ``verify()`` has already warmed the cache the views use it
    # (identical objects, identical answers); when it has not, they
    # decode headers alone. The one body-dependent fact ``boots()``
    # needs — a ``RECOVERY_TRUNCATED_TAIL`` event — is read by a probe
    # that looks at the first TLV of a cleartext EVENT body in place,
    # without copying the body: the profile requires ``EVT_KIND`` to be
    # present and first (inference §3), so the probe is the same answer
    # ``decode_record`` gives, at a fraction of the work.

    def _headers_decoded(self) -> Iterator[tuple[int, bytes, _HeaderFields | None]]:
        """``(index, header_bytes, fields | None)`` for every record —
        ``None`` where the header does not decode (unknown version or
        malformed TLVs), exactly the records the views skip.

        Yields the full ``Header`` from the cache when the chain is
        materialised, else a ``_HeaderFields`` view read straight off the
        bytes with the same accept/reject rule as ``Header.decode`` — the
        fields the views use, without building a ``Header`` (and its TLV
        list) per record.
        """
        cached = self._decoded
        if cached is not None:
            for i, (dr, hb) in enumerate(zip(cached, self._headers, strict=True)):
                yield i, hb, dr.header
            return
        for i, hb in enumerate(self._headers):
            yield i, hb, _header_fields(hb)

    def _kind_probe(self, index: int, hb: bytes) -> int | None:
        """``EVT_KIND`` of record ``index`` read in place, or ``None``.

        Same answer as ``decode_record(...).kind`` for the records the
        profile describes: a cleartext (``key_id = 0``) EVENT/SAFETY body
        whose first TLV is ``EVT_KIND``. A body that does not open with
        ``EVT_KIND`` falls back to the full decode so an unusual but
        well-formed body is never misread; no body is copied on the
        common path.
        """
        cached = self._decoded
        if cached is not None:
            return cached[index].kind
        rtype = struct.unpack_from("<H", hb, 8)[0]
        if rtype not in _KIND_BEARING:
            return None
        key_id = struct.unpack_from("<I", hb, 116)[0]
        start, end = self._body_spans[index]
        if key_id != 0 or end - start < 6:
            return None
        t, ln = struct.unpack_from("<HH", self._data, start)
        if t == EVT_KIND and ln >= 2 and start + 4 + ln <= end:
            return struct.unpack_from("<H", self._data, start + 4)[0]
        return self._record_at(index).kind

    def safety_records(self) -> Iterator[DecodedRecord]:
        """Every SAFETY record, decoded — and only those.

        The report's safety section and :meth:`acknowledged_candidates`
        need bodies for SAFETY records alone (candidates and acks are
        both SAFETY kinds); decoding the whole chain to reach them was
        the cost this method removes. Uses the warm cache when
        ``verify()`` has built one.
        """
        for i, hb in enumerate(self._headers):
            if struct.unpack_from("<H", hb, 8)[0] != RT_SAFETY:
                continue
            yield self._record_at(i)

    # ── structural views ────────────────────────────────────────────────
    def spans(self) -> list[SpanView]:
        order: list[bytes] = []
        table: dict[bytes, dict] = {}
        for _i, _hb, header in self._headers_decoded():
            if header is None:
                continue
            sid = header.span_id
            if sid == ZERO16:
                continue
            entry = table.get(sid)
            if entry is None:
                entry = {"parent": ZERO16, "start": None, "end": None, "seqs": []}
                table[sid] = entry
                order.append(sid)
            entry["seqs"].append(header.seq)
            if header.record_type == RT_SPAN_START:
                entry["start"] = header.seq
                entry["parent"] = header.parent_span_id
            elif header.record_type == RT_SPAN_END:
                entry["end"] = header.seq
        out = []
        for sid in order:
            e = table[sid]
            start = e["start"] if e["start"] is not None else e["seqs"][0]
            out.append(SpanView(sid, e["parent"], start, e["end"], list(e["seqs"])))
        return out

    def boots(self) -> list[BootView]:
        order: list[bytes] = []
        table: dict[bytes, dict] = {}
        for i, hb, header in self._headers_decoded():
            if header is None:
                continue
            bid = header.boot_id
            entry = table.get(bid)
            if entry is None:
                entry = {
                    "first": header.seq,
                    "last": header.seq,
                    "count": 0,
                    "tt": set(),
                    "recovery": None,
                }
                table[bid] = entry
                order.append(bid)
            entry["last"] = header.seq
            entry["count"] += 1
            entry["tt"].add(header.time_trust)
            if (
                entry["recovery"] is None
                and header.record_type == RT_EVENT
                and self._kind_probe(i, hb) == KIND_RECOVERY_TRUNCATED_TAIL
            ):
                entry["recovery"] = header.seq
        return [
            BootView(
                bid,
                table[bid]["first"],
                table[bid]["last"],
                table[bid]["count"],
                table[bid]["tt"],
                table[bid]["recovery"],
            )
            for bid in order
        ]

    def origin_at(self, seq: int) -> OriginView | None:
        return self._origin_state_at(seq)[0]

    def unloaded_at(self, seq: int) -> bool:
        """Whether the last EVENT record at or before ``seq`` that set the
        origin state was a ``MODEL_UNLOAD`` — distinguishing "declared,
        then unloaded" from "never declared" when :meth:`origin_at`
        returns ``None`` for both.

        Read directly rather than assumed: ``KIND_MODEL_UNLOAD`` sets the
        running origin to ``None``, exactly the value it starts at before
        any ``MODEL_LOAD`` — the two collapse in :meth:`origin_at` alone.
        Additive rather than a change to that method's own return type:
        a caller that only ever checked "is it None" is unaffected, and
        one that needs to render the two states differently now can.
        """
        return self._origin_state_at(seq)[1]

    def _origin_state_at(self, seq: int) -> tuple[OriginView | None, bool]:
        current: OriginView | None = None
        last_was_unload = False
        for dr in self._decoded_records():
            if dr.header is None:
                continue
            if dr.seq > seq:
                break
            if dr.record_type != RT_EVENT:
                continue
            if dr.kind == KIND_MODEL_UNLOAD:
                current = None
                last_was_unload = True
            elif dr.kind == KIND_MODEL_LOAD or _has_model_digest(dr.header):
                current = _origin_of(dr)
                last_was_unload = False
        return current, last_was_unload

    def acknowledged_candidates(self) -> set[int]:
        """The seq of every ``INCIDENT_CANDIDATE`` with at least one
        hash-verified ``OVERSIGHT_ACK`` naming it — the r2 loop's
        positive case.

        Matching on ``EVT_REF_SEQ`` alone would count a candidate
        acknowledged even when the ack's own ``EVT_REF_HASH`` does not
        match the record at that seq — precisely the case
        ``reference_hash_mismatch`` already exists to flag on the
        advisory side (:meth:`_check_reference`). This resolves
        references the same way, through :meth:`_hash_verified_target`,
        so the two cannot disagree about what "acknowledged" means.
        """
        # Only SAFETY records take part: an ack is SAFETY, and a target
        # that is anything but a SAFETY INCIDENT_CANDIDATE is not counted
        # either way — so a map of SAFETY records alone gives the same
        # set as a map of every record, without decoding every record.
        by_seq: dict[int, tuple[DecodedRecord, bytes]] = {
            dr.seq: (dr, self._headers[dr.index]) for dr in self.safety_records()
        }
        acknowledged: set[int] = set()
        for dr, _hb in by_seq.values():
            if dr.kind != KIND_OVERSIGHT_ACK:
                continue
            target = self._hash_verified_target(dr, by_seq)
            if target is not None and target.kind == KIND_INCIDENT_CANDIDATE:
                acknowledged.add(target.seq)
        return acknowledged

    def shredded_targets(self) -> dict[int, int]:
        """Maps a record's seq to the seq of the ``KEY_SHRED`` that
        successfully shreds it — resolved in the chain and key_id-
        matched, the same two checks :meth:`_check_shred_targets`
        already makes to flag the broken cases
        (``shred_target_unresolved``, ``shred_target_key_mismatch``) as
        advisories. The positive case, exposed directly — the same
        shape of gap :meth:`acknowledged_candidates` closed for r2's
        acknowledged state.

        A ``KEY_SHRED`` with no declared key (``TLV_SHRED_KEY_ID``
        absent) resolves every existing target it names — there is
        nothing to mismatch against, the same permissiveness
        :meth:`_check_shred_targets` already has. A record named by
        more than one resolving ``KEY_SHRED`` keeps the last one, in
        seq order — a re-shred is what actually holds now, not a
        history of every attempt.
        """
        by_seq: dict[int, DecodedRecord] = {
            dr.seq: dr for dr in self._decoded_records()
        }
        shredded: dict[int, int] = {}
        for dr in by_seq.values():
            if dr.record_type != RT_KEY_SHRED or dr.body_tlvs is None:
                continue
            tlvs = dict(dr.body_tlvs)
            raw = tlvs.get(SHRED_TARGET_SEQS)
            if raw is None or len(raw) % 8 != 0:
                continue
            shred_key: int | None = None
            if dr.header is not None:
                kid = _origin_tlv(dr.header, TLV_SHRED_KEY_ID)
                if kid is not None and len(kid) == 4:
                    (shred_key,) = struct.unpack("<I", kid)
            for i in range(0, len(raw), 8):
                (t_seq,) = struct.unpack_from("<Q", raw, i)
                target_dr = by_seq.get(t_seq)
                if target_dr is None:
                    continue
                target_key = (
                    target_dr.header.key_id if target_dr.header is not None else None
                )
                if shred_key is None or target_key == shred_key:
                    shredded[t_seq] = dr.seq
        return shredded


def decode_record(index: int, hb: bytes, body: bytes) -> DecodedRecord:
    """Decode one record from its header bytes and (already-sliced) body.

    Shared by the batch facade and the tailing reader so both interpret a
    record identically. An undecodable header (unknown version) yields a
    minimal record — reported, never rejected (§7.6). Kind is resolved only
    for EVENT/SAFETY bodies (§10.5) and only when the body is cleartext.
    """
    rhash = _record_hash(hb)
    try:
        header = Header.decode(hb)
    except MalformedRecord:
        rtype = struct.unpack_from("<H", hb, 8)[0]
        (seq,) = struct.unpack_from("<Q", hb, 12)
        return DecodedRecord(
            seq, index, rtype, None, None, None, None, None, rhash, None, None, None, None
        )

    rtype = header.record_type
    type_name = _TYPE_NAMES.get(rtype)
    body_tlvs: list[tuple[int, bytes]] | None = None
    kind: int | None = None
    kind_name: str | None = None
    detail: str | None = None
    operator_id: bytes | None = None
    disposition: int | None = None
    disposition_name: str | None = None

    if header.key_id == 0 and body:
        try:
            body_tlvs = decode_tlvs(body)
        except MalformedRecord:
            body_tlvs = None
        if body_tlvs is not None and rtype in _KIND_BEARING:
            for t, v in body_tlvs:
                if kind is None and t == EVT_KIND and len(v) >= 2:
                    kind = struct.unpack_from("<H", v, 0)[0]
                    kind_name = _KIND_NAMES.get(kind)
                elif detail is None and t == EVT_DETAIL:
                    detail = v.decode("utf-8", "replace")
                elif operator_id is None and t == EVT_OPERATOR_ID and len(v) == 16:
                    operator_id = v
                elif disposition is None and t == EVT_DISPOSITION and len(v) >= 2:
                    disposition = struct.unpack_from("<H", v, 0)[0]
                    disposition_name = _DISP_NAMES.get(disposition)

    return DecodedRecord(
        header.seq,
        index,
        rtype,
        type_name,
        header,
        body_tlvs,
        kind,
        kind_name,
        rhash,
        detail,
        operator_id,
        disposition,
        disposition_name,
    )


def _origin_tlv(header: Header, tag: int) -> bytes | None:
    for t, v in header.tlvs:
        if t == tag:
            return v
    return None


def _has_model_digest(header: Header) -> bool:
    return _origin_tlv(header, TLV_ORIGIN_MODEL_DIGEST) is not None


def _origin_of(dr: DecodedRecord) -> OriginView:
    header = dr.header
    role_b = _origin_tlv(header, TLV_ORIGIN_ROLE)
    md = _origin_tlv(header, TLV_ORIGIN_MODEL_DIGEST)
    cd = _origin_tlv(header, TLV_ORIGIN_CONFIG_DIGEST)
    return OriginView(
        role=role_b.decode("utf-8", "replace") if role_b is not None else None,
        model_digest=md,
        config_digest=cd,
        since_seq=dr.seq,
        detail=dr.detail,
    )
