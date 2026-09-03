# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""PALA-1 inference-profile writer.

The emitter for the PALA-1 inference profile (``docs/specs/pala-1/profiles/
inference.md``): the library records its own serving loop — model loads,
sessions, KV operations, prefix sharing, guard refusals, serving statistics —
into the frozen PALA-1 wire format. It is the first non-robotics chain in
existence, which is the point (profile §7): the format proves its width by
having two *emitted* profiles, not one dressed in generality.

Design boundaries:

- **The writer drives the codec; it does not reimplement it.** Every record is
  built by constructing a :class:`~palimpsests.audit.pala.codec.Header`, taking
  its ``.encode()``, and hashing it with ``record_hash`` — the same functions an
  independent verifier reproduces from the spec. No byte layout is duplicated
  here. This keeps the wire format single-sourced in ``audit/pala/`` (the
  extractable codec) and this module a *consumer* of it.
- **Envelope vs. profile.** The envelope (header fields, chain, TLV framing)
  belongs to the core codec. The tags below (``EVT_*``, ``AGG_*``) and the
  ``ORIGIN_ROLE`` vocabulary are the *inference profile's*, allocated by the
  profile document, so they live here rather than in the codec.
- **Metadata only.** Bodies carry operation metadata, never prompt or completion
  text (profile discipline). Bodies are cleartext (``key_id = 0``), like the
  core's ``AGGREGATE``; a deployment that logs content anyway must encrypt, and
  this writer does not offer that path.

The chain is a byte container (core §2.4): records concatenated back-to-back,
which ``palimpsests pala verify`` reads directly. Verifying the writer's own
output is the definition of done for this profile (profile §7).
"""

from __future__ import annotations

import json
import os
import struct
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    MAGIC,
    RT_AGGREGATE,
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
    RT_KEY_SHRED,
    RT_SAFETY,
    RT_SHED,
    RT_SPAN_END,
    RT_SPAN_START,
    TIER_A,
    TIME_UNKNOWN,
    TIME_UNSYNCED,
    TLV_ANCHOR_HEAD,
    TLV_ORIGIN_CONFIG_DIGEST,
    TLV_ORIGIN_MODEL_DIGEST,
    TLV_ORIGIN_ROLE,
    TLV_SHED_CLASS,
    TLV_SHED_COUNT,
    TLV_SHED_WINDOW_NS,
    TLV_SHRED_KEY_ID,
    ZERO16,
    ZERO32,
    Header,
    body_digest_of,
    encode_tlvs,
    record_hash,
)
from palimpsests.audit.pala.segments import SEGMENTS_FORMAT

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

_TOOL_NAME_MAX = 64

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

_DETAIL_CLIP = 200  # profile §3: EVT_DETAIL clipped, exception text may hide tokens


def _detail(text: str) -> bytes:
    """Encode EVT_DETAIL: UTF-8, clipped to 200 bytes on a char boundary."""
    raw = text.encode("utf-8")
    if len(raw) <= _DETAIL_CLIP:
        return raw
    # Clip to <=200 bytes without splitting a multi-byte character.
    return raw[:_DETAIL_CLIP].decode("utf-8", "ignore").encode("utf-8")


def canonical_config_digest(config: Mapping[str, object]) -> bytes:
    """Digest of the engine's memory configuration for ``ORIGIN_CONFIG_DIGEST``.

    Resolves inference-profile open issue §6.2: the encoding must be
    byte-deterministic across versions of the library, or the same config
    yields different origins. The canonical form is the config's ``key=value``
    pairs, keys sorted, values ``str()``-rendered, joined by newlines, UTF-8,
    then SHA-256. A config change is a different origin and the chain shows it.
    """
    lines = "\n".join(f"{k}={config[k]}" for k in sorted(config))
    return sha256(lines.encode("utf-8")).digest()


def canonical_tool_args_digest(arguments: object) -> bytes:
    """Digest of a tool invocation's arguments for ``EVT_PAYLOAD_DIGEST``.

    Resolves inference-profile open issue §6.4 the same way §6.2 was
    resolved for the config digest: the encoding must be byte-deterministic
    across library versions, or the same call yields different digests.
    The canonical form is JSON with sorted keys, compact separators, and
    non-ASCII preserved, UTF-8, then SHA-256. ``bytes`` are treated as
    already-canonical and digested as-is — for callers whose tool protocol
    has its own canonical encoding.
    """
    if isinstance(arguments, (bytes, bytearray)):
        return sha256(bytes(arguments)).digest()
    encoded = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(encoded).digest()


_monotonic = time.monotonic  # module alias: tests substitute a fake clock


@dataclass(frozen=True)
class RotationPolicy:
    """When the writer cuts a segment on its own (WS-ROT).

    Thresholds are checked after each record, under the writer's lock —
    the cut falls strictly between records, never inside one. A record
    that crosses a threshold stays in the segment it was written to;
    the next record opens the successor. While a span this writer
    opened is still open, a due cut is deferred to the span boundary
    (the #178 rule: a hand-made cut never severs a span), and performed
    right after the record that closes the last open span.

    ``max_age_s`` measures the age of the current segment on the
    process's monotonic clock; it has no cross-boot meaning, so after
    ``open_existing`` the age of the adopted segment restarts at zero.
    Byte- and record-thresholds carry across a resume exactly (bytes
    from the file, records from the resume scan).
    """

    max_records: int | None = None
    max_bytes: int | None = None
    max_age_s: float | None = None

    def __post_init__(self) -> None:
        if self.max_records is None and self.max_bytes is None and self.max_age_s is None:
            raise ValueError("an empty RotationPolicy rotates on nothing; set a threshold")
        for name in ("max_records", "max_bytes", "max_age_s"):
            v = getattr(self, name)
            if v is not None and v <= 0:
                raise ValueError(f"{name} must be positive when set")


def session_span_id(session_id: str) -> bytes:
    """Derive a 16-byte ``span_id`` from a session identifier, deterministically.

    A session is a span (profile §2). Deriving the span id from the session id
    keeps every record of a session on the same span without the writer holding
    per-session state, which matters under concurrent sessions.
    """
    return sha256(("pala-session:" + session_id).encode("utf-8")).digest()[:16]


def canonical_tool_names_digest(names) -> bytes:
    """Digest of the offered tool-name list for ``EVT_TOOLS_DIGEST`` (r4).

    The §6.2 discipline applied to names: the *sorted* list of names as a
    JSON array, compact separators, non-ASCII preserved, UTF-8, then
    SHA-256. Sorting makes the digest order-independent — the offer is a
    set, and two clients sending the same tools in different order made
    the same offer.
    """
    encoded = json.dumps(
        sorted(names), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return sha256(encoded).digest()


class PalaWriter:
    """Emits the PALA-1 inference profile to an append-only byte container.

    Thread-safe: a single lock guards the sequence counter, the head, and the
    file handle, so concurrent serving threads cannot interleave a record's
    header and body or race the chain link.

    ``time_trust`` defaults to ``TIME_UNSYNCED`` — honest for a host whose NTP
    state the library has not verified (a real ``wall_clock_ns`` is recorded,
    but no external-sync claim is made). Pass ``TIME_NTP_SYNCED`` only where the
    deployment actually knows the clock is synchronized; per core §5/§7.4 an
    unjustified confident timestamp is a verification violation.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        boot_id: bytes | None = None,
        time_trust: int = TIME_UNSYNCED,
        assurance_tier: int = TIER_A,
        rotation: RotationPolicy | None = None,
    ) -> None:
        if boot_id is not None and len(boot_id) != 16:
            raise ValueError("boot_id must be 16 bytes")
        self._boot_id = boot_id if boot_id is not None else os.urandom(16)
        self._time_trust = time_trust
        self._tier = assurance_tier
        self._lock = threading.Lock()
        self._seq = 0
        self._head = ZERO32
        self._started = False
        self._resume_boot_pending = False
        self._recovered_tail_bytes = 0
        self._recovered_tail_offset = 0
        self._open_spans: set[bytes] = set()
        if os.path.exists(path) and os.path.getsize(path) > 0:
            # A fresh writer on a non-empty file would append a second GENESIS
            # and corrupt the chain silently. Refuse; resuming is explicit.
            raise ValueError(
                "path already holds records — use PalaWriter.open_existing() "
                "to resume the chain (core §4.2: BOOT is the cross-boot link)"
            )
        self._path = os.fspath(path)
        self._fh = open(path, "ab", buffering=0)  # noqa: SIM115 — closed in close()
        self._init_rotation(rotation, seg_records=0, seg_first_seq=0,
                            seg_prev_head=ZERO32, seg_bytes=0)

    def _init_rotation(
        self,
        rotation: RotationPolicy | None,
        *,
        seg_records: int,
        seg_first_seq: int,
        seg_prev_head: bytes,
        seg_bytes: int,
        base_path: str | None = None,
    ) -> None:
        """Segment bookkeeping for the rotation policy (WS-ROT).

        ``_base_path`` stays the construction-time path: successors are
        named ``<base>.00001``, ``<base>.00002``, … and the manifest —
        maintained only when a policy is set — lives at
        ``<base>.segments.json`` in the ``pala-segments/1`` shape the
        offline knife writes, closed segments only, updated atomically
        at each cut. Every entry's ``prev_head`` is the head the segment
        started from, so any closed segment verifies **alone** via
        ``verify_headers(..., start_prev=...)``.
        """
        self._rotation = rotation
        self._base_path = base_path if base_path is not None else self._path
        self._seg_records = seg_records
        self._seg_first_seq = seg_first_seq
        self._seg_prev_head = seg_prev_head
        self._seg_bytes = seg_bytes
        self._seg_started_mono = _monotonic()
        self._seg_index = 0
        self._rotation_due = False
        self._manifest_entries: list[dict] = []
        if rotation is None:
            return
        mp = self._manifest_path()
        if os.path.exists(mp):
            with open(mp, encoding="utf-8") as fh:
                mf = json.load(fh)
            if mf.get("format") != SEGMENTS_FORMAT:
                raise ValueError(
                    f"{mp} is not a {SEGMENTS_FORMAT} manifest — refusing to "
                    "extend a history this writer cannot read"
                )
            self._manifest_entries = list(mf.get("segments", []))

    def _manifest_path(self) -> str:
        return f"{self._base_path}.segments.json"

    @classmethod
    def open_existing(
        cls,
        path: str | os.PathLike[str],
        *,
        rotation: RotationPolicy | None = None,
        boot_id: bytes | None = None,
        time_trust: int = TIME_UNSYNCED,
        assurance_tier: int = TIER_A,
        recover_torn_tail: bool = True,
    ) -> PalaWriter:
        """Resume an existing chain: adopt its tail head and seq (core §4.2).

        Walks the container to the last **complete** record, adopts
        ``head = record_hash`` of that record and ``seq = last + 1``, and
        returns a writer whose first record MUST be ``BOOT`` — the
        cross-boot link. A new ``boot_id`` is generated (it is a new boot).

        **Torn tail.** A crash mid-write can leave a partial record after
        the last complete one. Such bytes never entered the chain — their
        header never hashed into a link — so with ``recover_torn_tail``
        (the default) they are truncated away and the writer remembers the
        fact; the adapter records it as a ``RECOVERY_TRUNCATED_TAIL`` event
        right after ``BOOT`` (profile §3, kind 7). Append-only is not
        contradicted: what it demands is that the removal be *on the
        record*, not that bytes which never became a record be kept.

        **What is refused.** An empty file (start fresh instead), a file
        with no complete record at all, and — deliberately — a file whose
        bytes *after* the first unparseable point contain further record
        magic: that is mid-stream damage, not a torn tail, and truncating
        it would destroy evidence. Such a file is an incident to
        investigate with the verifier, not to auto-repair.

        The walk is O(file); resume happens once per boot. It performs no
        chain verification — that is the reader's job (§7); resume needs
        only the mechanical tail state.
        """
        size = os.path.getsize(path)
        if size == 0:
            raise ValueError("file is empty — use PalaWriter(path) to start a new chain")
        first_header: bytes | None = None
        last_header: bytes | None = None
        record_count = 0
        last_seq = 0
        last_end = 0
        off = 0
        with open(path, "rb") as fh:
            while off < size:
                if size - off < FIXED_HEADER_LEN:
                    break  # not even a fixed header — torn
                fixed = fh.read(FIXED_HEADER_LEN)
                if fixed[:4] != MAGIC:
                    break  # unparseable from this offset on
                (hlen,) = struct.unpack_from("<H", fixed, 6)
                (seq,) = struct.unpack_from("<Q", fixed, 12)
                (body_len,) = struct.unpack_from("<I", fixed, 120)
                if hlen < FIXED_HEADER_LEN or off + hlen + body_len > size:
                    break  # header or body overruns the file — torn
                rest = fh.read(hlen - FIXED_HEADER_LEN)
                fh.seek(body_len, os.SEEK_CUR)
                last_header = fixed + rest
                if first_header is None:
                    first_header = last_header
                record_count += 1
                last_seq = seq
                off += hlen + body_len
                last_end = off
            if last_header is None:
                raise ValueError(
                    "no complete record found — this is not a resumable chain"
                )
            torn = size - last_end
            if torn:
                fh.seek(last_end)
                tail_region = fh.read(torn)
                if MAGIC in tail_region[1:]:
                    raise ValueError(
                        f"damage at offset {last_end} is followed by further "
                        "record magic — mid-stream damage, not a torn tail; "
                        "refusing to truncate (investigate with the verifier)"
                    )
                if not recover_torn_tail:
                    raise ValueError(
                        f"{torn} torn byte(s) after the last complete record "
                        f"at offset {last_end}; pass recover_torn_tail=True "
                        "to truncate and record the recovery"
                    )
        if torn:
            os.truncate(path, last_end)

        w = cls.__new__(cls)
        if boot_id is not None and len(boot_id) != 16:
            raise ValueError("boot_id must be 16 bytes")
        w._boot_id = boot_id if boot_id is not None else os.urandom(16)
        w._time_trust = time_trust
        w._tier = assurance_tier
        w._lock = threading.Lock()
        w._seq = last_seq + 1
        w._head = record_hash(last_header)
        w._started = True
        w._resume_boot_pending = True
        w._recovered_tail_bytes = torn
        w._recovered_tail_offset = last_end
        w._open_spans = set()  # historic spans are outside this writer's knowledge
        w._path = os.fspath(path)
        w._fh = open(path, "ab", buffering=0)  # noqa: SIM115 — closed in close()
        first = Header.decode(first_header)
        base = None
        if rotation is not None:
            stem, dot, suffix = w._path.rpartition(".")
            if dot and suffix.isdigit():
                candidate = f"{stem}.segments.json"
                if os.path.exists(candidate):
                    try:
                        with open(candidate, encoding="utf-8") as mfh:
                            mf = json.load(mfh)
                        entries = mf.get("segments", [])
                        if (
                            mf.get("format") == SEGMENTS_FORMAT
                            and entries
                            and entries[-1].get("head") == first.prev_hash.hex()
                        ):
                            # The link checks out: this file continues the
                            # manifest's history — extend it, don't fork it.
                            base = stem
                    except (OSError, ValueError):
                        base = None
        w._init_rotation(
            rotation,
            seg_records=record_count,
            seg_first_seq=first.seq,
            seg_prev_head=first.prev_hash,
            seg_bytes=last_end,
            base_path=base,
        )
        return w

    # ─── the one place a record is written ──────────────────────────────────

    def _emit(
        self,
        record_type: int,
        *,
        tlvs: list[tuple[int, bytes]] | None = None,
        body: bytes = b"",
        span_id: bytes = ZERO16,
        parent_span_id: bytes = ZERO16,
    ) -> bytes:
        with self._lock:
            if not self._started:
                if record_type != RT_GENESIS:
                    raise RuntimeError("the first record MUST be GENESIS")
                self._started = True
            elif record_type == RT_GENESIS:
                raise RuntimeError("GENESIS may only be the first record")
            if self._resume_boot_pending:
                if record_type != RT_BOOT:
                    raise RuntimeError(
                        "the first record after a resume MUST be BOOT — "
                        "the cross-boot link (core §4.2)"
                    )
                self._resume_boot_pending = False

            wall = time.time_ns() if self._time_trust != TIME_UNKNOWN else 0
            header = Header(
                record_type=record_type,
                seq=self._seq,
                boot_id=self._boot_id,
                prev_hash=self._head,
                assurance_tier=self._tier,
                time_trust=self._time_trust,
                span_id=span_id,
                parent_span_id=parent_span_id,
                monotonic_ns=time.monotonic_ns(),
                wall_clock_ns=wall,
                key_id=0,
                body_len=len(body),
                body_digest=body_digest_of(body) if body else ZERO32,
                tlvs=tlvs or [],
            )
            header_bytes = header.encode()
            rh = record_hash(header_bytes)
            self._fh.write(header_bytes + body)
            self._head = rh
            self._seq += 1
            if record_type == RT_SPAN_START:
                self._open_spans.add(span_id)
            elif record_type == RT_SPAN_END:
                self._open_spans.discard(span_id)
            self._seg_records += 1
            self._seg_bytes += len(header_bytes) + len(body)
            self._maybe_rotate_locked()
            return rh

    @staticmethod
    def _event_body(
        kind: int,
        *,
        blob_digest: bytes | None = None,
        token_count: int | None = None,
        detail: str | None = None,
    ) -> bytes:
        tlvs: list[tuple[int, bytes]] = [(EVT_KIND, struct.pack("<H", kind))]
        if blob_digest is not None:
            if len(blob_digest) != 32:
                raise ValueError("blob_digest must be 32 bytes")
            tlvs.append((EVT_BLOB_DIGEST, blob_digest))
        if token_count is not None:
            tlvs.append((EVT_TOKEN_COUNT, struct.pack("<I", token_count)))
        if detail is not None:
            tlvs.append((EVT_DETAIL, _detail(detail)))
        return encode_tlvs(tlvs)

    @staticmethod
    def _origin(role: str, *extra: tuple[int, bytes]) -> list[tuple[int, bytes]]:
        return [(TLV_ORIGIN_ROLE, role.encode("utf-8")), *extra]

    # ─── chain structure ────────────────────────────────────────────────────

    def genesis(self) -> bytes:
        """Open the chain. MUST be the first record (core §4.2)."""
        return self._emit(RT_GENESIS)

    def boot(self) -> bytes:
        """Mark a boot; its ``prev_hash`` is the cross-boot link (core §4.2)."""
        return self._emit(RT_BOOT)

    def session_start(self, session_id: str, *, role: str = ROLE_NATIVE) -> bytes:
        """Open a session span; returns the ``span_id`` to scope its records."""
        span = session_span_id(session_id)
        self._emit(RT_SPAN_START, tlvs=self._origin(role), span_id=span)
        return span

    def session_end(self, span_id: bytes) -> bytes:
        """Close a session span (core §3.1: duration is derived at read time)."""
        return self._emit(RT_SPAN_END, span_id=span_id)

    # ─── §3 events: model and KV operations ─────────────────────────────────

    def model_load(
        self,
        model_digest: bytes,
        config_digest: bytes,
        *,
        role: str = ROLE_NATIVE,
        detail: str | None = None,
        span_id: bytes = ZERO16,
    ) -> bytes:
        """A model became the active origin (EVT_KIND MODEL_LOAD).

        Carries the origin triple so the chain answers "which weights said
        that?": ``model_digest`` is the loaded artefact's digest (the GGUF file
        for levels 2–3), ``config_digest`` the memory configuration's
        (see :func:`canonical_config_digest`). Both are 32 bytes.
        """
        if len(model_digest) != 32 or len(config_digest) != 32:
            raise ValueError("model_digest and config_digest must be 32 bytes")
        origin = self._origin(
            role,
            (TLV_ORIGIN_MODEL_DIGEST, model_digest),
            (TLV_ORIGIN_CONFIG_DIGEST, config_digest),
        )
        body = self._event_body(KIND_MODEL_LOAD, detail=detail)
        return self._emit(RT_EVENT, tlvs=origin, body=body, span_id=span_id)

    def model_unload(self, *, role: str = ROLE_NATIVE, detail: str | None = None) -> bytes:
        body = self._event_body(KIND_MODEL_UNLOAD, detail=detail)
        return self._emit(RT_EVENT, tlvs=self._origin(role), body=body)

    def kv_save(
        self, blob_digest: bytes, *, span_id: bytes = ZERO16, detail: str | None = None
    ) -> bytes:
        """Session state serialized (EVT_KIND KV_SAVE; blob digest recorded)."""
        body = self._event_body(KIND_KV_SAVE, blob_digest=blob_digest, detail=detail)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_KV_STORE), body=body, span_id=span_id)

    def kv_restore(self, blob_digest: bytes, *, span_id: bytes = ZERO16) -> bytes:
        """Session state restored (EVT_KIND KV_RESTORE; blob digest recorded)."""
        body = self._event_body(KIND_KV_RESTORE, blob_digest=blob_digest)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_KV_STORE), body=body, span_id=span_id)

    def prefix_copy(self, token_count: int, *, span_id: bytes = ZERO16) -> bytes:
        """A shared prefix copied into a session slot (token count = length)."""
        body = self._event_body(KIND_PREFIX_COPY, token_count=token_count)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_SCHEDULER), body=body, span_id=span_id)

    def prefix_warm(self, *, token_count: int | None = None) -> bytes:
        """A prefix holder decoded a prefix for sharing (EVT_KIND PREFIX_WARM)."""
        body = self._event_body(KIND_PREFIX_WARM, token_count=token_count)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_SCHEDULER), body=body)

    def recovery_truncated_tail(self, *, role: str = ROLE_NATIVE) -> bytes:
        """Record that resume removed a torn trailing record (profile §3, kind 7).

        Only meaningful on a writer produced by :meth:`open_existing` that
        actually truncated bytes; calling it otherwise raises — a recovery
        note about nothing would itself be a lie on the record.
        """
        if not self._recovered_tail_bytes:
            raise RuntimeError("no torn tail was recovered by this writer")
        body = self._event_body(
            KIND_RECOVERY_TRUNCATED_TAIL,
            detail=(
                f"resume truncated {self._recovered_tail_bytes} torn tail "
                f"byte(s) at offset {self._recovered_tail_offset}"
            ),
        )
        return self._emit(RT_EVENT, tlvs=self._origin(role), body=body)

    # ─── §4 safety: guard refusals (the audit observes, does not implement) ──

    def guard_prefix_release(
        self, holder_seq: int, consumer_count: int, *, span_id: bytes = ZERO16
    ) -> bytes:
        """A prefix-holder release was refused while consumers were live.

        The canonical guard: releasing a holder with live consumers would
        silently perturb their logits, so the scheduler refuses
        (``PrefixHolderInUseError``). This records the refusal — never the
        holder's contents.
        """
        detail = f"holder {holder_seq}: {consumer_count} live consumer(s)"
        body = self._event_body(KIND_GUARD_PREFIX_RELEASE, detail=detail)
        return self._emit(RT_SAFETY, tlvs=self._origin(ROLE_SCHEDULER), body=body, span_id=span_id)

    def guard_state_reject(
        self, *, detail: str | None = None, span_id: bytes = ZERO16
    ) -> bytes:
        """A persisted KV blob failed validation before reaching the C parser.

        Takes a ``span_id`` because the reject happens at a session's
        ``load_state`` boundary — the refusal belongs to that session's
        span (surfaced by wiring the writer into the engine).
        """
        body = self._event_body(KIND_GUARD_STATE_REJECT, detail=detail)
        return self._emit(
            RT_SAFETY, tlvs=self._origin(ROLE_KV_STORE), body=body, span_id=span_id
        )

    # ─── r2: the oversight loop (profile §4, kinds 102/103) ─────────────────

    def incident_candidate(
        self,
        category: int,
        severity: int,
        *,
        recoverable: bool | None = None,
        ref_seq: int | None = None,
        ref_hash: bytes | None = None,
        detail: str | None = None,
        role: str = ROLE_NATIVE,
    ) -> bytes:
        """Record that a pre-registered trigger fired (SAFETY kind 102).

        Deliberately not an incident *determination* — that is a legal
        judgment the log must not fake — but a never-shed observation for
        a human. ``ref_seq``/``ref_hash`` MAY name the source record and
        MUST be given together: the hash is what binds the reference past
        any seq ambiguity (profile r2).
        """
        if (ref_seq is None) != (ref_hash is None):
            raise ValueError("ref_seq and ref_hash must be given together")
        if ref_hash is not None and len(ref_hash) != 32:
            raise ValueError("ref_hash must be 32 bytes")
        tlvs: list[tuple[int, bytes]] = [
            (EVT_KIND, struct.pack("<H", KIND_INCIDENT_CANDIDATE)),
            (EVT_CATEGORY, struct.pack("<H", category)),
            (EVT_SEVERITY, struct.pack("<H", severity)),
        ]
        if recoverable is not None:
            tlvs.append((EVT_RECOVERABLE, b"\x01" if recoverable else b"\x00"))
        if ref_seq is not None and ref_hash is not None:
            tlvs.append((EVT_REF_SEQ, struct.pack("<Q", ref_seq)))
            tlvs.append((EVT_REF_HASH, ref_hash))
        if detail is not None:
            tlvs.append((EVT_DETAIL, _detail(detail)))
        return self._emit(RT_SAFETY, tlvs=self._origin(role), body=encode_tlvs(tlvs))

    def oversight_ack(
        self,
        candidate_seq: int,
        candidate_hash: bytes,
        disposition: int,
        operator_id: bytes,
        *,
        role: str = ROLE_NATIVE,
    ) -> bytes:
        """Record a disposition for a candidate (SAFETY kind 103).

        The writer is deliberately dumb here: it validates the *format* of
        every field and nothing about existence — whether
        ``candidate_seq``/``candidate_hash`` name a real candidate is the
        reader's referential-integrity check, reported as an advisory,
        never a chain violation (profile r2). ``operator_id`` is 16 opaque
        bytes, pseudonymous by construction: the mapping to a person lives
        with the deployer, outside the log.
        """
        if len(candidate_hash) != 32:
            raise ValueError("candidate_hash must be 32 bytes")
        if len(operator_id) != 16:
            raise ValueError("operator_id must be 16 bytes (pseudonymous)")
        if disposition not in (DISP_ACKNOWLEDGED, DISP_DISMISSED, DISP_ESCALATED):
            raise ValueError("disposition must be 0, 1 or 2")
        body = encode_tlvs(
            [
                (EVT_KIND, struct.pack("<H", KIND_OVERSIGHT_ACK)),
                (EVT_REF_SEQ, struct.pack("<Q", candidate_seq)),
                (EVT_REF_HASH, candidate_hash),
                (EVT_DISPOSITION, struct.pack("<H", disposition)),
                (EVT_OPERATOR_ID, operator_id),
            ]
        )
        return self._emit(RT_SAFETY, tlvs=self._origin(role), body=body)

    # ─── r3: tool-loop records (profile §3.1 / §4 kind 104) ─────────────────

    def tool_call(
        self,
        name: str,
        *,
        args_digest: bytes | None = None,
        detail: str | None = None,
        span_id: bytes = ZERO16,
        role: str = ROLE_NATIVE,
    ) -> bytes:
        """Record a dispatched tool invocation (EVENT kind 8, r3).

        ``name`` is the registered tool identifier — an identifier, never
        arguments; arguments enter the log only as ``args_digest``
        (``canonical_tool_args_digest``). What this records is the
        dispatch, not a "decision" — whether the dispatch was wise is a
        judgment the log must not fake (profile §3.1).
        """
        raw = name.encode("utf-8")
        if not raw or len(raw) > _TOOL_NAME_MAX:
            raise ValueError(f"tool name must be 1..{_TOOL_NAME_MAX} UTF-8 bytes")
        tlvs: list[tuple[int, bytes]] = [
            (EVT_KIND, struct.pack("<H", KIND_TOOL_CALL)),
            (EVT_TOOL_NAME, raw),
        ]
        if args_digest is not None:
            if len(args_digest) != 32:
                raise ValueError("args_digest must be 32 bytes")
            tlvs.append((EVT_PAYLOAD_DIGEST, args_digest))
        if detail is not None:
            tlvs.append((EVT_DETAIL, _detail(detail)))
        return self._emit(
            RT_EVENT, tlvs=self._origin(role), body=encode_tlvs(tlvs), span_id=span_id
        )

    def tool_result(
        self,
        call_seq: int,
        call_hash: bytes,
        outcome: int,
        *,
        result_digest: bytes | None = None,
        span_id: bytes = ZERO16,
        role: str = ROLE_NATIVE,
    ) -> bytes:
        """Record a returned/failed/abandoned invocation (EVENT kind 9, r3).

        The reference pair MUST name the ``TOOL_CALL`` — the hash binds it
        past any seq ambiguity, the OVERSIGHT_ACK rule reused. The writer
        validates the *format* only; whether the pair names a real call is
        the reader's referential-integrity advisory. Latency is the
        ``monotonic_ns`` delta between the two records — no duration field
        exists because none is needed (profile §3.1).
        """
        if len(call_hash) != 32:
            raise ValueError("call_hash must be 32 bytes")
        if outcome not in (OUTCOME_OK, OUTCOME_ERROR, OUTCOME_TIMEOUT, OUTCOME_CANCELLED):
            raise ValueError("outcome must be 0..3 (ok/error/timeout/cancelled)")
        tlvs: list[tuple[int, bytes]] = [
            (EVT_KIND, struct.pack("<H", KIND_TOOL_RESULT)),
            (EVT_REF_SEQ, struct.pack("<Q", call_seq)),
            (EVT_REF_HASH, call_hash),
            (EVT_OUTCOME, struct.pack("<H", outcome)),
        ]
        if result_digest is not None:
            if len(result_digest) != 32:
                raise ValueError("result_digest must be 32 bytes")
            tlvs.append((EVT_PAYLOAD_DIGEST, result_digest))
        return self._emit(
            RT_EVENT, tlvs=self._origin(role), body=encode_tlvs(tlvs), span_id=span_id
        )

    def tools_offered_no_call(
        self,
        count: int,
        tools_digest: bytes,
        *,
        span_id: bytes = ZERO16,
        role: str = ROLE_NATIVE,
        detail: str | None = None,
    ) -> bytes:
        """Record an offer the completion left untouched (EVENT kind 10, r4).

        An observation of the visibility boundary, never an inference:
        the request offered ``count`` structured tools
        (``canonical_tool_names_digest`` of their names in
        ``tools_digest``) and the completion produced no structured tool
        call. Whatever the reply text did with the offer is beyond
        structured audit (profile §3.1); this record turns that
        emptiness into a fact on the chain. When and whether to emit —
        e.g. suppressing completions already inside a visible structured
        loop — is the caller's stated policy, not this method's.
        """
        if not 0 <= count <= 0xFFFF:
            raise ValueError("count must fit u16")
        if len(tools_digest) != 32:
            raise ValueError("tools_digest must be 32 bytes")
        tlvs: list[tuple[int, bytes]] = [
            (EVT_KIND, struct.pack("<H", KIND_TOOLS_OFFERED_NO_CALL)),
            (EVT_TOOLS_OFFERED, struct.pack("<H", count)),
            (EVT_TOOLS_DIGEST, tools_digest),
        ]
        if detail is not None:
            tlvs.append((EVT_DETAIL, _detail(detail)))
        return self._emit(
            RT_EVENT, tlvs=self._origin(role), body=encode_tlvs(tlvs), span_id=span_id
        )

    def guard_tool_loop_limit(
        self,
        iterations: int,
        *,
        call_seq: int | None = None,
        call_hash: bytes | None = None,
        span_id: bytes = ZERO16,
        role: str = ROLE_NATIVE,
    ) -> bytes:
        """Record that the tool-loop cap refused further dispatches (SAFETY 104, r3).

        The §4 pattern applied to the loop: the cap refuses rather than let
        a runaway loop exhaust the engine, and this record observes the
        refusal — it never implements it. ``call_seq``/``call_hash`` MAY
        name the last ``TOOL_CALL`` before the cap and MUST be given
        together. Never shed.
        """
        if (call_seq is None) != (call_hash is None):
            raise ValueError("call_seq and call_hash must be given together")
        if call_hash is not None and len(call_hash) != 32:
            raise ValueError("call_hash must be 32 bytes")
        tlvs: list[tuple[int, bytes]] = [
            (EVT_KIND, struct.pack("<H", KIND_GUARD_TOOL_LOOP_LIMIT)),
            (EVT_TOKEN_COUNT, struct.pack("<I", iterations)),
        ]
        if call_seq is not None and call_hash is not None:
            tlvs.append((EVT_REF_SEQ, struct.pack("<Q", call_seq)))
            tlvs.append((EVT_REF_HASH, call_hash))
        return self._emit(
            RT_SAFETY, tlvs=self._origin(role), body=encode_tlvs(tlvs), span_id=span_id
        )

    # ─── r2: documented erasure (profile §8) ────────────────────────────────

    def key_shred(
        self,
        key_id: int,
        reason: int = REASON_UNSPECIFIED,
        *,
        target_seqs: list[int] | None = None,
        detail: str | None = None,
    ) -> bytes:
        """Note a key's destruction, with the erasure documented (§8).

        One record, one operation: the reason/targets/ticket ride the same
        ``KEY_SHRED`` record that documents the destruction. The body is
        cleartext by MUST — the note has to outlive every key. This method
        only *records*; destroying ``K[key_id]`` is the caller's key-store
        operation, and callers should emit this record inside that
        operation so the two cannot drift apart. Whether ``target_seqs``
        name real records under that key is a reader advisory.
        """
        tlvs: list[tuple[int, bytes]] = [(SHRED_REASON, struct.pack("<H", reason))]
        if target_seqs:
            tlvs.append(
                (SHRED_TARGET_SEQS, b"".join(struct.pack("<Q", t) for t in target_seqs))
            )
        if detail is not None:
            tlvs.append((SHRED_DETAIL, _detail(detail)))
        return self._emit(
            RT_KEY_SHRED,
            tlvs=[(TLV_SHRED_KEY_ID, struct.pack("<I", key_id))],
            body=encode_tlvs(tlvs),
        )

    # ─── §5 aggregate: serving statistics over a window ─────────────────────

    def aggregate(
        self,
        window_ns: int,
        *,
        requests: int,
        tokens_prefill: int,
        tokens_decode: int,
        prefill_saved: int,
        sessions_open: int,
    ) -> bytes:
        """Serving statistics for a window (cleartext; core §3.2).

        ``prefill_saved`` (``AGG_PREFILL_SAVED``) is deliberate: the library's
        measured value proposition is avoided re-prefill, and this makes that
        claim an auditable time series rather than a benchmark artefact.
        """
        body = encode_tlvs(
            [
                (AGG_WINDOW_NS, struct.pack("<Q", window_ns)),
                (AGG_SAMPLE_COUNT, struct.pack("<I", requests)),
                (AGG_REQUESTS, struct.pack("<I", requests)),
                (AGG_TOKENS_PREFILL, struct.pack("<Q", tokens_prefill)),
                (AGG_TOKENS_DECODE, struct.pack("<Q", tokens_decode)),
                (AGG_PREFILL_SAVED, struct.pack("<Q", prefill_saved)),
                (AGG_SESSIONS_OPEN, struct.pack("<I", sessions_open)),
            ]
        )
        return self._emit(RT_AGGREGATE, tlvs=self._origin(ROLE_NATIVE), body=body)

    def shed(self, shed_class: int, count: int, window_ns: int) -> bytes:
        """Record that records were dropped under saturation (core §3.3)."""
        tlvs = [
            (TLV_SHED_CLASS, struct.pack("<H", shed_class)),
            (TLV_SHED_COUNT, struct.pack("<I", count)),
            (TLV_SHED_WINDOW_NS, struct.pack("<Q", window_ns)),
        ]
        return self._emit(RT_SHED, tlvs=tlvs)

    # ─── anchoring ──────────────────────────────────────────────────────────

    def anchor(self) -> bytes:
        """Note the current head in-chain, and return the head to store.

        Writes an ``ANCHOR`` record whose ``ANCHOR_HEAD`` TLV is the head as of
        just before it (the head it anchors). The value returned is the *new*
        head (the tip, including the anchor record itself) — this is what the
        out-of-band anchor store should hold, so a later completeness check sees
        ``A == H`` until more records are appended (core §7.2, as clarified: the
        store holds the current head; an in-chain ANCHOR record is a historical
        note that may lag).
        """
        anchored = self._head
        self._emit(RT_ANCHOR, tlvs=[(TLV_ANCHOR_HEAD, anchored)])
        return self._head

    # ─── state / lifecycle ──────────────────────────────────────────────────

    @property
    def head(self) -> bytes:
        """The current chain head (``record_hash`` of the last record)."""
        return self._head

    @property
    def head_hex(self) -> str:
        return self._head.hex()

    @property
    def seq(self) -> int:
        """The sequence number the next record will receive."""
        return self._seq

    @property
    def recovered_tail_bytes(self) -> int:
        """Bytes removed as a torn tail by :meth:`open_existing` (0 if none)."""
        return self._recovered_tail_bytes

    @property
    def boot_id(self) -> bytes:
        return self._boot_id

    @property
    def path(self) -> str:
        """The container's filesystem path (for self-verification readers)."""
        return self._path

    def rotate(self, next_path: str | os.PathLike[str]) -> bytes:
        """Cut the container at a record boundary; continue in a new file.

        Rotation is a storage operation, invisible to the chain (core
        §2.4): same boot, same sequence, same head — the next record
        simply lands in ``next_path``, and the byte concatenation of the
        segments verifies as one container. No ``BOOT`` is emitted:
        ``BOOT`` is the cross-boot link (core §4.2), and this is not a
        new boot.

        Refused while a span **this writer opened** is still open. That
        is not a wire rule — the boundary is invisible either way — but
        an operational courtesy to readers who handle segments one at a
        time: close the span, rotate, reopen. Spans inherited by
        ``open_existing`` are outside this writer's knowledge and do not
        block rotation.

        Returns the chain head at the cut — the natural value to anchor
        or checkpoint for the closed segment.
        """
        p = os.fspath(next_path)
        with self._lock:
            if not self._started:
                raise ValueError("nothing to rotate: the chain has no records yet")
            if self._open_spans:
                raise ValueError(
                    f"rotation blocked: {len(self._open_spans)} span(s) opened by "
                    "this writer are still open — close them, rotate, reopen"
                )
            return self._rotate_core(p)

    def _rotate_core(self, p: str) -> bytes:
        """The cut itself — caller holds the lock and has cleared the spans.

        With a rotation policy set, the closed segment lands in the
        ``pala-segments/1`` manifest (closed segments only; the open one
        is never listed), written atomically via a same-directory
        replace. Without a policy, this is exactly the #178 behaviour.
        """
        if os.path.exists(p) and os.path.getsize(p) > 0:
            raise ValueError(
                "next_path already holds bytes — a rotation starts an empty "
                "segment; appending to a foreign file would interleave chains"
            )
        closed = {
            "file": os.path.basename(self._path),
            "first_seq": self._seg_first_seq,
            "last_seq": self._seq - 1,
            "records": self._seg_records,
            "head": self._head.hex(),
            "prev_head": self._seg_prev_head.hex(),
        }
        self._fh.close()
        self._fh = open(p, "ab", buffering=0)  # noqa: SIM115 — closed in close()
        self._path = p
        if self._rotation is not None:
            self._manifest_entries.append(closed)
            self._write_manifest()
        self._seg_prev_head = self._head
        self._seg_first_seq = self._seq
        self._seg_records = 0
        self._seg_bytes = 0
        self._seg_started_mono = _monotonic()
        return self._head

    def _maybe_rotate_locked(self) -> None:
        """Post-record policy check; the cut falls between records only."""
        pol = self._rotation
        if pol is None:
            return
        due = self._rotation_due
        if not due and pol.max_records is not None:
            due = self._seg_records >= pol.max_records
        if not due and pol.max_bytes is not None:
            due = self._seg_bytes >= pol.max_bytes
        if not due and pol.max_age_s is not None:
            due = _monotonic() - self._seg_started_mono >= pol.max_age_s
        if not due:
            return
        if self._open_spans:
            # Deferred to the span boundary (#178: a cut never severs a
            # span); performed right after the closing SPAN_END record.
            self._rotation_due = True
            return
        self._rotation_due = False
        self._rotate_core(self._next_segment_path())

    def _next_segment_path(self) -> str:
        n = self._seg_index + 1
        while os.path.exists(f"{self._base_path}.{n:05d}"):
            n += 1
        self._seg_index = n
        return f"{self._base_path}.{n:05d}"

    def _write_manifest(self) -> None:
        import palimpsests

        pol = self._rotation
        assert pol is not None
        manifest = {
            "format": SEGMENTS_FORMAT,
            "tool": {"name": "palimpsests", "version": palimpsests.__version__},
            "source_head": self._manifest_entries[-1]["head"],
            "rotation": {
                k: v
                for k, v in (
                    ("max_records", pol.max_records),
                    ("max_bytes", pol.max_bytes),
                    ("max_age_s", pol.max_age_s),
                )
                if v is not None
            },
            "segments": self._manifest_entries,
        }
        mp = self._manifest_path()
        tmp = f"{mp}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, mp)

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def __enter__(self) -> PalaWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
