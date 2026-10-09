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
from palimpsests.audit._oslock import ExclusiveLock, LockHeld
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
from palimpsests.audit.pala.frontier import MerkleFrontier
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
EVT_SOURCE = 0x0011  # u16 — 0 parsed-from-wire (default, absent), 1 reported-by-client (r5)

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

# r5 — kind 8/9 evidence-source values (EVT_SOURCE; absent tag == 0)
SOURCE_PARSED_FROM_WIRE = 0
SOURCE_REPORTED_BY_CLIENT = 1

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
    """Encode EVT_DETAIL: credentials scrubbed, UTF-8, clipped to 200 bytes
    on a char boundary.

    Scrubbed first (:func:`~palimpsests.audit.redact.scrub_secrets`): the
    note above says exception text may hide tokens, and clipping alone
    kept whatever fell in the first 200 bytes — on a hash-chained record
    that can never be rewritten.
    """
    from palimpsests.audit.redact import scrub_secrets

    raw = scrub_secrets(text).encode("utf-8")
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


#: Hashes a resumed writer holds before building its deferred frontier —
#: bounded, so a writer whose root is never asked for still does not grow
#: without limit.
_FRONTIER_PENDING_LIMIT = 4096


class ChainLocked(LockHeld):
    """Another process is already writing this chain."""


def _chain_lock_target(path: str | os.PathLike[str]) -> str:
    """The name a chain is locked under — the same for every segment of it.

    A rotated chain is ``base``, ``base.00001``, ``base.00002``… with
    ``base.segments.json`` beside them; its lock is ``base.lock``, so a
    writer resumed on any segment collides with one still writing from
    the base. Anything else is locked under its own name.
    """
    p = os.fspath(path)
    stem, dot, suffix = p.rpartition(".")
    if dot and suffix.isdigit() and os.path.exists(f"{stem}.segments.json"):
        return stem
    return p


def _acquire_chain_lock(path: str | os.PathLike[str]) -> ExclusiveLock:
    """One writer per chain, across processes — or a refusal that says why.

    The writer keeps the head and seq in memory; a second process appending
    to the same file would write records with seqs already used and a
    ``prev_hash`` the first never saw — a forked chain, reported by every
    verifier as a break, with no attack behind it. Two ``palimpsests serve``
    instances sharing a config directory did exactly that, silently.
    """
    lock = ExclusiveLock(_chain_lock_target(path))
    try:
        lock.acquire(blocking=False)
    except LockHeld as exc:
        raise ChainLocked(
            f"another process is already writing the chain at {os.fspath(path)} "
            f"({exc}); a second writer would fork it"
        ) from exc
    return lock


class FrontierUnavailable(RuntimeError):
    """The writer cannot state the derived root over records from seq 0."""


def _starting_frontier(
    path: str | os.PathLike[str], first_header: bytes
) -> tuple[MerkleFrontier | None, str | None]:
    """The frontier a resumed writer continues from, or why there is none.

    For a file that starts later than seq 0 — a segment. (A whole chain,
    starting at seq 0, is resumed with a deferred frontier instead and
    never reaches this function; seq 0 is still answered, with an empty
    frontier, so the function is correct on its own.) Only the frontier
    recorded when the segment's predecessor was closed covers what came
    before — taken from the segments manifest
    beside it, and accepted only if it names this segment's own
    ``prev_hash`` as the closed head and covers exactly ``first.seq``
    records. Anything else is refused rather than guessed: the earlier
    records may no longer exist to recompute it from.
    """
    first = Header.decode(first_header)
    if first.seq == 0:
        return MerkleFrontier(), None
    p = os.fspath(path)
    stem, dot, suffix = p.rpartition(".")
    gap = (
        f"this file starts at seq {first.seq}, and no frontier for the "
        f"{first.seq} records before it was found"
    )
    if not (dot and suffix.isdigit()):
        return None, gap
    manifest = f"{stem}.segments.json"
    try:
        with open(manifest, encoding="utf-8") as fh:
            mf = json.load(fh)
    except (OSError, ValueError):
        return None, gap + f" (no readable {os.path.basename(manifest)})"
    if mf.get("format") != SEGMENTS_FORMAT:
        return None, gap
    for entry in reversed(mf.get("segments", [])):
        if entry.get("head") != first.prev_hash.hex():
            continue
        raw = entry.get("frontier")
        if raw is None:
            return None, gap + " (the manifest predates recorded frontiers)"
        try:
            f = MerkleFrontier.from_bytes(bytes.fromhex(raw))
        except ValueError:
            return None, gap + " (the recorded frontier is malformed)"
        if f.count != first.seq:
            return None, (
                f"the recorded frontier covers {f.count} records, but this file "
                f"starts at seq {first.seq}"
            )
        return f, None
    return None, gap


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
        # The derived root over every record from seq 0, kept as the chain
        # grows (see chain_root()). A new chain starts at record 0, so the
        # frontier is known from the first record on.
        self._frontier: MerkleFrontier | None = MerkleFrontier()
        self._frontier_gap: str | None = None
        self._frontier_deferred: tuple[str, int] | None = None
        self._frontier_pending: list[bytes] = []
        if os.path.exists(path) and os.path.getsize(path) > 0:
            # A fresh writer on a non-empty file would append a second GENESIS
            # and corrupt the chain silently. Refuse; resuming is explicit.
            raise ValueError(
                "path already holds records — use PalaWriter.open_existing() "
                "to resume the chain (core §4.2: BOOT is the cross-boot link)"
            )
        self._path = os.fspath(path)
        self._xlock = _acquire_chain_lock(path)
        try:
            self._fh = open(path, "ab", buffering=0)  # noqa: SIM115 — closed in close()
            self._init_rotation(rotation, seg_records=0, seg_first_seq=0,
                                seg_prev_head=ZERO32, seg_bytes=0)
        except BaseException:
            self._xlock.release()
            raise

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

        Takes the chain's writer lock first — before the scan, and before
        any torn tail is truncated: truncating a file another process is
        appending to would destroy records it just wrote.
        """
        lock = _acquire_chain_lock(path)
        try:
            return cls._open_existing_locked(
                path,
                lock,
                rotation=rotation,
                boot_id=boot_id,
                time_trust=time_trust,
                assurance_tier=assurance_tier,
                recover_torn_tail=recover_torn_tail,
            )
        except BaseException:
            lock.release()
            raise

    @classmethod
    def _open_existing_locked(
        cls,
        path: str | os.PathLike[str],
        lock: ExclusiveLock,
        *,
        rotation: RotationPolicy | None,
        boot_id: bytes | None,
        time_trust: int,
        assurance_tier: int,
        recover_torn_tail: bool,
    ) -> PalaWriter:
        size = os.path.getsize(path)
        if size == 0:
            raise ValueError("file is empty — use PalaWriter(path) to start a new chain")
        first_header: bytes | None = None
        last_header: bytes | None = None
        # For a file that starts after seq 0 (a segment), the frontier
        # continues from the one recorded when its predecessor was closed:
        # known from the first header, then every record hash in the file
        # is appended in order during this one scan. A whole chain is
        # deferred instead — see below.
        frontier: MerkleFrontier | None = None
        frontier_gap: str | None = None
        record_count = 0
        last_seq = 0
        last_end = 0
        off = 0
        with open(path, "rb") as fh:
            while off < size:
                if size - off < FIXED_HEADER_LEN:
                    break
                fixed = fh.read(FIXED_HEADER_LEN)
                if fixed[:4] != MAGIC:
                    break
                (hlen,) = struct.unpack_from("<H", fixed, 6)
                (seq,) = struct.unpack_from("<Q", fixed, 12)
                (body_len,) = struct.unpack_from("<I", fixed, 120)
                if hlen < FIXED_HEADER_LEN or off + hlen + body_len > size:
                    break
                rest = fh.read(hlen - FIXED_HEADER_LEN)
                fh.seek(body_len, os.SEEK_CUR)
                last_header = fixed + rest
                if first_header is None:
                    first_header = last_header
                    # A whole chain (seq 0) is not hashed here: resuming a
                    # large file is common, asking it for its root is not,
                    # and hashing every header tripled the resume time at
                    # a million records. Its frontier is built on first use
                    # (see _materialize_frontier_locked). A later segment
                    # is bounded by its rotation policy, so it is hashed now.
                    if Header.decode(first_header).seq != 0:
                        frontier, frontier_gap = _starting_frontier(path, first_header)
                if frontier is not None:
                    frontier.append(record_hash(last_header))
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
        w._open_spans = set()
        w._path = os.fspath(path)
        w._xlock = lock
        w._fh = open(path, "ab", buffering=0)  # noqa: SIM115 — closed in close()
        first = Header.decode(first_header)
        w._frontier, w._frontier_gap = frontier, frontier_gap
        w._frontier_pending = []
        w._frontier_deferred = (w._path, record_count) if first.seq == 0 else None
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
            if self._frontier is not None:
                self._frontier.append(rh)
            elif self._frontier_deferred is not None:
                self._frontier_pending.append(rh)
                if len(self._frontier_pending) >= _FRONTIER_PENDING_LIMIT:
                    self._materialize_frontier_locked()
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
    def _append_source(tlvs: list[tuple[int, bytes]], source: int) -> None:
        """Append ``EVT_SOURCE`` for non-default sources (r5).

        The default value is expressed by absence: r3/r4 emitters and
        this writer with ``source=SOURCE_PARSED_FROM_WIRE`` produce the
        same bytes.
        """
        if source not in (SOURCE_PARSED_FROM_WIRE, SOURCE_REPORTED_BY_CLIENT):
            raise ValueError(
                "source must be SOURCE_PARSED_FROM_WIRE or SOURCE_REPORTED_BY_CLIENT"
            )
        if source == SOURCE_REPORTED_BY_CLIENT:
            tlvs.append((EVT_SOURCE, struct.pack("<H", source)))

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

    # ─── §3 events ──────────────────────────────────────────────────────────

    def model_load(
        self,
        model_digest: bytes,
        config_digest: bytes,
        *,
        role: str = ROLE_NATIVE,
        detail: str | None = None,
        span_id: bytes = ZERO16,
    ) -> bytes:
        """A model became the active origin (EVT_KIND MODEL_LOAD)."""
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
        body = self._event_body(KIND_PREFIX_COPY, token_count=token_count)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_SCHEDULER), body=body, span_id=span_id)

    def prefix_warm(self, *, token_count: int | None = None) -> bytes:
        body = self._event_body(KIND_PREFIX_WARM, token_count=token_count)
        return self._emit(RT_EVENT, tlvs=self._origin(ROLE_SCHEDULER), body=body)

    def recovery_truncated_tail(self, *, role: str = ROLE_NATIVE) -> bytes:
        """Record that resume removed a torn trailing record (profile §3, kind 7)."""
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

    # ─── §4 safety ──────────────────────────────────────────────────────────

    def guard_prefix_release(
        self, holder_seq: int, consumer_count: int, *, span_id: bytes = ZERO16
    ) -> bytes:
        detail = f"holder {holder_seq}: {consumer_count} live consumer(s)"
        body = self._event_body(KIND_GUARD_PREFIX_RELEASE, detail=detail)
        return self._emit(RT_SAFETY, tlvs=self._origin(ROLE_SCHEDULER), body=body, span_id=span_id)

    def guard_state_reject(
        self, *, detail: str | None = None, span_id: bytes = ZERO16
    ) -> bytes:
        body = self._event_body(KIND_GUARD_STATE_REJECT, detail=detail)
        return self._emit(
            RT_SAFETY, tlvs=self._origin(ROLE_KV_STORE), body=body, span_id=span_id
        )

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
        """Record that a pre-registered trigger fired (SAFETY kind 102)."""
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
        """Record a disposition for a candidate (SAFETY kind 103)."""
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

    # ─── r3: tool-loop records ───────────────────────────────────────────────

    def tool_call(
        self,
        name: str,
        *,
        args_digest: bytes | None = None,
        detail: str | None = None,
        span_id: bytes = ZERO16,
        role: str = ROLE_NATIVE,
        source: int = SOURCE_PARSED_FROM_WIRE,
    ) -> bytes:
        """Record a dispatched tool invocation (EVENT kind 8, r3)."""
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
        self._append_source(tlvs, source)
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
        source: int = SOURCE_PARSED_FROM_WIRE,
    ) -> bytes:
        """Record a returned/failed/abandoned invocation (EVENT kind 9, r3)."""
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
        self._append_source(tlvs, source)
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
        """Record an offer the completion left untouched (EVENT kind 10, r4)."""
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
        """Record that the tool-loop cap refused further dispatches (SAFETY 104, r3)."""
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

    # ─── r2: documented erasure ──────────────────────────────────────────────

    def key_shred(
        self,
        key_id: int,
        reason: int = REASON_UNSPECIFIED,
        *,
        target_seqs: list[int] | None = None,
        detail: str | None = None,
    ) -> bytes:
        """Note a key's destruction, with the erasure documented (§8)."""
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

    # ─── §5 aggregate ────────────────────────────────────────────────────────

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
        """Serving statistics for a window (cleartext; core §3.2)."""
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
        """Note the current head in-chain, and return the head to store."""
        anchored = self._head
        self._emit(RT_ANCHOR, tlvs=[(TLV_ANCHOR_HEAD, anchored)])
        return self._head

    # ─── state / lifecycle ──────────────────────────────────────────────────

    @property
    def head(self) -> bytes:
        return self._head

    @property
    def head_hex(self) -> str:
        return self._head.hex()

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def recovered_tail_bytes(self) -> int:
        return self._recovered_tail_bytes

    @property
    def boot_id(self) -> bytes:
        return self._boot_id

    @property
    def path(self) -> str:
        return self._path

    def _materialize_frontier_locked(self) -> None:
        """Build a deferred frontier: rescan the resumed file, then replay
        the hashes of the records written since. Called with the lock held."""
        source, count = self._frontier_deferred
        f = MerkleFrontier()
        with open(source, "rb") as fh:
            for _ in range(count):
                fixed = fh.read(FIXED_HEADER_LEN)
                (hlen,) = struct.unpack_from("<H", fixed, 6)
                (body_len,) = struct.unpack_from("<I", fixed, 120)
                f.append(record_hash(fixed + fh.read(hlen - FIXED_HEADER_LEN)))
                fh.seek(body_len, os.SEEK_CUR)
        for rh in self._frontier_pending:
            f.append(rh)
        self._frontier = f
        self._frontier_deferred = None
        self._frontier_pending = []

    def chain_root(self) -> bytes:
        """The derived root over every record from seq 0 to the last one written.

        The §4.3 tree over record hashes in seq order — the value
        ``pala consistency`` lands on and ``SEG_PRIOR_ROOT`` is defined
        as (retention-continuation design). Kept incrementally, so it
        stays available after earlier segments are deleted.

        Raises :class:`FrontierUnavailable` when the writer cannot know
        it: it resumed on a later segment and no earlier frontier was
        recorded for it (a manifest from before frontiers were kept, or
        none at all). A root over only the records this writer can see
        would be a different number under the same name, so none is
        given.
        """
        with self._lock:
            if self._frontier_deferred is not None:
                self._materialize_frontier_locked()
            if self._frontier is None:
                raise FrontierUnavailable(self._frontier_gap or "no frontier")
            if self._frontier.count != self._seq:
                raise FrontierUnavailable(
                    f"frontier covers {self._frontier.count} records, the chain "
                    f"has {self._seq} — refusing to state a root"
                )
            return self._frontier.root()

    def rotate(self, next_path: str | os.PathLike[str]) -> bytes:
        """Cut the container at a record boundary; continue in a new file."""
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
        if self._frontier_deferred is not None:
            self._materialize_frontier_locked()  # the source file is still here
        if self._frontier is not None:
            # What a writer resuming on the *next* segment needs to keep
            # stating the root over every record since seq 0 — including
            # after this segment and its predecessors are deleted under a
            # retention policy. The count and a handful of subtree roots;
            # the root is recorded beside it for a reader that only wants
            # the value.
            closed["frontier"] = self._frontier.to_bytes().hex()
            closed["root"] = self._frontier.root().hex()
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
            self._xlock.release()

    def __enter__(self) -> PalaWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
