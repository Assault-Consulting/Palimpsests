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

import os
import struct
import threading
import time
from collections.abc import Mapping
from hashlib import sha256
from palimpsests.audit.pala.codec import (
    RT_AGGREGATE,
    RT_ANCHOR,
    RT_BOOT,
    RT_EVENT,
    RT_GENESIS,
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
    ZERO16,
    ZERO32,
    Header,
    body_digest_of,
    encode_tlvs,
    record_hash,
)

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

# EVT_KIND values — operations (profile §3)
KIND_MODEL_LOAD = 1
KIND_MODEL_UNLOAD = 2
KIND_KV_SAVE = 3
KIND_KV_RESTORE = 4
KIND_PREFIX_COPY = 5
KIND_PREFIX_WARM = 6
# EVT_KIND values — guard refusals (profile §4), from 100 upward
KIND_GUARD_PREFIX_RELEASE = 100
KIND_GUARD_STATE_REJECT = 101

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


def session_span_id(session_id: str) -> bytes:
    """Derive a 16-byte ``span_id`` from a session identifier, deterministically.

    A session is a span (profile §2). Deriving the span id from the session id
    keeps every record of a session on the same span without the writer holding
    per-session state, which matters under concurrent sessions.
    """
    return sha256(("pala-session:" + session_id).encode("utf-8")).digest()[:16]


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
        self._fh = open(path, "ab", buffering=0)  # noqa: SIM115 — closed in close()

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
    def boot_id(self) -> bytes:
        return self._boot_id

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def __enter__(self) -> PalaWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
