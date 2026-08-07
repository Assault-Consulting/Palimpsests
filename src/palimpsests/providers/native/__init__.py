# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""pal-native adapter — level 3 (our own in-process serving loop).

This is the level where we stop wrapping someone else's engine and run
our own decode loop, with direct control over KV state. Per ADR-0001 the
forward pass is llama.cpp via its low-level C API; per ADR-0002 it runs
**in-process** (no subprocess, no wire protocol) so the scheduler calls
the KV primitives directly.

**Scope so far.** N1 shipped the stateless path (``chat_stream`` →
``streaming``). N3a added stateful sessions (``open_session`` →
``stateful_sessions``). N3b made sessions concurrent (``run_sessions`` /
``Scheduler.run_batch`` → ``continuous_batching``). N5 added the
server-side tool loop (``append_tool_result`` → ``server_side_tools``).
N4 added shared-prefix KV (``share_prefixes`` → ``shared_prefix``). N6
adds KV persistence: ``NativeSession.save_state`` / ``load_state``
serialize a session's KV to bytes and back — position packed in — so a
session can be frozen and thawed without re-prefill, flipping
``kv_persistence`` on. That completes the level-3 skeleton.

**Prefix policy (Variant B).** The scheduler owns only the mechanism
(``reserve_prefix_holder`` / ``warm_prefix`` / ``copy_prefix_to_slot`` /
``release_prefix_holder``). The *policy* lives here: a registry keyed by
the exact prefix tokens decides when to reserve a new holder and when to
reuse one. Reuse is by exact token match — simplest and collision-free.
Holders live until ``close`` (per-session refcount eviction is a later
refinement); this is fine for a local single-user runtime where holders
are few and freed at shutdown.

**The test seam (ADR-0002).** The engine composes the pure-Python
``Scheduler`` (fully CI-tested with a fake backend) and a
``NativeBackend`` implementation. The real backend — ``LlamaCppBackend``,
mapping onto ``llama_cpp.llama_cpp`` — needs a build toolchain and a GGUF
model, so it lives behind the ``[native]`` extra with a lazy import and
is validated on hardware, never in CI. A caller without it gets a clear
``EngineUnavailable``, not a crash.
"""
from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from palimpsests.audit.pala_writer import PalaWriter, canonical_config_digest
from palimpsests.engine import (
    BaseInferenceEngine,
    ChatChunk,
    EngineCapabilities,
    EngineMemoryConfig,
    InferenceSession,
    Message,
    ModelInfo,
)
from palimpsests.providers.errors import EngineUnavailable
from palimpsests.providers.native.audit import (
    NativeAudit,
    file_digest,
    injected_backend_digest,
)
from palimpsests.providers.native.backend import NativeBackend, Token
from palimpsests.providers.native.scheduler import GenerationRequest, Scheduler
from palimpsests.providers.native.session import NativeSession

ENGINE_ID = "pal-native"

# How the model file is located, mirroring the level-2 opt-in convention.
_MODEL_ENV = "PALIMPSESTS_NATIVE_MODEL"

# How many sessions may run concurrently in one batched step by default.
_DEFAULT_MAX_SESSIONS = 4


def _render_prompt(messages: Sequence[Message]) -> str:
    """Flatten chat messages into a single prompt string.

    A minimal ``role: content`` rendering. A model-specific chat template
    belongs to the backend later; the scheduler and engine stay
    template-agnostic for now.
    """
    lines = [f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages]
    lines.append("assistant:")
    return "\n".join(lines)


class _Holder:
    """A reserved prefix holder and how many sessions reference it."""

    __slots__ = ("seq_id", "prefix_len", "refcount")

    def __init__(self, seq_id: int, prefix_len: int) -> None:
        self.seq_id = seq_id
        self.prefix_len = prefix_len
        self.refcount = 0


class NativeEngine(BaseInferenceEngine):
    """Level-3 engine: an in-process decode loop over a llama.cpp backend.

    Constructed with an optional explicit ``backend`` (tests pass a fake
    one); otherwise the backend is loaded lazily from the ``[native]``
    extra on first use. Everything above the backend — prompt rendering,
    the scheduler, streaming, sessions, prefix policy — is backend-agnostic
    and CI-tested.

    ``share_prefixes`` opts into shared-prefix KV (N4): sessions with an
    identical system prompt share one prefix holder instead of each
    re-decoding it. Off by default because a holder costs a sequence from
    the budget, which only pays off when prefixes actually coincide.
    """

    def __init__(
        self,
        *,
        backend: NativeBackend | None = None,
        model_path: str | None = None,
        max_tokens: int = 512,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
        share_prefixes: bool = False,
        audit: PalaWriter | None = None,
    ) -> None:
        self._backend = backend
        self._model_path = model_path
        self._max_tokens = max_tokens
        self._max_sessions = max_sessions
        self._share_prefixes = share_prefixes
        # PALA-1 wiring (Phase 3). Passing a writer makes the engine emit
        # the inference profile about its own serving: chain opened here
        # (GENESIS/BOOT), then model loads, session spans, KV boundary
        # events, prefix sharing, and guard refusals at their real points.
        # The engine borrows the writer — the caller owns its lifecycle —
        # and with audit=None every emission site is a single None check.
        self._audit = NativeAudit(audit) if audit is not None else None
        self._model_announced = False
        # One shared scheduler for all sessions, so concurrent sessions
        # occupy slots in the same batch. Built lazily on first session.
        self._session_scheduler: Scheduler | None = None
        # Prefix policy state (Variant B): holders keyed by exact prefix
        # tokens. Populated only when share_prefixes is on.
        self._holders: dict[tuple[Token, ...], _Holder] = {}

    # ─── identity ────────────────────────────────────────────────────────

    @property
    def engine_id(self) -> str:
        return ENGINE_ID

    @property
    def capabilities(self) -> EngineCapabilities:
        # The full level-3 skeleton: streaming (N1), stateful sessions
        # (N3a), concurrent batching (N3b), the server-side tool loop
        # (N5), shared-prefix KV (N4), and KV persistence (N6).
        return EngineCapabilities(
            control_level=3,
            streaming=True,
            stateful_sessions=True,
            shared_prefix=True,
            server_side_tools=True,
            continuous_batching=True,
            kv_persistence=True,
        )

    # ─── backend loading (lazy, behind the [native] extra) ───────────────

    def _load_backend(self) -> NativeBackend:
        """Return the backend, loading the real one on first use.

        An explicitly-injected backend (tests) is used as-is. Otherwise we
        import ``LlamaCppBackend`` lazily — it pulls native code that is
        absent in CI — and surface a clear ``EngineUnavailable`` if the
        extra isn't installed or no model is configured.
        """
        if self._backend is not None:
            self._announce_model(self._backend)
            return self._backend
        try:
            from palimpsests.providers.native.llamacpp_backend import (
                LlamaCppBackend,
            )
        except ImportError as e:
            raise EngineUnavailable(
                "the native (level-3) backend needs the '[native]' extra; "
                "install palimpsests[native]"
            ) from e
        if not self._model_path:
            raise EngineUnavailable(
                f"no model configured for the native engine; set {_MODEL_ENV}"
            )
        self._backend = LlamaCppBackend(model_path=self._model_path)
        self._announce_model(self._backend)
        return self._backend

    def _announce_model(self, backend: NativeBackend) -> None:
        """Emit MODEL_LOAD (origin triple) once per loaded backend.

        The model digest is the GGUF file's streaming SHA-256 when a model
        path exists — computed only with audit on, a one-time cost dwarfed
        by the load itself. An injected backend has no artefact, so its
        digest derives from the backend's importable identity and the
        detail says ``injected:`` — a reader cannot mistake one for a file
        digest. The config digest canonicalizes the engine parameters that
        shape memory/serving behaviour, so a config change is a visibly
        different origin.
        """
        if self._audit is None or self._model_announced:
            return
        self._model_announced = True
        if self._model_path and os.path.isfile(self._model_path):
            model_digest = file_digest(self._model_path)
            detail = f"gguf:{os.path.basename(self._model_path)}"
        else:
            model_digest = injected_backend_digest(backend)
            detail = f"injected:{type(backend).__qualname__}"
        config_digest = canonical_config_digest(
            {
                "engine": ENGINE_ID,
                "model_path": self._model_path or "",
                "max_tokens": self._max_tokens,
                "max_sessions": self._max_sessions,
                "share_prefixes": self._share_prefixes,
            }
        )
        self._audit.model_loaded(model_digest, config_digest, detail=detail)

    def is_available(self) -> bool:
        """True only if a backend can actually be obtained.

        An injected backend counts. Otherwise availability means the
        native extra is importable and a model path is set — probed
        without loading the model.
        """
        if self._backend is not None:
            return True
        try:
            import importlib.util

            spec = importlib.util.find_spec(
                "palimpsests.providers.native.llamacpp_backend"
            )
        except ImportError:
            return False
        return spec is not None and bool(self._model_path)

    # ─── models ──────────────────────────────────────────────────────────

    def list_models(self) -> Sequence[ModelInfo]:
        """The native engine serves the single loaded model.

        Reported from the configured path rather than probed, so this
        works without forcing a load.
        """
        name = self._model_path or "pal-native"
        return [ModelInfo(name=name, engine_id=ENGINE_ID)]

    # ─── chat (stateless path) ────────────────────────────────────────────

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        """Stream a response by driving one generation through the scheduler.

        Renders the messages to a prompt, tokenizes via the backend, runs
        a dedicated single-slot scheduler to completion, and yields each
        detokenized token as a ``ChatChunk``. Stateless work uses its own
        scheduler so it never contends with session slots.
        """
        backend = self._load_backend()
        prompt = _render_prompt(messages)
        prompt_tokens = backend.tokenize(prompt, add_special=True)

        scheduler = Scheduler(backend, max_active=1, audit=self._audit)
        request = GenerationRequest(
            prompt_tokens=prompt_tokens,
            max_tokens=self._max_tokens,
        )
        for token in scheduler.run(request):
            text = backend.detokenize([token])
            yield ChatChunk(delta=text)
        yield ChatChunk(delta="", done=True, finish_reason="stop")

    # ─── sessions (stateful, concurrent path) ─────────────────────────────

    def _get_session_scheduler(self) -> Scheduler:
        """Return the shared session scheduler, building it on first use.

        All sessions share one scheduler with ``max_active=max_sessions``,
        so several can occupy slots and advance together in one batched
        step (continuous batching).
        """
        if self._session_scheduler is None:
            backend = self._load_backend()
            self._session_scheduler = Scheduler(
                backend, max_active=self._max_sessions, audit=self._audit
            )
        return self._session_scheduler

    def _prefix_key(
        self, backend: NativeBackend, system_prompt: str
    ) -> tuple[Token, ...]:
        """The exact prefix tokens used as the holder registry key."""
        rendered = f"system: {system_prompt}\n"
        return tuple(backend.tokenize(rendered, add_special=True))

    def _holder_for(
        self, scheduler: Scheduler, backend: NativeBackend, system_prompt: str
    ) -> _Holder:
        """Return the holder for this prefix, reserving+warming if new.

        Exact token match: an identical system prompt reuses the existing
        holder; a new one reserves a fresh holder and decodes the prefix
        into it once.
        """
        key = self._prefix_key(backend, system_prompt)
        holder = self._holders.get(key)
        if holder is None:
            seq_id = scheduler.reserve_prefix_holder()
            prefix_len = scheduler.warm_prefix(seq_id, list(key))
            holder = _Holder(seq_id=seq_id, prefix_len=prefix_len)
            self._holders[key] = holder
            if self._audit is not None:
                self._audit.prefix_warmed(prefix_len)
        return holder

    def open_session(
        self,
        *,
        model: str,
        system_prompt: str | None = None,
        memory: EngineMemoryConfig | None = None,
    ) -> InferenceSession:
        """Open a stateful session on the shared session scheduler.

        With ``share_prefixes`` on and a system prompt given, the session's
        slot is seeded from a shared prefix holder (the prompt is decoded
        once per unique prompt and copied in), so the session skips
        prepending it inline. Otherwise the session prepends the system
        prompt on its first turn as before.
        """
        scheduler = self._get_session_scheduler()
        backend = self._load_backend()
        span = self._audit.session_opened() if self._audit is not None else None

        if self._share_prefixes and system_prompt:
            holder = self._holder_for(scheduler, backend, system_prompt)
            session = NativeSession(
                backend,
                scheduler,
                system_prompt=system_prompt,
                max_tokens=self._max_tokens,
                prefix_already_seeded=True,
                audit=self._audit,
                audit_span=span,
            )
            scheduler.copy_prefix_to_slot(
                holder.seq_id, session.seq_id, holder.prefix_len
            )
            holder.refcount += 1
            if self._audit is not None and span is not None:
                self._audit.prefix_copied(holder.prefix_len, span)
            return session

        return NativeSession(
            backend,
            scheduler,
            system_prompt=system_prompt,
            max_tokens=self._max_tokens,
            audit=self._audit,
            audit_span=span,
        )

    # ─── lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        """Release sessions and prefix holders, then the backend if loaded."""
        sched = self._session_scheduler
        if sched is not None:
            # Release consumer sessions BEFORE their holders. In unified KV a
            # holder's prefix cells are shared with the sessions seeded from it,
            # so the holder must outlive them (the scheduler enforces this).
            # Slots first, holders second.
            for seq_id in sched.active_slots():
                sched.close_slot(seq_id)
            for holder in self._holders.values():
                sched.release_prefix_holder(holder.seq_id)
        self._holders.clear()
        self._session_scheduler = None
        if self._backend is not None:
            self._backend.close()
            self._backend = None
        if self._audit is not None:
            # Slots force-closed above bypass NativeSession.close, so their
            # spans stay open in the chain — deliberately: the owner never
            # ended them, and the record says so. Unload if we announced a
            # load, then anchor the tip so a completeness check has a head
            # to hold. The writer is NOT closed here: the engine borrows
            # it, the caller owns it.
            if self._model_announced:
                self._audit.model_unloaded()
                self._model_announced = False
            self._audit.anchor()
