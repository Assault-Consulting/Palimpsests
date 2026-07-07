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

from collections.abc import Iterator, Sequence
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
    ) -> None:
        self._backend = backend
        self._model_path = model_path
        self._max_tokens = max_tokens
        self._max_sessions = max_sessions
        self._share_prefixes = share_prefixes
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
        return self._backend

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

        scheduler = Scheduler(backend, max_active=1)
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
                backend, max_active=self._max_sessions
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

        if self._share_prefixes and system_prompt:
            holder = self._holder_for(scheduler, backend, system_prompt)
            session = NativeSession(
                backend,
                scheduler,
                system_prompt=system_prompt,
                max_tokens=self._max_tokens,
                prefix_already_seeded=True,
            )
            scheduler.copy_prefix_to_slot(
                holder.seq_id, session.seq_id, holder.prefix_len
            )
            holder.refcount += 1
            return session

        return NativeSession(
            backend,
            scheduler,
            system_prompt=system_prompt,
            max_tokens=self._max_tokens,
        )

    # ─── lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        """Release prefix holders and the backend if one was loaded."""
        if self._session_scheduler is not None:
            for holder in self._holders.values():
                self._session_scheduler.release_prefix_holder(holder.seq_id)
        self._holders.clear()
        self._session_scheduler = None
        if self._backend is not None:
            self._backend.close()
            self._backend = None
