"""pal-native adapter — level 3 (our own in-process serving loop).

This is the level where we stop wrapping someone else's engine and run
our own decode loop, with direct control over KV state. Per ADR-0001 the
forward pass is llama.cpp via its low-level C API; per ADR-0002 it runs
**in-process** (no subprocess, no wire protocol) so the scheduler calls
the KV primitives directly.

**N1 scope.** This ships the stateless path only: ``chat_stream`` drives
one generation through the batch-ready ``Scheduler`` at N=1. That flips
the ``streaming`` capability to True. The genuinely stateful level-3
features — multi-session batching (N>1), shared-prefix KV, the
server-side tool loop, KV persistence — stay off, and ``open_session``
still refuses via the base class, until their PRs land and flip their
flags.

**The test seam (ADR-0002).** The engine composes two pieces: the pure
Python ``Scheduler`` (fully CI-tested with a fake backend) and a
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
    Message,
    ModelInfo,
)
from palimpsests.providers.errors import EngineUnavailable
from palimpsests.providers.native.backend import NativeBackend
from palimpsests.providers.native.scheduler import GenerationRequest, Scheduler

ENGINE_ID = "pal-native"

# How the model file is located, mirroring the level-2 opt-in convention.
_MODEL_ENV = "PALIMPSESTS_NATIVE_MODEL"


def _render_prompt(messages: Sequence[Message]) -> str:
    """Flatten chat messages into a single prompt string.

    N1 uses a minimal ``role: content`` rendering. A model-specific chat
    template belongs to the backend later; the scheduler and engine stay
    template-agnostic for now.
    """
    lines = [f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages]
    lines.append("assistant:")
    return "\n".join(lines)


class NativeEngine(BaseInferenceEngine):
    """Level-3 engine: an in-process decode loop over a llama.cpp backend.

    Constructed with an optional explicit ``backend`` (tests pass a fake
    one); otherwise the backend is loaded lazily from the ``[native]``
    extra on first use. Everything above the backend — prompt rendering,
    the scheduler, streaming — is backend-agnostic and CI-tested.
    """

    def __init__(
        self,
        *,
        backend: NativeBackend | None = None,
        model_path: str | None = None,
        max_tokens: int = 512,
    ) -> None:
        self._backend = backend
        self._model_path = model_path
        self._max_tokens = max_tokens

    # ─── identity ────────────────────────────────────────────────────────

    @property
    def engine_id(self) -> str:
        return ENGINE_ID

    @property
    def capabilities(self) -> EngineCapabilities:
        # N1: streaming works via the N=1 scheduler. The stateful level-3
        # features stay off until their PRs flip them on.
        return EngineCapabilities(
            control_level=3,
            streaming=True,
            stateful_sessions=False,
            shared_prefix=False,
            server_side_tools=False,
            continuous_batching=False,
            kv_persistence=False,
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

    # ─── chat (stateless path, N=1) ──────────────────────────────────────

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        """Stream a response by driving one generation through the scheduler.

        Renders the messages to a prompt, tokenizes via the backend, runs
        the N=1 scheduler to completion, and yields each detokenized token
        as a ``ChatChunk``. This is the stateless path; stateful sessions
        arrive with ``open_session`` in a later PR.
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

    # ─── lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        """Release the backend if one was loaded."""
        if self._backend is not None:
            self._backend.close()
            self._backend = None
