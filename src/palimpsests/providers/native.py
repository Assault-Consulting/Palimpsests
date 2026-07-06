"""pal-native adapter — level 3 (our own serving service).

This is the slot for level 3: the level where we stop wrapping someone
else's engine and run our own serving service, the one that will do
continuous batching, shared-prefix KV, a server-side tool loop, and
KV-as-memory persistence.

None of that exists yet. This file is deliberately a **skeleton, not an
implementation** — an honest placeholder that makes the three-level
architecture complete and visible (the registry now lists all three
levels behind one contract) without pretending the level works.

How the honesty is enforced:

- ``capabilities`` declares ``control_level=3`` but every level-3
  feature flag stays ``False``. The flags are the truth the orchestrator
  reads; with all of them off, no caller will route a stateful/batched/
  persistent request here by mistake. Each flag flips to ``True`` in the
  PR that actually ships that feature — that is the "graduation" the
  README describes.
- every operation raises ``CapabilityUnsupported`` rather than returning
  a fake answer. ``chat_stream`` refuses, so the inherited ``chat``
  (which accumulates the stream) refuses too; ``open_session`` refuses
  via the base while ``stateful_sessions`` is False. There is no server
  to talk to, and a level-1-style stateless shim would be exactly the
  silent degradation the whole design rejects.
- ``is_available`` is ``False``: the registry reports pal-native as known
  but not installed, which is accurate — the serving service isn't
  built.

The reusable ``ProcessManager`` (extracted from ``process.py``) is *not*
introduced here. We still have only one concrete process lifecycle
(llama-server); extracting an abstraction against a single case is the
guessing we've avoided. It gets extracted when the native server gives
us a second concrete lifecycle to compare against — i.e. in the PR that
first spawns a real pal-native server.
"""
from __future__ import annotations

from collections.abc import Iterator, Sequence
from palimpsests.engine import (
    BaseInferenceEngine,
    CapabilityUnsupported,
    ChatChunk,
    EngineCapabilities,
    EngineMemoryConfig,
    Message,
    ModelInfo,
)

ENGINE_ID = "pal-native"


class NativeEngine(BaseInferenceEngine):
    """A level-3 slot: declared, registered, not yet implemented.

    Subclasses ``BaseInferenceEngine`` so it satisfies the engine
    contract the way the other adapters do: ``chat`` is derived from
    ``chat_stream`` (and so refuses along with it), and ``open_session``
    is inherited and refuses while ``stateful_sessions`` is False. Only
    the abstract surface is defined here, each method a loud refusal
    until real level-3 code replaces it.
    """

    @property
    def engine_id(self) -> str:
        return ENGINE_ID

    @property
    def capabilities(self) -> EngineCapabilities:
        # Level 3, but nothing implemented yet: every L3 feature flag is
        # False. Each flips to True in the PR that ships that feature.
        return EngineCapabilities(
            control_level=3,
            streaming=False,
            stateful_sessions=False,
            shared_prefix=False,
            server_side_tools=False,
            continuous_batching=False,
            kv_persistence=False,
        )

    def is_available(self) -> bool:
        """The serving service isn't built, so it's never available."""
        return False

    def _not_implemented(self, what: str) -> CapabilityUnsupported:
        return CapabilityUnsupported(
            f"engine {ENGINE_ID!r} is a level-3 placeholder; {what} is not "
            f"implemented yet"
        )

    def list_models(self) -> Sequence[ModelInfo]:
        raise self._not_implemented("list_models")

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        raise self._not_implemented("chat_stream")

    def close(self) -> None:
        """Nothing to release yet — no client, no process."""
        return None
