"""The InferenceEngine contract and its base implementation.

``InferenceEngine`` is the single abstraction every level hides behind.
Adapters implement streaming (``chat_stream``) and model listing; the
base class derives the non-streaming ``chat`` from the stream so no
adapter writes that twice. Stateful sessions are opt-in: the base
``open_session`` raises ``CapabilityUnsupported``, and only a level-3
adapter overrides it to return a real ``InferenceSession``.

The split matters for the migration path. Levels 1-2 are stateless and
implement only ``chat_stream`` + ``list_models`` + ``capabilities``.
When a level-3 engine arrives it *fills the existing slot* — overriding
``open_session`` — without any call site above the engine changing.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from palimpsests.engine.capabilities import (
    CapabilityUnsupported,
    EngineCapabilities,
    EngineMemoryConfig,
)
from palimpsests.engine.messages import ChatChunk, ChatResponse, ModelInfo
from palimpsests.engine.session import InferenceSession
from typing import Protocol, runtime_checkable

# A chat message in the minimal shape every backend understands.
Message = dict[str, str]


@runtime_checkable
class InferenceEngine(Protocol):
    """Structural contract for any inference engine, all levels."""

    @property
    def engine_id(self) -> str:
        """Stable identifier: ``ollama`` / ``llamacpp`` / ``pal-native``."""
        ...

    @property
    def capabilities(self) -> EngineCapabilities:
        """What this engine can do — the orchestrator reads this."""
        ...

    def list_models(self) -> Sequence[ModelInfo]:
        """Models this engine can currently see."""
        ...

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        """Stream a response chunk by chunk."""
        ...

    def chat(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> ChatResponse:
        """Return a whole response (derived from the stream)."""
        ...

    def open_session(
        self,
        *,
        model: str,
        system_prompt: str | None = None,
        memory: EngineMemoryConfig | None = None,
    ) -> InferenceSession:
        """Open a stateful session (level 3 only)."""
        ...


class BaseInferenceEngine(ABC):
    """Common logic shared by concrete adapters.

    Adapters subclass this and implement ``engine_id``, ``capabilities``,
    ``list_models``, and ``chat_stream``. Everything else is derived:
    ``chat`` accumulates the stream, and ``open_session`` refuses unless
    an adapter overrides it.
    """

    @property
    @abstractmethod
    def engine_id(self) -> str: ...

    @property
    @abstractmethod
    def capabilities(self) -> EngineCapabilities: ...

    @abstractmethod
    def list_models(self) -> Sequence[ModelInfo]: ...

    @abstractmethod
    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]: ...

    def chat(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> ChatResponse:
        """Accumulate ``chat_stream`` into a single response.

        Adapters implement streaming only; this gives every engine a
        correct non-streaming path for free. Tool calls seen mid-stream
        are collected so a caller that doesn't stream still learns the
        model requested them.
        """
        parts: list[str] = []
        finish_reason: str | None = None
        tool_calls = []
        for chunk in self.chat_stream(
            model=model, messages=messages, memory=memory
        ):
            parts.append(chunk.delta)
            if chunk.tool_call is not None:
                tool_calls.append(chunk.tool_call)
            if chunk.done:
                finish_reason = chunk.finish_reason
        return ChatResponse(
            text="".join(parts),
            finish_reason=finish_reason,
            tool_calls=tuple(tool_calls),
        )

    def open_session(
        self,
        *,
        model: str,
        system_prompt: str | None = None,
        memory: EngineMemoryConfig | None = None,
    ) -> InferenceSession:
        """Refuse by default — stateful sessions are level 3 only.

        Loud refusal, not silent degradation: a caller that reached for
        a session on a level-1/2 engine has a real mismatch to fix, and
        hiding it behind a fake stateless shim would only move the bug
        downstream.
        """
        raise CapabilityUnsupported(
            f"engine {self.engine_id!r} (control level "
            f"{self.capabilities.control_level}) does not support stateful "
            f"sessions; open_session requires a level-3 engine"
        )
