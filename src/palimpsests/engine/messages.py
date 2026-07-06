"""Data types shared across all engine levels.

These are plain immutable carriers. They intentionally contain no
behavior — the engine adapters produce them, the orchestration layer
consumes them, and neither side needs to know which level produced a
given chunk. The ``tool_call`` slot on ``ChatChunk`` is present at every
level but only ever populated by a level-3 server-side tool loop; on
levels 1-2 it is always ``None``.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolCall:
    """A model-requested tool invocation surfaced mid-stream.

    Only produced by engines whose ``server_side_tools`` capability is
    set (level 3). The ``id`` correlates the call with the result the
    caller later feeds back via ``InferenceSession.append_tool_result``.
    """

    id: str
    name: str
    arguments: str  # raw JSON string as emitted by the model


@dataclass(frozen=True)
class ChatChunk:
    """One increment of a streamed response.

    ``delta`` is the text produced since the previous chunk. ``done``
    marks the final chunk, which is also where terminal metadata (e.g.
    a finish reason) is carried. ``tool_call`` is populated only when a
    level-3 engine pauses generation to request a tool.
    """

    delta: str = ""
    done: bool = False
    finish_reason: str | None = None
    tool_call: ToolCall | None = None


@dataclass(frozen=True)
class ChatResponse:
    """A whole response, accumulated from a stream.

    ``BaseInferenceEngine.chat`` builds this by concatenating the
    ``delta`` of each ``ChatChunk``, so non-streaming callers get a
    complete answer without every adapter implementing a separate
    non-streaming path.
    """

    text: str
    finish_reason: str | None = None
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ModelInfo:
    """Descriptor for a model an engine can see.

    ``engine_id`` records which adapter surfaced the model, so a caller
    listing models across a switch of active engine can still tell them
    apart. ``loaded`` reflects whether the backend currently holds the
    model in memory (best-effort; not all backends report it).
    """

    name: str
    engine_id: str
    size_bytes: int | None = None
    quant: str | None = None
    loaded: bool = False
