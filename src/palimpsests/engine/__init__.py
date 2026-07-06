"""Inference engine abstraction — the contract every level hides behind.

Public surface:

- ``InferenceEngine``      — the structural contract (all levels).
- ``BaseInferenceEngine``  — base class adapters subclass.
- ``InferenceSession``     — stateful session contract (level 3).
- ``EngineCapabilities``   — capability declaration read by callers.
- ``EngineMemoryConfig``   — memory-reduction knobs (levels 1-2 expose).
- ``CapabilityUnsupported``— raised on an unsupported capability.
- ``ChatChunk`` / ``ChatResponse`` / ``ModelInfo`` / ``ToolCall``
  — the data types flowing through the abstraction.

Nothing here is wired to a backend yet: this PR is the inert contract.
Adapters (Ollama, llama.cpp, native) land in later PRs and fill it in.
"""
from __future__ import annotations

from palimpsests.engine.base import BaseInferenceEngine, InferenceEngine, Message
from palimpsests.engine.capabilities import (
    CapabilityUnsupported,
    EngineCapabilities,
    EngineMemoryConfig,
)
from palimpsests.engine.messages import ChatChunk, ChatResponse, ModelInfo, ToolCall
from palimpsests.engine.session import InferenceSession

__all__ = [
    "InferenceEngine",
    "BaseInferenceEngine",
    "Message",
    "InferenceSession",
    "EngineCapabilities",
    "EngineMemoryConfig",
    "CapabilityUnsupported",
    "ChatChunk",
    "ChatResponse",
    "ModelInfo",
    "ToolCall",
]
