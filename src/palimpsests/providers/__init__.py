"""Engine adapters — concrete backends behind the InferenceEngine contract.

- ``OllamaEngine``    — level 1, thin HTTP client to an external daemon.
- ``LlamaCppEngine``  — level 2, a managed llama-server subprocess we own.
- ``NativeEngine``    — level 3 slot: declared and registered, not yet
                        implemented (every operation refuses loudly).

The error taxonomy (``EngineError`` and friends) is shared by all
adapters so callers handle failures by kind, not by backend.
"""
from __future__ import annotations

from palimpsests.providers.errors import (
    EngineError,
    EngineRequestError,
    EngineUnavailable,
    ModelNotFound,
)
from palimpsests.providers.llamacpp import LlamaCppEngine
from palimpsests.providers.native import NativeEngine
from palimpsests.providers.ollama import OllamaEngine

__all__ = [
    "OllamaEngine",
    "LlamaCppEngine",
    "NativeEngine",
    "EngineError",
    "EngineUnavailable",
    "ModelNotFound",
    "EngineRequestError",
]
