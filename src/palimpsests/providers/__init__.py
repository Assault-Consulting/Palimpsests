"""Engine adapters — concrete backends behind the InferenceEngine contract.

- ``OllamaEngine``  — level 1, thin HTTP client to an external daemon.
- (llama.cpp level-2 and the native level-3 slot land in later PRs.)

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
from palimpsests.providers.ollama import OllamaEngine

__all__ = [
    "OllamaEngine",
    "EngineError",
    "EngineUnavailable",
    "ModelNotFound",
    "EngineRequestError",
]
