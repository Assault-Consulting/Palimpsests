"""Context-memory — orchestration above the engine, at the text level.

Works identically on all engine levels because it operates on the
messages entering the model, not on the attention kernel.

- ``ContextWindowManager`` — sink/window/evict fitting to a token
  budget (this PR).
- (``BlockMemory`` — retrieval of evicted content — lands in I5.)
"""
from __future__ import annotations

from palimpsests.context.tokens import (
    TokenCounter,
    default_token_counter,
    estimate_tokens,
)
from palimpsests.context.window_manager import ContextWindowManager, FitResult

__all__ = [
    "ContextWindowManager",
    "FitResult",
    "TokenCounter",
    "estimate_tokens",
    "default_token_counter",
]
