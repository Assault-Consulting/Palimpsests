"""Context-memory — orchestration above the engine, at the text level.

Works identically on all engine levels because it operates on the
messages entering the model, not on the attention kernel.

- ``ContextWindowManager`` — sink/window/evict fitting to a token
  budget: keeps a stable sink + recent window, evicts the middle.
- ``BlockMemory`` — retrieval of the evicted middle: embeds evicted
  text and returns the most similar blocks on demand. The two halves of
  the palimpsest image — scrape (evict) and bleed-through (retrieve).
- ``Embedder`` / ``engine_embedder`` — the injectable embedding source,
  defaulting through the active engine.
"""
from __future__ import annotations

from palimpsests.context.block_memory import BlockMemory, RetrievedBlock
from palimpsests.context.embeddings import (
    DEFAULT_EMBED_MODEL,
    Embedder,
    engine_embedder,
)
from palimpsests.context.tokens import (
    TokenCounter,
    default_token_counter,
    estimate_tokens,
)
from palimpsests.context.window_manager import ContextWindowManager, FitResult

__all__ = [
    "ContextWindowManager",
    "FitResult",
    "BlockMemory",
    "RetrievedBlock",
    "Embedder",
    "engine_embedder",
    "DEFAULT_EMBED_MODEL",
    "TokenCounter",
    "estimate_tokens",
    "default_token_counter",
]
