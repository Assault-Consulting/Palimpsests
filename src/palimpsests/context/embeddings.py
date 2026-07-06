"""Embedder interface for block-memory retrieval.

BlockMemory turns evicted text into vectors so it can retrieve relevant
blocks back later. Where those vectors come from is deliberately not
hardcoded — the same behavior-via-injection pattern used for the token
counter and the engine factory:

- The default routes through the *active engine's* embedding endpoint
  (Ollama's ``/api/embeddings``). Zero extra dependency, and retrieval
  works out of the box for a typical Ollama user — they just need an
  embed-capable model pulled (e.g. ``nomic-embed-text``).
- A caller who wants engine-independence (an offline batch job, a
  level-2/3 setup, a different embed model) passes their own
  ``Embedder`` and BlockMemory never touches the engine.

An ``Embedder`` is any callable ``str -> list[float]``. Keeping the
contract that narrow means a sentence-transformers model, a fastembed
model, or a remote API are all drop-in without BlockMemory knowing.
"""
from __future__ import annotations

from collections.abc import Callable

# text -> embedding vector
Embedder = Callable[[str], list[float]]

# The default embed model for the engine-backed embedder. nomic-embed-text
# is small, widely available in Ollama, and produces 768-dim vectors.
DEFAULT_EMBED_MODEL = "nomic-embed-text"


def engine_embedder(engine, *, model: str = DEFAULT_EMBED_MODEL) -> Embedder:
    """Build an Embedder that routes through an engine's ``embed`` method.

    ``engine`` is any object exposing ``embed(*, model, text) -> list``
    — the Ollama adapter does. Bound to a fixed embed model so the
    resulting callable matches the plain ``str -> list[float]`` shape
    BlockMemory expects.

    We depend on the method structurally (duck-typed), not on a concrete
    class, so a future level-2/3 engine that grows an ``embed`` method
    slots in unchanged.
    """

    def _embed(text: str) -> list[float]:
        return engine.embed(model=model, text=text)

    return _embed
