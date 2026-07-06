"""Tests for BlockMemory and the embedder interface.

Retrieval logic is tested with a deterministic fake embedder (no
network): each word maps to a fixed axis, so similarity is predictable
and assertions are exact. The engine-backed embedder path is tested
separately against a mocked Ollama wire.
"""
from __future__ import annotations

import math
import pytest
from palimpsests.context import (
    BlockMemory,
    RetrievedBlock,
    engine_embedder,
)
from palimpsests.engine import Message

# ─── a deterministic fake embedder ───────────────────────────────────────

# Fixed vocabulary → one-hot-ish axes, so "similarity" is just shared
# vocabulary. Lets us assert exact ranking without a real model.
_VOCAB = ["cat", "dog", "fish", "car", "boat", "plane"]


def fake_embed(text: str) -> list[float]:
    """Embed by counting vocabulary words on fixed axes."""
    vec = [0.0] * len(_VOCAB)
    for word in text.lower().split():
        if word in _VOCAB:
            vec[_VOCAB.index(word)] += 1.0
    # Avoid the all-zero vector (norm 0) for texts with no vocab word:
    # put a tiny mass on a "misc" dimension by appending it.
    return vec + [0.1]


def _msg(role: str, content: str) -> Message:
    return {"role": role, "content": content}


@pytest.fixture
def mem(tmp_path):
    m = BlockMemory(workspace=tmp_path, embedder=fake_embed)
    yield m
    m.close()


# ─── ingest ──────────────────────────────────────────────────────────────


def test_add_stores_messages(mem: BlockMemory) -> None:
    n = mem.add([_msg("user", "cat"), _msg("assistant", "dog")])
    assert n == 2
    assert mem.count() == 2


def test_add_skips_empty_content(mem: BlockMemory) -> None:
    n = mem.add([_msg("user", "cat"), _msg("user", ""), _msg("user", "dog")])
    assert n == 2
    assert mem.count() == 2


def test_add_empty_list(mem: BlockMemory) -> None:
    assert mem.add([]) == 0
    assert mem.count() == 0


# ─── retrieve ────────────────────────────────────────────────────────────


def test_retrieve_finds_most_similar(mem: BlockMemory) -> None:
    mem.add(
        [
            _msg("user", "cat cat cat"),  # strongly "cat"
            _msg("user", "car boat plane"),  # vehicles
            _msg("user", "dog"),  # "dog"
        ]
    )
    results = mem.retrieve("cat", top_k=1)
    assert len(results) == 1
    assert isinstance(results[0], RetrievedBlock)
    assert results[0].message["content"] == "cat cat cat"


def test_retrieve_ranks_by_similarity(mem: BlockMemory) -> None:
    mem.add(
        [
            _msg("user", "cat"),
            _msg("user", "car boat"),
            _msg("user", "cat dog"),
        ]
    )
    results = mem.retrieve("cat", top_k=3)
    # "cat" and "cat dog" both share the cat axis; "car boat" shares none.
    contents = [r.message["content"] for r in results]
    assert "car boat" == contents[-1]  # least similar is last
    # scores are sorted descending
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_retrieve_respects_top_k(mem: BlockMemory) -> None:
    mem.add([_msg("user", w) for w in ["cat", "dog", "fish", "car"]])
    assert len(mem.retrieve("cat", top_k=2)) == 2


def test_retrieve_empty_store(mem: BlockMemory) -> None:
    assert mem.retrieve("cat", top_k=3) == []


def test_retrieve_zero_top_k(mem: BlockMemory) -> None:
    mem.add([_msg("user", "cat")])
    assert mem.retrieve("cat", top_k=0) == []


def test_retrieve_reconstructs_role(mem: BlockMemory) -> None:
    mem.add([_msg("assistant", "cat")])
    results = mem.retrieve("cat", top_k=1)
    assert results[0].message["role"] == "assistant"


def test_score_is_cosine_range(mem: BlockMemory) -> None:
    mem.add([_msg("user", "cat")])
    results = mem.retrieve("cat", top_k=1)
    # identical text → cosine ~ 1.0
    assert math.isclose(results[0].score, 1.0, rel_tol=1e-4)


# ─── dimension safety ────────────────────────────────────────────────────


def test_retrieve_skips_mismatched_dimension(tmp_path) -> None:
    """A block stored with a different embedding width is skipped, not
    compared across incompatible spaces."""
    m = BlockMemory(workspace=tmp_path, embedder=fake_embed)
    m.add([_msg("user", "cat")])
    m.close()

    # Reopen with an embedder of a different width.
    def wide_embed(text: str) -> list[float]:
        return [1.0] * 20

    m2 = BlockMemory(workspace=tmp_path, embedder=wide_embed)
    try:
        # query embeds to width 20; stored block is width 7 → skipped.
        results = m2.retrieve("cat", top_k=3)
        assert results == []
    finally:
        m2.close()


# ─── persistence ─────────────────────────────────────────────────────────


def test_store_persists_across_instances(tmp_path) -> None:
    m1 = BlockMemory(workspace=tmp_path, embedder=fake_embed)
    m1.add([_msg("user", "cat"), _msg("user", "dog")])
    m1.close()

    m2 = BlockMemory(workspace=tmp_path, embedder=fake_embed)
    try:
        assert m2.count() == 2
        results = m2.retrieve("cat", top_k=1)
        assert results[0].message["content"] == "cat"
    finally:
        m2.close()


def test_store_lives_under_context_memory_dir(tmp_path) -> None:
    m = BlockMemory(workspace=tmp_path, embedder=fake_embed)
    try:
        assert (tmp_path / ".context-memory").is_dir()
    finally:
        m.close()


# ─── engine_embedder ─────────────────────────────────────────────────────


def test_engine_embedder_routes_to_engine() -> None:
    """engine_embedder builds a str->vec callable bound to an engine's
    embed method and a fixed model."""

    class FakeEngine:
        def __init__(self):
            self.calls = []

        def embed(self, *, model: str, text: str) -> list[float]:
            self.calls.append((model, text))
            return [1.0, 2.0, 3.0]

    engine = FakeEngine()
    embed = engine_embedder(engine, model="nomic-embed-text")
    vec = embed("hello")
    assert vec == [1.0, 2.0, 3.0]
    assert engine.calls == [("nomic-embed-text", "hello")]
