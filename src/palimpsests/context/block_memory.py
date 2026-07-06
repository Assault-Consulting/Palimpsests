"""BlockMemory — retrieval of evicted context.

The other half of the palimpsest image: ContextWindowManager scrapes
the middle of the conversation (evicts it); BlockMemory is how the old
text bleeds back through. When a later turn is relevant to something
that was evicted, we find it by similarity and hand it back so the
model can see it again without keeping it resident in the window the
whole time.

Flow:

    evicted message  ──embed──▶  vector
                                  │
                                  ▼
                     SQLite (block_id, text, role, embedding BLOB, ...)
                                  │
    query text  ──embed──▶  cosine top-k  ──▶  the evicted blocks back

Design choices
--------------
- **Injectable embedder.** Where vectors come from is the caller's
  choice (see ``embeddings.py``); the default routes through the active
  engine. BlockMemory itself never imports an engine.
- **SQLite + numpy, no vector DB.** At local scale — tens to low
  hundreds of blocks per session — a full scan with a numpy dot product
  beats the overhead and dependency weight of a real vector store. The
  table is a plain ``(block_id, text, role, embedding, created_at)``.
- **Backing store shared with future KV persistence.** The store lives
  under ``<workspace>/.context-memory/`` on purpose: level 3 will
  persist KV state into the same directory, so evicted-text memory and
  evicted-KV memory are one substrate, not two.
- **Dimension-agnostic.** We store whatever width the embedder returns
  and compare only vectors of matching width, so switching embed models
  doesn't silently mix incompatible spaces.
"""
from __future__ import annotations

import sqlite3
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from palimpsests.context.embeddings import Embedder
from palimpsests.engine import Message
from pathlib import Path

CONTEXT_MEMORY_DIRNAME = ".context-memory"
_DB_FILENAME = "blocks.db"


@dataclass(frozen=True)
class RetrievedBlock:
    """A previously-evicted message returned by similarity search.

    ``score`` is cosine similarity in [-1, 1]; higher is closer. ``message``
    is reconstructed in the ``{"role", "content"}`` shape so a caller can
    splice it straight back into a message list.
    """

    message: Message
    score: float


def _pack(vec: Sequence[float]) -> bytes:
    """Serialize a float vector to bytes (little-endian float32)."""
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack(blob: bytes) -> list[float]:
    """Inverse of ``_pack``."""
    n = len(blob) // 4
    return list(struct.unpack(f"<{n}f", blob))


class BlockMemory:
    """Stores evicted messages and retrieves them by similarity.

    Not thread-safe; one instance per session. The SQLite file is created
    on first use under ``<workspace>/.context-memory/``.
    """

    def __init__(self, workspace: Path, embedder: Embedder) -> None:
        self._dir = Path(workspace) / CONTEXT_MEMORY_DIRNAME
        self._dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._dir / _DB_FILENAME
        self._embedder = embedder
        self._conn = sqlite3.connect(str(self._db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                block_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                role       TEXT NOT NULL,
                text       TEXT NOT NULL,
                dim        INTEGER NOT NULL,
                embedding  BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        self._conn.commit()

    # ─── ingest ──────────────────────────────────────────────────────────

    def add(self, messages: Sequence[Message]) -> int:
        """Embed and store messages (typically a FitResult's ``evicted``).

        Empty-content messages are skipped (nothing to embed or retrieve).
        Returns the number actually stored.
        """
        stored = 0
        for msg in messages:
            text = msg.get("content", "")
            if not text:
                continue
            vec = self._embedder(text)
            self._conn.execute(
                "INSERT INTO blocks (role, text, dim, embedding) "
                "VALUES (?, ?, ?, ?)",
                (msg.get("role", "user"), text, len(vec), _pack(vec)),
            )
            stored += 1
        if stored:
            self._conn.commit()
        return stored

    # ─── retrieve ────────────────────────────────────────────────────────

    def retrieve(self, query: str, *, top_k: int = 3) -> list[RetrievedBlock]:
        """Return the ``top_k`` stored blocks most similar to ``query``.

        Embeds the query, scans stored blocks of matching dimension, and
        ranks by cosine similarity. A block of a different embedding
        width (a model switch mid-session) is skipped rather than
        compared across incompatible spaces. Returns fewer than ``top_k``
        if the store holds fewer comparable blocks.
        """
        if top_k <= 0:
            return []
        q = self._embedder(query)
        rows = self._conn.execute(
            "SELECT role, text, dim, embedding FROM blocks"
        ).fetchall()
        if not rows:
            return []

        try:
            import numpy as np
        except ImportError as e:  # pragma: no cover - environment guard
            raise RuntimeError(
                "BlockMemory.retrieve needs numpy; install the "
                "'embeddings' extra: pip install 'palimpsests[embeddings]'"
            ) from e

        qv = np.asarray(q, dtype=np.float32)
        qn = float(np.linalg.norm(qv))
        if qn == 0.0:
            return []

        scored: list[RetrievedBlock] = []
        for role, text, dim, blob in rows:
            if dim != len(q):
                continue  # different embedding space, don't compare
            bv = np.asarray(_unpack(blob), dtype=np.float32)
            bn = float(np.linalg.norm(bv))
            if bn == 0.0:
                continue
            score = float(np.dot(qv, bv) / (qn * bn))
            scored.append(
                RetrievedBlock(
                    message={"role": role, "content": text}, score=score
                )
            )

        scored.sort(key=lambda b: b.score, reverse=True)
        return scored[:top_k]

    # ─── lifecycle ───────────────────────────────────────────────────────

    def count(self) -> int:
        """Number of stored blocks."""
        return self._conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
