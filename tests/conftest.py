"""Shared test fixtures.

Every global singleton gets a reset fixture so no test bleeds into
another. Autouse resets guarantee a clean slate even for tests that
don't request the setup fixture by name.

``FakeBackend`` also lives here so both the scheduler tests and the
engine tests use it without importing across test modules.
"""
from __future__ import annotations

import pytest
from collections.abc import Sequence
from palimpsests.audit import AuditLog, generate_key, set_audit_log
from palimpsests.providers.native.backend import BatchEntry, Token
from palimpsests.registry import EngineRegistry, set_registry
from pathlib import Path


@pytest.fixture
def audit_log(tmp_path: Path):
    """A fresh, isolated, per-test audit log with an ephemeral key.

    Never touches the real OS keychain or the user's real audit DB —
    each test gets its own key and its own tmp_path-backed database.
    Tests that assert on the log request this fixture by name.
    """
    key = generate_key()
    log = AuditLog(tmp_path / "audit.db", key)
    set_audit_log(log)
    try:
        yield log
    finally:
        log.close()
        set_audit_log(None)


@pytest.fixture(autouse=True)
def _reset_audit_log():
    """Drop the audit-log singleton between every test.

    Autouse complement to the explicit ``audit_log`` fixture: tests
    that don't request it still start with no log installed, and the
    singleton never leaks across tests.
    """
    yield
    set_audit_log(None)


@pytest.fixture
def registry(tmp_path: Path):
    """A fresh, isolated engine registry backed by tmp_path.

    The real registry config lives in the user's config dir; this must
    never be touched during tests. Yields the registry so tests can
    register engines and toggle the active choice.
    """
    reg = EngineRegistry(tmp_path / "registry.json")
    set_registry(reg)
    try:
        yield reg
    finally:
        set_registry(None)


@pytest.fixture(autouse=True)
def _reset_registry():
    """Drop the registry singleton between every test."""
    yield
    set_registry(None)


class FakeBackend:
    """A deterministic stand-in for a real llama.cpp backend.

    It implements the ``NativeBackend`` surface without a model. Decode
    returns, for each sequence, a logits vector that makes ``argmax`` pick
    a scripted next token — so a test can assert the exact token stream.

    The script is ``{seq_id: [t0, t1, ...]}`` and is keyed to *generation
    steps per sequence*: the i-th decode of a sequence emits ``t_i``. When
    a sequence's script is exhausted it emits ``eos``. This lets tests
    drive precise, repeatable generations.

    It also records ``seq_copy`` / ``seq_remove`` / ``state_*`` calls so
    the scheduler's KV bookkeeping (slot recycling) can be asserted.
    """

    def __init__(
        self,
        *,
        vocab_size: int = 32,
        n_seq_max: int = 4,
        eos: Token = 0,
        script: dict[int, list[Token]] | None = None,
    ) -> None:
        self._vocab = vocab_size
        self._n_seq_max = n_seq_max
        self._eos = eos
        self._script = script or {}
        self._decode_count: dict[int, int] = {}
        self.removed: list[int] = []
        self.copied: list[tuple[int, int]] = []
        self.states: dict[int, bytes] = {}

    # ─── vocab ───────────────────────────────────────────────────────────

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        # Deterministic, model-free: one token per character code, kept in
        # range. Enough for tests that just need a prompt to feed.
        return [(ord(c) % self._vocab) for c in text]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        return " ".join(str(t) for t in tokens)

    # ─── decode ──────────────────────────────────────────────────────────

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        out: dict[int, list[float]] = {}
        for entry in entries:
            if not entry.wants_logits:
                continue
            i = self._decode_count.get(entry.seq_id, 0)
            self._decode_count[entry.seq_id] = i + 1
            script = self._script.get(entry.seq_id, [])
            token = script[i] if i < len(script) else self._eos
            # One-hot logits so argmax picks exactly `token`.
            logits = [0.0] * self._vocab
            logits[token] = 1.0
            out[entry.seq_id] = logits
        return out

    # ─── prefix sharing / state (recorded, not modelled) ─────────────────

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        self.copied.append((src_seq, dst_seq))

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        self.removed.append(seq_id)
        # A recycled sequence starts its generation count fresh, exactly
        # as a real backend's cleared KV would.
        self._decode_count.pop(seq_id, None)

    def state_get(self, seq_id: int) -> bytes:
        return self.states.get(seq_id, b"")

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.states[seq_id] = state

    # ─── lifecycle ───────────────────────────────────────────────────────

    def n_seq_max(self) -> int:
        return self._n_seq_max

    def close(self) -> None:
        return None
