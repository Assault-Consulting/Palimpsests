"""The level-3 stateful session — live KV held across turns.

``NativeSession`` implements the ``InferenceSession`` protocol on top of
the scheduler's held-slot lifecycle (``open_slot`` / ``feed`` /
``run_turn`` / ``close_slot``). Its whole reason to exist is that the KV
state stays on the server between turns: the second and later turns
append to the existing context instead of re-prefilling the whole
conversation.

N3a scope: sessions work and hold state, at one session at a time
(scheduler ``max_active=1``). ``append_tool_result`` is the server-side
tool loop's entry point (N5) and refuses for now; ``save_state`` /
``load_state`` are KV persistence (N6) and refuse for now. Refusing
loudly here — rather than faking — keeps the capability flags honest:
the engine only advertises what actually works.
"""
from __future__ import annotations

from collections.abc import Iterator
from palimpsests.engine.capabilities import CapabilityUnsupported
from palimpsests.engine.messages import ChatChunk
from palimpsests.providers.native.backend import NativeBackend
from palimpsests.providers.native.scheduler import Scheduler

# Default per-turn generation cap, mirroring the engine's stateless path.
_DEFAULT_MAX_TOKENS = 512


class NativeSession:
    """A live, stateful inference session backed by a held scheduler slot.

    Construction reserves a sequence and prefills the system prompt into
    it (so every later turn shares that context without recomputation).
    Each ``send`` feeds only the new user turn's tokens and continues
    generation from the preserved KV.
    """

    def __init__(
        self,
        backend: NativeBackend,
        scheduler: Scheduler,
        *,
        system_prompt: str | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
    ) -> None:
        self._backend = backend
        self._scheduler = scheduler
        self._max_tokens = max_tokens
        self._closed = False
        self._seq_id = scheduler.open_slot()
        # Prefill the system prompt once into the held slot. It is decoded
        # as part of the first turn's forward passes; its KV then persists
        # for the life of the session.
        self._prefix_tokens: list[int] = []
        if system_prompt:
            self._prefix_tokens = backend.tokenize(
                f"system: {system_prompt}\n", add_special=True
            )

    # ─── the stateful contract ────────────────────────────────────────────

    def send(self, content: str) -> Iterator[ChatChunk]:
        """Stream the response to one user turn, reusing session KV.

        The prompt fed to the backend is the (one-time) system prefix on
        the first turn, then the user turn, then the assistant cue. On
        later turns only the new turn's tokens are fed — the prior KV is
        already on the server.
        """
        self._ensure_open()
        turn_text = f"user: {content}\nassistant:"
        turn_tokens = self._backend.tokenize(turn_text, add_special=False)
        # The system prefix is only prepended on the first turn; after
        # that it already lives in the slot's KV.
        tokens = self._prefix_tokens + turn_tokens
        self._prefix_tokens = []

        self._scheduler.feed(
            self._seq_id,
            tokens,
            max_tokens=self._max_tokens,
        )
        for token in self._scheduler.run_turn(self._seq_id):
            yield ChatChunk(delta=self._backend.detokenize([token]))
        yield ChatChunk(delta="", done=True, finish_reason="stop")

    def append_tool_result(
        self, tool_call_id: str, result: str
    ) -> Iterator[ChatChunk]:
        """Resume after a server-side tool call — not yet implemented.

        The server-side tool loop is N5. Until then this refuses rather
        than silently degrading, so the ``server_side_tools`` capability
        stays an honest ``False``.
        """
        raise CapabilityUnsupported(
            "server-side tool loop (append_tool_result) is not implemented "
            "yet; it arrives with the tool-loop step (N5)"
        )

    def save_state(self) -> bytes:
        """Serialize session KV — not yet implemented (N6)."""
        raise CapabilityUnsupported(
            "KV persistence (save_state) is not implemented yet; it arrives "
            "with the persistence step (N6)"
        )

    def load_state(self, state: bytes) -> None:
        """Restore session KV — not yet implemented (N6)."""
        raise CapabilityUnsupported(
            "KV persistence (load_state) is not implemented yet; it arrives "
            "with the persistence step (N6)"
        )

    def close(self) -> None:
        """Release the held slot and its KV. Idempotent."""
        if not self._closed:
            self._scheduler.close_slot(self._seq_id)
            self._closed = True

    # ─── internals ────────────────────────────────────────────────────────

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("session is closed")
