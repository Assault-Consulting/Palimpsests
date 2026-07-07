"""The level-3 stateful session — live KV held across turns.

``NativeSession`` implements the ``InferenceSession`` protocol on top of
the scheduler's held-slot lifecycle (``open_slot`` / ``feed`` /
``run_turn`` / ``close_slot``). Its whole reason to exist is that the KV
state stays on the server between turns: the second and later turns
append to the existing context instead of re-prefilling the whole
conversation.

A single session drives itself via ``send`` (feed + ``run_turn``).
Several sessions that share one scheduler can be advanced together by the
batch driver (``run_sessions``), which feeds each turn and then runs one
shared decode loop over all of them — true continuous batching (N3b).

``append_tool_result`` is the server-side tool loop's entry point (N5)
and refuses for now; ``save_state`` / ``load_state`` are KV persistence
(N6) and refuse for now. Refusing loudly here — rather than faking —
keeps the capability flags honest.
"""
from __future__ import annotations

from collections.abc import Iterator, Sequence
from palimpsests.engine.capabilities import CapabilityUnsupported
from palimpsests.engine.messages import ChatChunk
from palimpsests.providers.native.backend import NativeBackend, Token
from palimpsests.providers.native.scheduler import Scheduler, TurnRequest

# Default per-turn generation cap, mirroring the engine's stateless path.
_DEFAULT_MAX_TOKENS = 512


class NativeSession:
    """A live, stateful inference session backed by a held scheduler slot.

    Construction reserves a sequence and prepares the system prompt (so
    every later turn shares that context without recomputation). Each
    ``send`` feeds only the new user turn's tokens and continues
    generation from the preserved KV.

    ``stop_tokens`` are the ids that end a turn (typically the model's EOS,
    which the real backend knows; tests pass it explicitly). Without them a
    turn only ends at ``max_tokens``.
    """

    def __init__(
        self,
        backend: NativeBackend,
        scheduler: Scheduler,
        *,
        system_prompt: str | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        stop_tokens: tuple[Token, ...] = (),
    ) -> None:
        self._backend = backend
        self._scheduler = scheduler
        self._max_tokens = max_tokens
        self._stop_tokens = stop_tokens
        self._closed = False
        self._seq_id = scheduler.open_slot()
        # The system prefix is tokenized once and prepended only on the
        # first turn; after that it lives in the slot's KV.
        self._prefix_tokens: list[int] = []
        if system_prompt:
            self._prefix_tokens = backend.tokenize(
                f"system: {system_prompt}\n", add_special=True
            )

    # ─── identity (used by the batch driver) ──────────────────────────────

    @property
    def seq_id(self) -> int:
        """The held slot this session occupies."""
        return self._seq_id

    # ─── turn preparation (shared by send and the batch driver) ───────────

    def _prepare_turn_tokens(self, content: str) -> list[int]:
        """Tokenize one user turn, prepending the system prefix once.

        Separated from feeding so the batch driver can prepare several
        sessions' turns and feed them into one shared decode loop.
        """
        self._ensure_open()
        turn_text = f"user: {content}\nassistant:"
        turn_tokens = self._backend.tokenize(turn_text, add_special=False)
        tokens = self._prefix_tokens + turn_tokens
        self._prefix_tokens = []
        return tokens

    def _turn_request(self, content: str) -> TurnRequest:
        """Build a ``TurnRequest`` for this session's next turn."""
        return TurnRequest(
            seq_id=self._seq_id,
            tokens=self._prepare_turn_tokens(content),
            max_tokens=self._max_tokens,
            stop_tokens=self._stop_tokens,
        )

    def detokenize(self, token: int) -> str:
        """Render one token to text (used when demuxing batch output)."""
        return self._backend.detokenize([token])

    # ─── the stateful contract ────────────────────────────────────────────

    def send(self, content: str) -> Iterator[ChatChunk]:
        """Stream the response to one user turn, reusing session KV.

        The single-session path: feed this turn and drive it to
        completion via ``run_turn``. Several sessions at once go through
        ``run_sessions`` instead.
        """
        tokens = self._prepare_turn_tokens(content)
        self._scheduler.feed(
            self._seq_id,
            tokens,
            max_tokens=self._max_tokens,
            stop_tokens=self._stop_tokens,
        )
        for token in self._scheduler.run_turn(self._seq_id):
            yield ChatChunk(delta=self._backend.detokenize([token]))
        yield ChatChunk(delta="", done=True, finish_reason="stop")

    def append_tool_result(
        self, tool_call_id: str, result: str
    ) -> Iterator[ChatChunk]:
        """Resume after a server-side tool call — not yet implemented (N5)."""
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


def run_sessions(
    scheduler: Scheduler,
    turns: Sequence[tuple[NativeSession, str]],
) -> dict[int, str]:
    """Advance several sessions' turns concurrently and return their text.

    The synchronous batch driver at the session level: builds a
    ``TurnRequest`` for each (session, content) pair, feeds them all, and
    runs one shared decode loop (``Scheduler.run_batch``) so every turn
    advances together — true continuous batching. Returns each session's
    completed turn text keyed by ``seq_id``.

    All sessions must share the passed ``scheduler`` (so they occupy slots
    in the same batch) and must already be open. The number of concurrent
    sessions must not exceed the scheduler's ``max_active``.

    This returns whole turns rather than streaming, because interleaving
    several token streams into one synchronous return is the caller's
    concern; a caller that wants live streaming can drive
    ``scheduler.run_batch`` directly and demultiplex ``StepToken`` by
    ``seq_id``.
    """
    requests = [session._turn_request(content) for session, content in turns]
    by_seq = {session.seq_id: session for session, _ in turns}
    out: dict[int, list[str]] = {r.seq_id: [] for r in requests}
    for st in scheduler.run_batch(requests):
        session = by_seq.get(st.seq_id)
        if session is not None:
            out[st.seq_id].append(session.detokenize(st.token))
    return {seq_id: "".join(parts) for seq_id, parts in out.items()}
