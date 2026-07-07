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

**Server-side tool loop (N5).** ``append_tool_result`` continues the
*same* turn after an external tool ran: it feeds only the tool result's
tokens into the live KV and resumes generation. This is the level's
strongest case — an agentic loop of generate → call tool → continue does
not re-prefill the conversation on each hop, unlike a stateless engine.
It reuses ``feed`` / ``run_turn``; no new backend primitive is needed
(the KV is already live in the slot).

**KV persistence (N6).** ``save_state`` serializes this session's KV to
bytes; ``load_state`` restores it. The position (``n_past``) is packed
into the bytes alongside the backend state, so a restored session resumes
without re-prefilling. This is the per-session primitive; a
content-addressed store that reuses saved states by content is a layer
above (N6b).
"""
from __future__ import annotations

from collections.abc import Iterator, Sequence
from palimpsests.engine.messages import ChatChunk
from palimpsests.providers.native.backend import NativeBackend, Token
from palimpsests.providers.native.scheduler import Scheduler, TurnRequest

# Default per-turn generation cap, mirroring the engine's stateless path.
_DEFAULT_MAX_TOKENS = 512

# Width in bytes of the n_past header packed in front of the KV state.
_N_PAST_HEADER = 4


class NativeSession:
    """A live, stateful inference session backed by a held scheduler slot.

    Construction reserves a sequence and prepares the system prompt (so
    every later turn shares that context without recomputation). Each
    ``send`` feeds only the new user turn's tokens and continues
    generation from the preserved KV.

    ``stop_tokens`` are the ids that end a turn (typically the model's EOS,
    which the real backend knows; tests pass it explicitly). Without them a
    turn only ends at ``max_tokens``.

    ``prefix_already_seeded`` means the engine has copied a shared prefix
    into this slot's KV already (N4); the session then skips prepending the
    system prompt inline, since it is present in the KV.
    """

    def __init__(
        self,
        backend: NativeBackend,
        scheduler: Scheduler,
        *,
        system_prompt: str | None = None,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        stop_tokens: tuple[Token, ...] = (),
        prefix_already_seeded: bool = False,
    ) -> None:
        self._backend = backend
        self._scheduler = scheduler
        self._max_tokens = max_tokens
        self._stop_tokens = stop_tokens
        self._closed = False
        self._seq_id = scheduler.open_slot()
        # The system prefix is tokenized once and prepended only on the
        # first turn — UNLESS the engine already seeded it into the slot's
        # KV from a shared prefix holder (N4), in which case it is already
        # present and must not be prepended again.
        self._prefix_tokens: list[int] = []
        if system_prompt and not prefix_already_seeded:
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
        yield from self._stream_turn()

    def append_tool_result(
        self, tool_call_id: str, result: str
    ) -> Iterator[ChatChunk]:
        """Resume generation after a server-side tool call.

        Continues the *same* turn: only the tool result's tokens are fed
        into the live KV and generation resumes — the conversation is not
        re-prefilled. This is the agentic-loop win: generate → tool →
        continue costs one short feed per hop, not a full re-read.

        ``tool_call_id`` identifies which pending call this answers; in
        this minimal loop it is echoed into the rendered result so the
        model can correlate. Real tool-call *parsing* from the model's
        output (deciding a tool was requested) is a model-format concern
        layered above this method.
        """
        self._ensure_open()
        result_text = f"tool_result[{tool_call_id}]: {result}\nassistant:"
        tokens = self._backend.tokenize(result_text, add_special=False)
        self._scheduler.feed(
            self._seq_id,
            tokens,
            max_tokens=self._max_tokens,
            stop_tokens=self._stop_tokens,
        )
        yield from self._stream_turn()

    def save_state(self) -> bytes:
        """Serialize this session's KV to bytes (N6).

        The slot's KV bytes with a small header carrying ``n_past`` (the
        position), so a restore knows where to resume. Self-contained: the
        returned bytes are everything ``load_state`` needs.
        """
        self._ensure_open()
        n_past = self._scheduler.slot_n_past(self._seq_id)
        state = self._scheduler.save_slot_state(self._seq_id)
        header = n_past.to_bytes(_N_PAST_HEADER, "big")
        return header + state

    def load_state(self, state: bytes) -> None:
        """Restore this session's KV from bytes produced by ``save_state``.

        Unpacks the ``n_past`` header, restores the backend KV, and sets
        the slot's position so the next turn resumes without re-prefilling
        the restored context.
        """
        self._ensure_open()
        if len(state) < _N_PAST_HEADER:
            raise ValueError("state blob too short to contain an n_past header")
        n_past = int.from_bytes(state[:_N_PAST_HEADER], "big")
        payload = state[_N_PAST_HEADER:]
        self._scheduler.load_slot_state(self._seq_id, payload, n_past)

    def close(self) -> None:
        """Release the held slot and its KV. Idempotent."""
        if not self._closed:
            self._scheduler.close_slot(self._seq_id)
            self._closed = True

    # ─── internals ────────────────────────────────────────────────────────

    def _stream_turn(self) -> Iterator[ChatChunk]:
        """Drive the held slot to the end of its current turn.

        Shared by ``send`` and ``append_tool_result``: both feed input
        into the live slot and then stream the generated continuation.
        """
        for token in self._scheduler.run_turn(self._seq_id):
            yield ChatChunk(delta=self._backend.detokenize([token]))
        yield ChatChunk(delta="", done=True, finish_reason="stop")

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
