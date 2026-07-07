"""The level-3 scheduler — a batch-ready decode loop.

This is the core of the level-3 server: the loop that turns queued work
into forward passes. It is written entirely against ``NativeBackend``
(ADR-0002 seam), so it is pure Python and fully tested with a fake
backend.

**Batch-ready.** The structure is ``queue -> scheduler -> batched
decode-step -> demux``: work occupies slots, each ``step`` builds one
batch from *all* active slots and calls ``decode`` once, then routes each
slot's sampled token back. ``step`` has always looped over slots, so
raising the admission cap to N>1 is an unlock, not a rewrite.

**Two ways to drive it.**

- *Stateless* (``run``): submit one request, drive it to completion, free
  the slot. This is the ``chat_stream`` path shipped in N1.
- *Stateful* (``open_slot`` / ``feed`` / ``run_turn`` / ``close_slot``):
  a slot is held across turns. ``feed`` pushes a turn's tokens into an
  existing slot without releasing it; ``run_turn`` advances the loop
  until *that* slot finishes its turn and yields its tokens, leaving the
  slot (and its KV) alive for the next turn. This is the substrate for
  ``NativeSession`` (N3a).

In N3a the admission cap is still 1, so one slot is active at a time —
the session model is proven correct before concurrency is switched on in
N3b. The batching machinery is already multi-slot; only the cap gates it.

Sampling is intentionally trivial (greedy argmax); a real sampler chain
replaces ``_argmax`` later without touching the loop.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from palimpsests.providers.native.backend import BatchEntry, NativeBackend, Token


def _argmax(logits: list[float]) -> int:
    """Greedy sampling: the highest-logit token id.

    Deliberately the simplest possible sampler. A real sampler chain
    replaces this later without touching the scheduler's structure.
    """
    best_i = 0
    best_v = logits[0]
    for i, v in enumerate(logits):
        if v > best_v:
            best_v = v
            best_i = i
    return best_i


@dataclass
class _Slot:
    """One occupied backend sequence.

    Holds the per-sequence decode state: which ``seq_id`` it owns, the
    tokens to feed on the next step (a prompt/turn first, then one
    sampled token per step), the stop tokens that end a turn, the count
    generated *this turn*, and the output of the current turn.

    ``session`` distinguishes the two lifecycles. A stateless slot is
    released the moment its turn ends. A session slot stays alive when a
    turn ends (``turn_done``) — its KV persists for the next ``feed`` —
    and is released only by ``close_slot``.
    """

    seq_id: int
    pending: list[Token]
    max_tokens: int
    stop_tokens: tuple[Token, ...] = ()
    session: bool = False
    generated: list[Token] = field(default_factory=list)
    turn_done: bool = False


@dataclass
class GenerationRequest:
    """A unit of stateless work handed to the scheduler.

    ``prompt_tokens`` is the already-tokenized prompt; the scheduler does
    not tokenize (that is the engine's job, via the backend) so it stays
    free of vocab concerns and easy to test.
    """

    prompt_tokens: list[Token]
    max_tokens: int = 128
    stop_tokens: tuple[Token, ...] = ()


@dataclass
class StepToken:
    """One token produced for one slot in a step — the demux output."""

    seq_id: int
    token: Token
    done: bool


class Scheduler:
    """Drives a ``NativeBackend`` through batched decode steps.

    N3a admits at most one item at a time (``max_active=1``); the loop is
    written to admit and batch several, so lifting the cap (N3b) is the
    only change needed here to run sessions concurrently.
    """

    def __init__(self, backend: NativeBackend, *, max_active: int = 1) -> None:
        self._backend = backend
        # Never admit more than the context can hold, even if asked to.
        self._max_active = min(max_active, backend.n_seq_max())
        self._queue: deque[GenerationRequest] = deque()
        self._slots: dict[int, _Slot] = {}
        self._free_seq_ids: deque[int] = deque(range(backend.n_seq_max()))

    # ─── stateless admission (the N1 chat_stream path) ────────────────────

    def submit(self, request: GenerationRequest) -> None:
        """Queue a stateless request; admitted when a slot frees."""
        self._queue.append(request)

    def _admit(self) -> None:
        """Move queued stateless requests into free slots, up to the cap."""
        while (
            self._queue
            and len(self._slots) < self._max_active
            and self._free_seq_ids
        ):
            request = self._queue.popleft()
            seq_id = self._free_seq_ids.popleft()
            self._slots[seq_id] = _Slot(
                seq_id=seq_id,
                pending=list(request.prompt_tokens),
                max_tokens=request.max_tokens,
                stop_tokens=request.stop_tokens,
                session=False,
            )

    def _release(self, seq_id: int) -> None:
        """Free a slot and recycle its sequence id, clearing its KV."""
        self._backend.seq_remove(seq_id)
        self._slots.pop(seq_id, None)
        self._free_seq_ids.append(seq_id)

    # ─── stateful slots (the session path, N3a) ───────────────────────────

    def open_slot(self) -> int:
        """Reserve a held slot for a session and return its ``seq_id``.

        Unlike ``submit``, this occupies a sequence immediately and keeps
        it until ``close_slot``. Raises if no sequence is free (with
        ``max_active=1`` that means one session at a time in N3a).
        """
        if not self._free_seq_ids or len(self._slots) >= self._max_active:
            raise RuntimeError("no free sequence slot for a new session")
        seq_id = self._free_seq_ids.popleft()
        self._slots[seq_id] = _Slot(
            seq_id=seq_id,
            pending=[],
            max_tokens=0,
            session=True,
        )
        return seq_id

    def feed(
        self,
        seq_id: int,
        tokens: list[Token],
        *,
        max_tokens: int,
        stop_tokens: tuple[Token, ...] = (),
    ) -> None:
        """Load a turn's input into a held session slot.

        Resets the per-turn counters but leaves the slot (and its KV)
        in place, so generation continues from the existing context
        rather than re-prefilling.
        """
        slot = self._slots[seq_id]
        slot.pending = list(tokens)
        slot.max_tokens = max_tokens
        slot.stop_tokens = stop_tokens
        slot.generated = []
        slot.turn_done = False

    def close_slot(self, seq_id: int) -> None:
        """Release a session slot and its KV. Idempotent."""
        if seq_id in self._slots:
            self._release(seq_id)

    # ─── the decode step (shared by both lifecycles) ──────────────────────

    def step(self) -> list[StepToken]:
        """Run one batched forward pass across all active slots.

        Builds one batch from every active slot with pending input, calls
        ``decode`` once, samples each such slot's next token, appends it,
        and reports it. A slot that hits ``max_tokens`` or a stop token
        ends its turn: a stateless slot is released; a session slot is
        marked ``turn_done`` and kept alive for the next ``feed``.
        Returns the tokens produced this step (the demux).
        """
        self._admit()
        # Only slots that still have input to process take part this step.
        active = [
            s for s in self._slots.values() if s.pending and not s.turn_done
        ]
        if not active:
            return []

        entries = [
            BatchEntry(seq_id=s.seq_id, tokens=s.pending, wants_logits=True)
            for s in active
        ]
        logits_by_seq = self._backend.decode(entries)

        produced: list[StepToken] = []
        finished_stateless: list[int] = []
        for slot in active:
            logits = logits_by_seq.get(slot.seq_id)
            if logits is None:
                continue
            token = _argmax(logits)
            slot.generated.append(token)
            # Next step feeds back only the freshly sampled token.
            slot.pending = [token]

            is_stop = token in slot.stop_tokens
            hit_cap = len(slot.generated) >= slot.max_tokens
            done = is_stop or hit_cap
            produced.append(StepToken(seq_id=slot.seq_id, token=token, done=done))
            if done:
                slot.turn_done = True
                slot.pending = []
                if not slot.session:
                    finished_stateless.append(slot.seq_id)

        for seq_id in finished_stateless:
            self._release(seq_id)
        return produced

    # ─── stateless driver (N1 chat_stream) ────────────────────────────────

    def run(self, request: GenerationRequest) -> Iterator[Token]:
        """Submit one stateless request and yield its tokens to completion.

        A thin driver over ``submit``/``step`` for the single-request
        path the engine's ``chat_stream`` uses.
        """
        self.submit(request)
        while self._queue or any(not s.session for s in self._slots.values()):
            for st in self.step():
                yield st.token

    # ─── stateful driver (session turn, N3a) ──────────────────────────────

    def run_turn(self, seq_id: int) -> Iterator[Token]:
        """Advance the loop until session ``seq_id`` finishes its turn.

        Yields that session's tokens in order. The slot is left alive on
        completion (its KV persists for the next ``feed``); only
        ``close_slot`` releases it. With ``max_active=1`` this drives the
        one active session; at N>1 the same ``step`` advances every active
        session together, and a per-session driver reads off its own
        tokens.
        """
        slot = self._slots[seq_id]
        while not slot.turn_done:
            for st in self.step():
                if st.seq_id == seq_id:
                    yield st.token
            # Guard against a slot that somehow lost its input without
            # finishing (should not happen; prevents a spin).
            if not slot.pending and not slot.turn_done:
                break
