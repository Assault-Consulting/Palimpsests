"""The level-3 scheduler — a batch-ready decode loop, at N=1.

This is the core of the level-3 server: the loop that turns queued
generation requests into forward passes. It is written entirely against
``NativeBackend`` (ADR-0002 seam), so it is pure Python and fully tested
with a fake backend.

**Batch-ready, N=1.** The structure is ``queue -> scheduler -> batched
decode-step -> demux``: requests wait in a queue, the scheduler admits
them into slots, each ``step`` builds one batch from *all* active slots
and calls ``decode`` once, then routes each slot's sampled token back.
In N1 the admission cap is 1, so exactly one slot is ever active and the
batch always holds one sequence. Raising that cap to N>1 (step N3) is an
unlock, not a rewrite: the batch-building and demux already loop over
slots.

Sampling is intentionally trivial here (greedy argmax). Real sampling
(temperature, top-p, penalties) is a later concern; N1 exists to prove
the loop drives a backend end-to-end through our contract, not to be a
good sampler.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from palimpsests.providers.native.backend import BatchEntry, NativeBackend, Token


def _argmax(logits: list[float]) -> int:
    """Greedy sampling: the highest-logit token id.

    Deliberately the simplest possible sampler — N1 proves the loop, not
    the sampling. A real sampler chain replaces this later without
    touching the scheduler's structure.
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
    """One active generation, occupying a backend sequence.

    Holds the per-sequence decode state: which ``seq_id`` it owns, the
    tokens still to be fed on the next step (the prompt on the first
    step, then one sampled token per step after), how many tokens have
    been generated, and the output collected so far.
    """

    seq_id: int
    pending: list[Token]
    max_tokens: int
    generated: list[Token] = field(default_factory=list)
    prefixed: bool = False
    done: bool = False


@dataclass
class GenerationRequest:
    """A unit of work handed to the scheduler.

    ``prompt_tokens`` is the already-tokenized prompt; the scheduler does
    not tokenize (that is the engine's job, via the backend) so the
    scheduler stays free of vocab concerns and easy to test.
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

    N1 admits at most one request at a time (``max_active=1``); the loop
    is written to admit and batch several, so lifting the cap is the only
    change N3 needs here.
    """

    def __init__(self, backend: NativeBackend, *, max_active: int = 1) -> None:
        self._backend = backend
        # Never admit more than the context can hold, even if asked to.
        self._max_active = min(max_active, backend.n_seq_max())
        self._queue: deque[GenerationRequest] = deque()
        self._slots: dict[int, _Slot] = {}
        self._free_seq_ids: deque[int] = deque(range(backend.n_seq_max()))

    # ─── admission ───────────────────────────────────────────────────────

    def submit(self, request: GenerationRequest) -> None:
        """Queue a request. It is admitted into a slot when one is free."""
        self._queue.append(request)

    def _admit(self) -> None:
        """Move queued requests into free slots, up to the active cap."""
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
            )

    def _release(self, seq_id: int) -> None:
        """Free a finished slot and recycle its sequence id.

        Clears the slot's KV so a future occupant of this ``seq_id``
        starts clean.
        """
        self._backend.seq_remove(seq_id)
        self._slots.pop(seq_id, None)
        self._free_seq_ids.append(seq_id)

    # ─── the decode step ─────────────────────────────────────────────────

    def step(self) -> list[StepToken]:
        """Run one batched forward pass across all active slots.

        Builds one batch from every active slot's pending tokens, calls
        ``decode`` once, samples each slot's next token, appends it, and
        reports it. Slots that hit ``max_tokens`` or a stop token are
        marked done and released. Returns the tokens produced this step
        (one per slot that generated), i.e. the demux.
        """
        self._admit()
        if not self._slots:
            return []

        entries = [
            BatchEntry(seq_id=slot.seq_id, tokens=slot.pending, wants_logits=True)
            for slot in self._slots.values()
        ]
        logits_by_seq = self._backend.decode(entries)

        produced: list[StepToken] = []
        finished: list[int] = []
        for seq_id, slot in self._slots.items():
            slot.prefixed = True
            logits = logits_by_seq.get(seq_id)
            if logits is None:
                continue
            token = _argmax(logits)
            slot.generated.append(token)
            # Next step feeds back only the freshly sampled token.
            slot.pending = [token]

            is_stop = token in self._current_stops.get(seq_id, ())
            hit_cap = len(slot.generated) >= slot.max_tokens
            slot.done = is_stop or hit_cap
            produced.append(StepToken(seq_id=seq_id, token=token, done=slot.done))
            if slot.done:
                finished.append(seq_id)

        for seq_id in finished:
            self._release(seq_id)
        return produced

    # ─── convenience: drive one request to completion ────────────────────

    _current_stops: dict[int, tuple[Token, ...]]

    def run(self, request: GenerationRequest) -> Iterator[Token]:
        """Submit one request and yield its tokens until it finishes.

        A thin driver over ``submit``/``step`` for the single-request
        (N=1) path the engine's ``chat_stream`` uses. Yields each
        generated token in order.
        """
        self.submit(request)
        # Track stops per admitted seq so step() can see them.
        self._current_stops = {}
        while self._queue or self._slots:
            # Bind stop tokens to whatever slot the request lands in.
            for seq_id, slot in self._slots.items():
                if seq_id not in self._current_stops and not slot.generated:
                    self._current_stops[seq_id] = request.stop_tokens
            produced = self.step()
            for st in produced:
                yield st.token
