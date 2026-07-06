"""Context window management — StreamingLLM's principle at message level.

The research finding behind this: the first few tokens of a sequence
("attention sinks") absorb a wildly disproportionate share of attention
mass, and evicting them under a naive sliding window makes perplexity
explode. Keep a stable prefix plus a recent window and the model stays
coherent far past its nominal context length.

We apply that one level up, on whole messages rather than KV tokens:

    [SINK:   system prompt + first N messages]  <- never evicted
    [EVICTED MIDDLE: older messages]            <- dropped (or, later,
                                                    retrieved back by
                                                    BlockMemory in I5)
    [WINDOW: most recent W messages]            <- always kept

Two properties fall out of this for free:

- **Coherence.** The sink carries the task framing (system prompt,
  opening turns); keeping it stable is why eviction doesn't derail the
  model the way blind truncation does.
- **Prefix-cache reuse.** Because the sink is byte-stable across calls,
  the engine's prompt/prefix cache keeps hitting on it — Idea 3 in the
  design, obtained by construction rather than as separate machinery.

What this class does NOT do: it never splits a message. Cutting a
user turn in half leaves the model a fragment with no role, so eviction
is whole-message. It also doesn't retrieve evicted content back — that
is BlockMemory's job (I5). Here, evicted messages are simply reported
so a caller (or BlockMemory) can decide what to do with them.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from palimpsests.context.tokens import TokenCounter, default_token_counter
from palimpsests.engine import Message


@dataclass(frozen=True)
class FitResult:
    """The outcome of fitting a conversation to a budget.

    ``messages`` is what to actually send (sink + surviving window).
    ``evicted`` is the middle that was dropped, in original order, so a
    caller can archive or index it. ``token_estimate`` is the counted
    size of ``messages`` — useful for logging and tests.
    """

    messages: list[Message]
    evicted: list[Message] = field(default_factory=list)
    token_estimate: int = 0


class ContextWindowManager:
    """Fits a growing conversation into a token budget.

    Sink = the system prompt (if present) plus the first
    ``sink_messages`` non-system messages. Window = the most recent
    ``window_messages``. When sink + window + middle exceed the usable
    budget, the middle is evicted oldest-first until it fits.

    The usable budget is ``context_size`` scaled by ``safety_margin``
    (default 0.8), because the token count is an estimate: leaving
    headroom means an estimation error costs a few wasted tokens, not
    an overflow.
    """

    def __init__(
        self,
        *,
        context_size: int,
        sink_messages: int = 2,
        window_messages: int = 8,
        safety_margin: float = 0.8,
        token_counter: TokenCounter | None = None,
    ) -> None:
        if context_size <= 0:
            raise ValueError("context_size must be positive")
        if not 0.0 < safety_margin <= 1.0:
            raise ValueError("safety_margin must be in (0, 1]")
        if sink_messages < 0 or window_messages < 0:
            raise ValueError("sink/window message counts must be >= 0")
        self._context_size = context_size
        self._sink_messages = sink_messages
        self._window_messages = window_messages
        self._budget = int(context_size * safety_margin)
        self._count = token_counter or default_token_counter()

    # ─── public API ──────────────────────────────────────────────────────

    def fit(self, messages: Sequence[Message]) -> FitResult:
        """Return the messages to send, evicting the middle if needed.

        Never splits a message; never drops a sink or window message.
        If sink + window alone already exceed the budget, nothing more
        can be evicted (they are protected), so they are returned as-is
        and the caller must cope with an over-budget prompt — better a
        known overflow of protected content than silent corruption.
        """
        msgs = list(messages)
        if not msgs:
            return FitResult(messages=[], evicted=[], token_estimate=0)

        sink, middle, window = self._partition(msgs)

        # Start from sink + window (always kept) and add as much of the
        # middle back as fits, newest-middle-first so the most recent
        # context survives.
        kept_middle: list[Message] = []
        evicted: list[Message] = []
        base_tokens = self._tokens(sink) + self._tokens(window)

        running = base_tokens
        # Walk the middle from newest to oldest, keeping what fits.
        for msg in reversed(middle):
            cost = self._message_tokens(msg)
            if running + cost <= self._budget:
                kept_middle.append(msg)
                running += cost
            else:
                evicted.append(msg)
        kept_middle.reverse()  # restore chronological order
        evicted.reverse()

        final = sink + kept_middle + window
        return FitResult(
            messages=final,
            evicted=evicted,
            token_estimate=self._tokens(final),
        )

    # ─── internals ───────────────────────────────────────────────────────

    def _partition(
        self, msgs: list[Message]
    ) -> tuple[list[Message], list[Message], list[Message]]:
        """Split messages into (sink, middle, window).

        The sink is the leading system message(s) plus the first
        ``sink_messages`` messages overall. The window is the last
        ``window_messages``. Whatever remains between them is the
        middle. Sink and window never overlap: if the conversation is
        short enough that they would, the window yields to the sink
        (the sink's framing is the more load-bearing of the two).
        """
        n = len(msgs)
        sink_end = min(self._sink_messages, n)

        # Extend the sink to include a leading system message even if it
        # sits beyond sink_messages count-wise (there is normally one).
        # We include contiguous leading system messages first.
        lead_system = 0
        for m in msgs:
            if m.get("role") == "system":
                lead_system += 1
            else:
                break
        sink_end = min(max(sink_end, lead_system), n)

        window_start = max(sink_end, n - self._window_messages)

        sink = msgs[:sink_end]
        window = msgs[window_start:]
        middle = msgs[sink_end:window_start]
        return sink, middle, window

    def _message_tokens(self, msg: Message) -> int:
        """Token estimate for one message: its content plus a small
        per-message overhead for role/formatting scaffolding."""
        return self._count(msg.get("content", "")) + 4

    def _tokens(self, msgs: Sequence[Message]) -> int:
        return sum(self._message_tokens(m) for m in msgs)
