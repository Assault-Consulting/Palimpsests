"""Shared tool-loop workload content — single source of truth for both arms.

Extracted from ``bench_tool_loop.py`` (0.4 harness) so that the llama-server
arm (``bench_tool_loop_server.py``) drives byte-identical content through a
different engine, per BENCHMARKING.md §2 (one variable at a time). Any change
here changes EVERY arm of the N5 benchmark at once — never one arm alone.
"""

from __future__ import annotations

# One user turn opens the loop; each hop then appends one tool result.
BEGIN_MESSAGE = "Begin the task."

# Fixed short generation per turn (the win is avoided prefill, not verbosity).
GEN_TOKENS = 32


def big_system_prompt(target_tokens: int) -> str:
    """A filler system prompt of roughly ``target_tokens`` tokens.

    The point of the benchmark is the COST of carrying this prefix, so its
    content is irrelevant — only its length matters. Rough 4 chars/token
    heuristic; the exact count is measured from the tokenizer at runtime
    and recorded, so the approximation here does not affect honesty.
    """
    sentence = (
        "You are a meticulous assistant operating under a large, fixed "
        "system context that must be carried across every step of the task. "
    )
    reps = max(1, (target_tokens * 4) // len(sentence))
    return sentence * reps


def tool_call_id(hop: int) -> str:
    """The id the loop assigns to hop N's tool call."""
    return f"call_{hop}"


def tool_result(hop: int) -> str:
    """The payload the simulated tool returns on hop N."""
    return f"tool {hop} returned value {hop * 7}"
