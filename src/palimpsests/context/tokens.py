"""Token counting — deliberately approximate, honestly so.

At level 1 (Ollama) we don't know the model's tokenizer: Qwen, Llama,
and Mistral all tokenize differently, and the daemon doesn't expose
which one a given model uses. A precise-looking count would be false
precision — we'd still be guessing, just with more machinery.

So the default is a transparent heuristic, and the real lever is that
``ContextWindowManager`` takes a ``token_counter`` you can replace. At
levels 2-3, where the tokenizer is known, a caller passes an exact
counter; the default keeps everything working with zero dependencies
everywhere else.

The heuristic errs toward *over*-counting (a low chars-per-token ratio)
so that the safety margin in the window manager evicts a little early
rather than a little late — an over-full context is an OOM, an
under-full one is just a few wasted tokens.
"""
from __future__ import annotations

from collections.abc import Callable

# Conservative: real English averages ~4 chars/token, code and
# non-Latin scripts run denser. Using 3.5 biases the estimate high so
# we evict early rather than overflow.
_CHARS_PER_TOKEN = 3.5

TokenCounter = Callable[[str], int]


def estimate_tokens(text: str) -> int:
    """Approximate the token count of a string.

    A character-ratio heuristic with a deliberate high bias. Not
    accurate for any specific tokenizer — it doesn't try to be. Its job
    is to be *safe*: consistently at or above the true count so the
    window manager never underestimates how full the context is.
    """
    if not text:
        return 0
    # Round up: a non-empty string is always at least one token.
    return max(1, int(len(text) / _CHARS_PER_TOKEN + 0.999))


def default_token_counter() -> TokenCounter:
    """The zero-dependency default counter (the heuristic above)."""
    return estimate_tokens
