"""Token-identity checks for the greedy sampler (``_argmax``).

Bench Run 0.1 traced ~30% of the per-token cost to boxing the full logits
vector and running a Python argmax loop over it. The fix returns numpy from
``decode`` and argmaxes in C. These tests pin that the *result* is unchanged
— the fix is a speed change, not a generation change — by checking
``_argmax`` against the former explicit loop, including the tie-break and the
float32-vs-float64 precision the numpy path must preserve.
"""
from __future__ import annotations

import numpy as np
from palimpsests.providers.native.scheduler import _argmax


def _reference_argmax(logits) -> int:
    """The former explicit loop: index of the *first* maximum (strict >)."""
    best_i = 0
    best_v = logits[0]
    for i, v in enumerate(logits):
        if v > best_v:
            best_v = v
            best_i = i
    return best_i


def test_argmax_basic():
    assert _argmax(np.array([0.1, 0.9, 0.2, 0.3], dtype=np.float32)) == 1


def test_argmax_accepts_plain_list():
    # Test doubles return plain Python lists; _argmax coerces via np.asarray.
    logits = [0.0] * 5
    logits[3] = 1.0
    assert _argmax(logits) == 3


def test_argmax_tiebreak_is_first_maximum():
    # Two equal maxima: the first index wins, matching the former loop.
    logits = np.array([1.0, 3.0, 3.0, 2.0], dtype=np.float32)
    assert _argmax(logits) == 1
    assert _argmax(logits) == _reference_argmax(logits.tolist())


def test_argmax_matches_reference_on_random_data():
    rng = np.random.default_rng(0)
    for _ in range(200):
        logits = rng.standard_normal(1024).astype(np.float32)
        assert _argmax(logits) == _reference_argmax(logits.tolist())


def test_argmax_float32_and_float64_agree():
    # The old path promoted float32 -> Python float (double) before comparing;
    # the new path argmaxes float32 directly. Promotion is exact and
    # monotonic, so the winning index is identical.
    rng = np.random.default_rng(1)
    for _ in range(200):
        f32 = rng.standard_normal(2048).astype(np.float32)
        assert _argmax(f32) == _argmax(f32.astype(np.float64))
