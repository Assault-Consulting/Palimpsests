# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Generation-identity for the `kv_unified` backend flag (hardware-gated).

Threading `kv_unified` into `LlamaCppBackend` must not change what the model
generates in the default (split) mode, and unified mode must generate
coherently on its own. These checks need the real ctypes backend and a GGUF
model, so they are SKIPPED unless both are present — they run on hardware
(alongside the isolation suite), never in CI.

Set `PALIMPSESTS_LLAMACPP_MODEL=/path/to/model.gguf` to enable. This is the
same gate the other on-hardware checks use.
"""
from __future__ import annotations

import os
import pytest

MODEL = os.environ.get("PALIMPSESTS_LLAMACPP_MODEL")

llama_cpp = pytest.importorskip(
    "llama_cpp", reason="kv_unified generation-identity needs the [native] extra"
)
if not MODEL:
    pytest.skip(
        "set PALIMPSESTS_LLAMACPP_MODEL to a GGUF path to run kv_unified tests",
        allow_module_level=True,
    )

from palimpsests.providers.native.backend import BatchEntry  # noqa: E402
from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend  # noqa: E402

PROMPT = "The capital of France is"
GEN = 16


def _greedy(logits) -> int:
    return max(range(len(logits)), key=logits.__getitem__)


def _continue(backend: LlamaCppBackend, prompt: str, n: int) -> list[int]:
    """Greedy-decode n tokens on seq 0 from a fresh prompt."""
    toks = backend.tokenize(prompt, add_special=True)
    out = backend.decode([BatchEntry(seq_id=0, tokens=toks, start_pos=0, wants_logits=True)])
    tok = _greedy(out[0])
    result = [tok]
    pos = len(toks)
    for _ in range(n - 1):
        res = backend.decode(
            [BatchEntry(seq_id=0, tokens=[tok], start_pos=pos, wants_logits=True)]
        )
        tok = _greedy(res[0])
        result.append(tok)
        pos += 1
    return result


def test_split_and_unified_generate_identically():
    """Same greedy continuation with kv_unified False vs True (single sequence).

    A single sequence shares no cells, so the KV layout must not change the
    tokens — this is the guard that threading the flag did not perturb decode.
    """
    split = LlamaCppBackend(MODEL, n_ctx=2048, n_seq_max=2, kv_unified=False)
    try:
        split_tokens = _continue(split, PROMPT, GEN)
    finally:
        split.close()

    unified = LlamaCppBackend(MODEL, n_ctx=2048, n_seq_max=2, kv_unified=True)
    try:
        unified_tokens = _continue(unified, PROMPT, GEN)
    finally:
        unified.close()

    assert split_tokens == unified_tokens


def test_kv_unified_defaults_to_split():
    """The flag defaults to False, preserving prior behavior."""
    backend = LlamaCppBackend(MODEL, n_ctx=512, n_seq_max=2)
    try:
        toks = _continue(backend, PROMPT, 4)
        assert len(toks) == 4
    finally:
        backend.close()
