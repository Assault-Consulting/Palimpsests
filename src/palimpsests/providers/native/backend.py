"""The backend interface the level-3 scheduler is written against.

This is the seam established by ADR-0002: the scheduler, the session
state machine, and the decode loop are pure Python written against
``NativeBackend`` — an abstract interface over exactly the four
llama.cpp primitives the spike (ADR-0001) confirmed we need. Two things
implement it:

- ``FakeBackend`` (in tests) — deterministic, no model, no native code,
  so the whole scheduler is verified in CI.
- ``LlamaCppBackend`` (later, behind the ``[native]`` extra) — the thin
  real mapping onto ``llama_cpp.llama_cpp`` ctypes calls, exercised only
  on real hardware with a GGUF model.

Keeping the scheduler on this side of the seam is what lets level-3
control logic be developed and tested without a build toolchain or a
model, while the native layer stays a thin, separately-validated shim.

The interface is deliberately the *primitives*, not a high-level "chat"
call. The scheduler composes them into batching, prefix sharing, the
tool loop, and persistence — that composition is our value; the
primitives are llama.cpp's.
"""
from __future__ import annotations

import numpy as np
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# A token is an int id, as the C API deals in them. Text <-> token
# conversion is a backend concern (the model's vocab), exposed via
# tokenize/detokenize below rather than assumed here.
Token = int


@dataclass(frozen=True)
class BatchEntry:
    """One sequence's contribution to a single decode step.

    ``seq_id`` tags which sequence these tokens belong to — the field
    that makes one ``llama_decode`` serve several sequences (the
    continuous-batching primitive, ADR-0001 S1.1). ``tokens`` are the
    positions to evaluate this step; ``start_pos`` is the KV position of
    the first of them (how many tokens already sit in this sequence's KV),
    which the real ``llama_batch`` needs as each token's ``pos``.
    ``wants_logits`` marks whether the last token's logits are wanted back
    (only the sequences actually generating this step need them).
    """

    seq_id: int
    tokens: Sequence[Token]
    start_pos: int = 0
    wants_logits: bool = True


@runtime_checkable
class NativeBackend(Protocol):
    """The four-primitive surface the scheduler is written against.

    Every method maps to a confirmed llama.cpp low-level call (ADR-0001).
    Implementations own the model and context; the scheduler owns *when*
    and *in what combination* these are called.
    """

    # ─── model / vocab ───────────────────────────────────────────────────

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        """Text -> token ids, using the model's vocabulary."""
        ...

    def detokenize(self, tokens: Sequence[Token]) -> str:
        """Token ids -> text."""
        ...

    # ─── decode (the batching primitive) ─────────────────────────────────

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, np.ndarray]:
        """Run one forward pass over a multi-sequence batch.

        Maps to building a ``llama_batch`` with per-token ``seq_id`` and
        ``pos`` (from each entry's ``start_pos``) and calling
        ``llama_decode`` once. Returns, per ``seq_id`` that asked for
        logits, the logits vector (``np.ndarray``, float32) for its last
        position. The real backend returns numpy so the sampler can argmax
        in C instead of a Python loop over the vocab; consumers coerce with
        ``np.asarray``, so a test double may return any float sequence.
        Sequences sharing one ``decode`` call is the whole point of the
        level.
        """
        ...

    # ─── prefix sharing (S1.3) ───────────────────────────────────────────

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        """Copy KV cells from ``src_seq`` into ``dst_seq`` over [p0, p1).

        Maps to ``llama_memory_seq_cp``. ``-1`` bounds mean "the whole
        sequence" (the shared-prefix broadcast pattern from
        ``examples/parallel/parallel.cpp``).
        """
        ...

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        """Drop KV cells of ``seq_id`` over [p0, p1). Maps to
        ``llama_memory_seq_rm`` — used to recycle a finished slot."""
        ...

    # ─── per-sequence state (S1.2: tool loop + KV persistence) ───────────

    def state_get(self, seq_id: int) -> bytes:
        """Serialize one sequence's KV to opaque bytes.

        Maps to ``llama_state_seq_get_data``. The substrate for both the
        tool loop (pause/resume) and KV-as-memory persistence.
        """
        ...

    def state_set(self, seq_id: int, state: bytes) -> None:
        """Restore a sequence's KV from bytes. Maps to
        ``llama_state_seq_set_data``."""
        ...

    # ─── lifecycle ───────────────────────────────────────────────────────

    def n_seq_max(self) -> int:
        """Maximum number of concurrent sequences the context allows.

        The scheduler treats this as the slot count. Maps to the
        context's ``n_seq_max`` / ``llama_n_seq_max``.
        """
        ...

    def close(self) -> None:
        """Free the context and model."""
        ...
