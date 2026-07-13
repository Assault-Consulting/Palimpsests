"""Primitive-level validation of the native backend (RUNBOOK Step 3).

Runs the backend primitives one at a time, cheapest first, so a failure is
unambiguous — this is the "Run 0" gate before any 0.5-campaign sweep. Where
the RUNBOOK asks for a coherence judgement (the seq_copy seed-position trap),
this script replaces eyeballing with an exact check: greedy continuations
from the source and the copied sequence must be token-identical, because a
correct KV copy makes the logits identical.

Usage:
    python benchmarks/validate_primitives.py --model models/M.gguf [--basic] \
        [--n-gpu-layers 999] [--n-ctx 2048]

--basic runs only construction + tokenize round-trip + single decode (the
"is this model alive on this environment" check for a second model); the
default runs the full RUNBOOK Step 3 list.

Exit code 0 = all attempted checks passed; 1 = at least one failed.
"""
from __future__ import annotations

import argparse
import sys

from palimpsests.providers.native.backend import BatchEntry
from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend

PROMPT_A = "The capital of France is"
PROMPT_B = "Water boils at a temperature of"
GEN_LEN = 16  # tokens per greedy continuation in the copy/state checks


def greedy(logits: list[float]) -> int:
    return max(range(len(logits)), key=logits.__getitem__)


def generate_greedy(backend, seq_id: int, start_pos: int, first_logits, n: int):
    """Greedy-decode n tokens on seq_id starting from first_logits at start_pos."""
    out = []
    tok = greedy(first_logits)
    out.append(tok)
    pos = start_pos
    for _ in range(n - 1):
        res = backend.decode(
            [BatchEntry(seq_id=seq_id, tokens=[tok], start_pos=pos, wants_logits=True)]
        )
        tok = greedy(res[seq_id])
        out.append(tok)
        pos += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--basic", action="store_true",
                    help="construction + tokenize + single decode only")
    ap.add_argument("--n-gpu-layers", type=int, default=999)
    ap.add_argument("--n-ctx", type=int, default=2048)
    args = ap.parse_args()

    results: list[tuple[str, str, str]] = []

    def record(name: str, status: str, detail: str = "") -> None:
        results.append((name, status, detail))
        print(f"[{status}] {name}" + (f" — {detail}" if detail else ""), flush=True)

    backend = None
    try:
        # ── 0. construction ────────────────────────────────────────────────
        backend = LlamaCppBackend(
            args.model, n_ctx=args.n_ctx, n_seq_max=2,
            n_gpu_layers=args.n_gpu_layers,
        )
        record("construction", "PASS", f"n_ctx={args.n_ctx} n_seq_max=2")

        n_vocab = backend._lib.llama_n_vocab(backend._vocab)

        # ── 1. tokenize / detokenize round-trip ───────────────────────────
        toks = backend.tokenize("Hello, world!", add_special=True)
        rt = backend.detokenize(toks)
        assert "Hello, world!" in rt, f"roundtrip got {rt!r}"
        record("tokenize_roundtrip", "PASS", f"{len(toks)} tokens, exact recovery")

        # ── 2. single-token decode ────────────────────────────────────────
        one = backend.tokenize(PROMPT_A, add_special=True)[:1]
        out = backend.decode(
            [BatchEntry(seq_id=0, tokens=one, start_pos=0, wants_logits=True)]
        )
        assert 0 in out, f"no logits for seq 0: keys={list(out)}"
        assert len(out[0]) == n_vocab, f"logits len {len(out[0])} != n_vocab {n_vocab}"
        record("single_decode", "PASS", f"logits len == n_vocab ({n_vocab})")
        backend.seq_remove(0)

        if args.basic:
            print("\nBASIC MODE — construction/tokenize/decode only, all green.")
            return 0

        # ── 3. multi-token prefill (logits only on last token) ────────────
        toks_a = backend.tokenize(PROMPT_A, add_special=True)
        out = backend.decode(
            [BatchEntry(seq_id=0, tokens=toks_a, start_pos=0, wants_logits=True)]
        )
        assert list(out) == [0] and len(out[0]) == n_vocab
        next_a = greedy(out[0])
        record("multi_token_prefill", "PASS",
               f"{len(toks_a)} tokens prefilled, one logits row, argmax={next_a}")
        backend.seq_remove(0)

        # ── 4. two-sequence batch (demux by seq_id) ───────────────────────
        toks_b = backend.tokenize(PROMPT_B, add_special=True)
        out = backend.decode([
            BatchEntry(seq_id=0, tokens=toks_a, start_pos=0, wants_logits=True),
            BatchEntry(seq_id=1, tokens=toks_b, start_pos=0, wants_logits=True),
        ])
        assert sorted(out) == [0, 1], f"keys={sorted(out)}"
        assert len(out[0]) == n_vocab and len(out[1]) == n_vocab
        assert greedy(out[0]) != greedy(out[1]) or out[0] != out[1], \
            "different prompts produced identical logits — demux suspect"
        record("two_sequence_batch", "PASS",
               f"argmax seq0={greedy(out[0])} seq1={greedy(out[1])}")
        backend.seq_remove(0)
        backend.seq_remove(1)

        # ── 5. seq_copy + seed position ───────────────────────────────────
        # Warm seq 0, copy to seq 1, then greedy-continue BOTH from the same
        # position: a correct copy makes the continuations token-identical.
        out = backend.decode(
            [BatchEntry(seq_id=0, tokens=toks_a, start_pos=0, wants_logits=True)]
        )
        first = out[0]
        pos = len(toks_a)
        backend.seq_copy(0, 1)
        cont_src = generate_greedy(backend, 0, pos, first, GEN_LEN)
        cont_cpy = generate_greedy(backend, 1, pos, first, GEN_LEN)
        assert cont_src == cont_cpy, (
            f"continuations diverge:\n src={cont_src}\n cpy={cont_cpy}"
        )
        text = backend.detokenize(cont_cpy)
        record("seq_copy_seed_pos", "PASS",
               f"copied-slot continuation identical to source; text={text!r}")
        backend.seq_remove(0)
        backend.seq_remove(1)

        # ── 6. seq_remove + slot reuse ────────────────────────────────────
        out = backend.decode(
            [BatchEntry(seq_id=1, tokens=toks_b, start_pos=0, wants_logits=True)]
        )
        assert len(out[1]) == n_vocab
        record("seq_remove_reuse", "PASS", "freed slot accepts a fresh prompt at pos 0")
        backend.seq_remove(1)

        # ── 7. state_get / state_set round-trip ───────────────────────────
        # Reference: prefill + greedy continuation without interruption.
        out = backend.decode(
            [BatchEntry(seq_id=0, tokens=toks_a, start_pos=0, wants_logits=True)]
        )
        first = out[0]
        pos = len(toks_a)
        blob = backend.state_get(0)
        assert len(blob) > 0, "state_get returned empty blob"
        ref = generate_greedy(backend, 0, pos, first, GEN_LEN)
        # Destroy, restore, regenerate — must match the reference exactly.
        backend.seq_remove(0)
        backend.state_set(0, blob)
        # The saved state holds the prompt KV (positions 0..pos-1); logits are
        # NOT part of per-sequence state. Continue at the next free position by
        # feeding the first reference token there — decoding into an occupied
        # position instead makes llama_decode return -1 on this build.
        out2 = backend.decode(
            [BatchEntry(seq_id=0, tokens=[ref[0]], start_pos=pos,
                        wants_logits=True)]
        )
        restored = [ref[0]] + generate_greedy(backend, 0, pos + 1, out2[0],
                                              GEN_LEN - 1)
        assert restored == ref, (
            f"post-restore continuation diverges:\n ref={ref}\n got={restored}"
        )
        record("state_roundtrip", "PASS",
               f"{len(blob)} bytes; post-restore continuation identical")
        backend.seq_remove(0)

    except AssertionError as exc:
        record(sys._getframe().f_code.co_name, "FAIL", str(exc))
    except Exception as exc:  # noqa: BLE001 - report any backend explosion
        record("unexpected_error", "FAIL", repr(exc))
    finally:
        if backend is not None:
            backend.close()

    failed = [r for r in results if r[1] == "FAIL"]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
