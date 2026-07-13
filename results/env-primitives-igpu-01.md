# Bench report — Run 0.1: baseline rebuild on the vendored llama.cpp commit — iGPU/Vulkan

- Run ID:            env-primitives-igpu-01
- Date / operator:   2026-07-10 / Oleksandr
- Config-hash:       45fe13f2fdde1f5f (NEW — supersedes 9a68a724ef58b2b2 for
  runs 1–6; the old hash remains valid history for Run 0)

## Config (pinned)

```
llama-cpp-python: 0.3.33 (source build, CMAKE_ARGS=-DGGML_VULKAN=on; vendors llama.cpp 78d2f524682d9fee790a6460c93d018dafeb5229 per the v0.3.33 tag submodule)
llama-server: build 9874, commit 78d2f524682d9fee790a6460c93d018dafeb5229 (MSVC 19.44.35228.0, -DGGML_VULKAN=ON) — same llama.cpp commit as the backend (same-build discipline)
model 1.5B: qwen2.5-1.5b-instruct-q4_k_m.gguf Q4_K_M sha256=6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
model 7B part1: qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf Q4_K_M sha256=dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db
model 7B part2: qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf Q4_K_M sha256=539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a
vulkan driver: 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics
n_ctx: 8192  n_batch: 8192  ngl: 999 (effective: full offload 29/29 on both models)
sampling: greedy (temp 0)
```

The gap fixed by this run: the Run 0 baseline was built from llama.cpp master
(b9990, 259ae1df8) while the backend's vendored engine is 78d2f524. The exact
vendored commit was resolved from the `vendor/llama.cpp` submodule of the
`abetlen/llama-cpp-python` `v0.3.33` tag (GitHub API, not guessed). Both the
old build (`build/`) and the pinned build (`build-pinned/`) are kept on disk;
the old one is Run 0 history.

## Why this run exists

Run 1's control gate caught a three-arm control (prefix=50, hops=1, 5 timed
repeats) outside the 1.2x parity band:

| arm | median | vs ours |
|---|---|---|
| ours (live-KV tool loop) | 2.397 s | — |
| mechanism (naive re-prefill, same backend) | 2.477 s | 1.03x ✓ |
| honest (llama-server **b9990** slot reuse) | 1.749 s | **ours/server = 1.37x — out of band** |

Diagnosis at the time: mismatched engine builds (backend on the 0.3.33
vendored engine, ~31 tok/s raw decode; server on fresh master b9990,
~53 tok/s) — a direct violation of BENCHMARKING.md §1 same-build discipline.
Maintainer decision: rebuild the baseline server on the vendored commit and
re-verify (this run). The mismatched-build control artifacts are preserved
(`results/n5-sweep/*-mismatched-build.log`, untracked raw logs).

## Pre-registration (written BEFORE running)

Expectation: on the vendored-commit rebuild, the three-arm control lands
within 0.9–1.2 pairwise, and the rebuilt server's raw decode speed is close
to our backend's (~31 tok/s), confirming the 1.37x control gap was an
engine-build artifact.
Would disappoint if: the control gap persists on matched builds (the gap is
then in our stack, not the engine).

## Baseline used

llama-server rebuilt at the vendored commit (`build-pinned/`), otherwise the
exact Run 0 configuration: Vulkan, same device, `--parallel 1`, n_ctx 8192,
ngl 999, greedy. Our backend primitives were NOT re-validated: the backend
did not change in this run (explicitly noted per protocol).

## Results

### 1. Rebuild verification (mirror of Run 0 §3)

| check | status | evidence |
|---|---|---|
| `--version` | PASS | `version: 9874 (78d2f5246)`, MSVC 19.44.35228.0 |
| Vulkan device used | PASS | `Vulkan0 : Intel(R) Arc(TM) Graphics (18384 MiB)`; `llama_prepare_model_devices: using device Vulkan0` |
| Full offload | PASS | `load_tensors: offloaded 29/29 layers to GPU` |
| `/v1/chat/completions` | PASS | greedy "Hello." — coherent; fingerprint `b9874-78d2f5246` |
| `cache_prompt` slot reuse | PASS | repeat request: A `cache_n=0, prompt_n=38` → B `cache_n=37, prompt_n=1` |

### 2. Raw decode speed, same engine commit, two stacks

| path | raw decode |
|---|---|
| llama-server b9990 (master; Run 0 build) | ~53 tok/s (Run 0 logs, warm graphs) |
| **llama-server b9874 (vendored commit; this build)** | **44.4 tok/s** (128 tok, ignore_eos) |
| our backend (llama-cpp-python 0.3.33, same vendored engine) | ~31 tok/s (Run 0 thermal test, sustained) |

### 3. Acceptance control — three arms, matched builds (prefix=50, hops=1, 5 timed repeats)

| arm | median [min–max] | TTFT | vs ours |
|---|---|---|---|
| ours (live-KV tool loop) | 2.392 s [2.263–2.590] | 0.090 s | — |
| mechanism (re-prefill) | 2.305 s [2.252–2.410] | 0.091 s | 0.96x ✓ |
| honest (llama-server **b9874** slot reuse) | 1.746 s [1.700–1.817] | 0.287 s | **ours/server = 1.37x — FAIL (band 0.9–1.2)** |

Slot-cache reset between repeats verified (`cache_n == 0` after each erase);
erase endpoint used (server long-lived, graphs warm).

## Observation

Verdict vs the pre-registration: **disappointed** — and that is the finding.
The control gap did NOT move on matched builds (1.749 s → 1.746 s server-arm
median; the engine build was irrelevant at this point size). The 1.37x gap is
an **implementation confound, found and root-caused** — not "the architecture
loses":

- Root cause (exact location): `LlamaCppBackend.decode()` in
  `src/palimpsests/providers/native/llamacpp_backend.py` copies the FULL
  logits vector — `[float(ptr[j]) for j in range(n_vocab)]`, n_vocab=151,936 —
  from C into a Python list for EVERY generated token, plus per-token Python
  scheduler/session overhead. The server samples in C++ with no per-token
  Python boundary crossing. Same C engine, ~31 vs 44.4 tok/s: the ~30%
  per-token deficit lives in our Python hot path.
- Implementation vs architecture: the state-control mechanism (live-KV loop,
  slot copy, save/restore) is orthogonal to this; the mechanism-vs-ours
  parity (0.96x) and all 0.4 results compared arms on the SAME stack and are
  unaffected — their ratios measured state control, with the Python cost
  identical in both arms. Only the CROSS-stack honest ratio inherits the
  confound, which is exactly why the Run 1 control gate exists.

## Next steps

The hot-path fix is owned by the maintainer (separate product PR on his
side); after it lands, an acceptance re-run (Run 0.2) with the same
pre-registered bands will be scoped. Diagnostic material for it is contained
in this report: the root cause with the exact location in
`llamacpp_backend.decode()`, the 44.4 vs ~31 tok/s same-engine reference
points, and `benchmarks/validate_primitives.py` as the ready re-validation
tool (its token-identical checks prove a fix changed speed, not generation
results), plus the before/after measurement protocol (raw decode tok/s + the
three-arm control at 50×1, 5 repeats, bands 0.9–1.2 pairwise).

Honest scope note: with both arms now on the older vendored llama.cpp, the
campaign's absolute numbers will not reflect the current ecosystem (fresh
master is faster: graph reuse, ~53 tok/s on this device); the ratios measure
state-control mechanics, not builds. Consolidation backlog: a control check
on a fresh MATCHED stack (both arms on current llama.cpp) as a separate
campaign item.
