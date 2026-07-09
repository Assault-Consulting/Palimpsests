# v0.4 tool-loop measurement report — Intel iGPU (Vulkan), 7B model

## Expected (written BEFORE running)
- Control (prefix=50, hops=1): ~1.0 regardless of model size; if it drifts, suspect
  harness or offload, not the model.
- Primary prediction: speedup coefficients HIGHER than the 1.5B iGPU run
  (1.00 / 1.22 / 2.13 / 3.41), because prefill cost grows faster than decode cost
  with model size, and the baseline pays re-prefill on every hop.
- Stated caveat to the primary prediction: decode also gets ~4.5x more expensive
  and sits equally in both arms; the prediction holds only if prefill
  (compute-bound) scales worse than decode (memory-bound) on this shared-DDR5
  iGPU. If both scale alike, coefficients may stay roughly FLAT — a third valid
  outcome ("no model-size dependence"), record it as such.
- If coefficients come out LOWER — the most interesting outcome: something else
  became the bottleneck (memory, not compute); valid, keep honestly.
- TTFT should remain near-identical between arms in every config.
- Absolute times will grow several-fold; baseline at 4000/12 may take minutes per
  repeat.
- Memory risk named upfront: ~4.5-5 GB weights + KV at n_ctx 8192 on shared DDR5
  (31.5 GiB total). OOM unlikely, but swapping/throttling possible; if min/max
  spread exceeds ~1.2x on any config, re-run it at --repeats 10 (as done for
  2000/8 on 1.5B).

## Environment
- commit: ca33295a05cb0a2faaaa74a3b5e19638af176cab (same pinned commit as the 1.5B
  iGPU run; verified via git rev-parse before running)
- environment UNCHANGED from the 1.5B iGPU run — same .venv-vulkan, same
  llama-cpp-python 0.3.33 Vulkan build (re-verified before running:
  llama_supports_gpu_offload() == True, ggml_vulkan device = Intel(R) Arc(TM)
  Graphics, uma: 1, fp16: 1); nothing rebuilt or updated. The ONLY changed
  variable is the model.
- GPU: Intel(R) Arc(TM) Graphics (integrated, Core Ultra 9 185H), Vulkan API
  1.4.328, driver 101.8331
- model file / quant / source: qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf +
  -00002-of-00002.gguf (split GGUF, 3.72 + 0.64 = 4.36 GB total) / Q4_K_M /
  https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF; first part passed as
  --model, llama.cpp loads the split automatically
- OS / CPU / RAM: Windows 11 Pro 10.0.26200; Intel Core Ultra 9 185H, 22 logical
  cores; 31.5 GiB RAM (shared with the iGPU)
- baseline free RAM before any run: 11.3 GiB of 31.5 GiB (Docker Desktop VM and
  desktop apps hold the rest; noted so memory pressure during runs can be judged
  against this floor)
- benchmark flags: --n-gpu-layers 999 everywhere; offload verified per run via
  llama.cpp stderr; with 7B there are more layers than 1.5B (29) — full offload
  expected, and PARTIAL offload (fewer than N/N layers), if it happens, will be
  flagged explicitly because it changes interpretation

## Local patches
(none yet)

## Results

### config: prefix=50 hops=1 (control)
Offload verified: ggml_vulkan device = Intel(R) Arc(TM) Graphics; load_tensors: offloaded 29/29 layers to GPU (FULL offload — Qwen2.5-7B has 28 transformer blocks + output layer, same reported layer count as 1.5B).
Free RAM after run: 12.4 GiB (no memory pressure).
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
    "hops": 1,
    "prefix_tokens_requested": 50,
    "prefix_tokens_measured": 27,
    "n_ctx": 8192,
    "n_gpu_layers": 999,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 6.333555100020021,
    "total_seconds_min": 6.306107199983671,
    "total_seconds_max": 6.357048799982294,
    "ttft_seconds_median": 0.36880709999240935
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 6.25906179996673,
    "total_seconds_min": 6.24218820000533,
    "total_seconds_max": 6.291923700016923,
    "ttft_seconds_median": 0.36978830001316965
  },
  "speedup_baseline_over_treatment": 0.9882383118364194
}
```
speedup: 0.99x

### config: prefix=500 hops=4
Offload verified: load_tensors: offloaded 29/29 layers to GPU. Free RAM after run: 16.7 GiB.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
    "hops": 4,
    "prefix_tokens_requested": 500,
    "prefix_tokens_measured": 363,
    "n_ctx": 8192,
    "n_gpu_layers": 999,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 18.17190610000398,
    "total_seconds_min": 18.109728100011125,
    "total_seconds_max": 19.383002599992324,
    "ttft_seconds_median": 1.5938336999970488
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 24.382970899983775,
    "total_seconds_min": 23.220508400001563,
    "total_seconds_max": 25.641002299962565,
    "ttft_seconds_median": 1.6046270999941044
  },
  "speedup_baseline_over_treatment": 1.3417948984437265
}
```
speedup: 1.34x

### config: prefix=2000 hops=8
Offload verified: load_tensors: offloaded 29/29 layers to GPU. Free RAM after run: 16.7 GiB.
Spread tight (treatment min/max ratio 1.04x) — no repeats=10 re-run needed.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
    "hops": 8,
    "prefix_tokens_requested": 2000,
    "prefix_tokens_measured": 1491,
    "n_ctx": 8192,
    "n_gpu_layers": 999,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 38.89094309997745,
    "total_seconds_min": 38.39156909997109,
    "total_seconds_max": 39.76446189999115,
    "ttft_seconds_median": 7.024887600040529
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 95.74622400000226,
    "total_seconds_min": 93.81661840004381,
    "total_seconds_max": 96.22742760000983,
    "ttft_seconds_median": 7.056192199990619
  },
  "speedup_baseline_over_treatment": 2.461915715282764
}
```
speedup: 2.46x

### config: prefix=4000 hops=12
Offload verified: load_tensors: offloaded 29/29 layers to GPU.
Spread tight (treatment 63.366-64.608 s, ratio 1.02x; baseline 260.640-263.896 s, ratio 1.01x) — no re-run needed.
Memory during the ~35-min run: minimum free RAM 7.3 GiB (sampled every 20 s) — no swap pressure; free RAM recovered to 16.6 GiB after the run.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
    "hops": 12,
    "prefix_tokens_requested": 4000,
    "prefix_tokens_measured": 2979,
    "n_ctx": 8192,
    "n_gpu_layers": 999,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 63.831781700020656,
    "total_seconds_min": 63.365695400047116,
    "total_seconds_max": 64.6080123000429,
    "ttft_seconds_median": 16.263613099989016
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 261.6263477000175,
    "total_seconds_min": 260.640404500009,
    "total_seconds_max": 263.8960571999778,
    "ttft_seconds_median": 16.320822999987286
  },
  "speedup_baseline_over_treatment": 4.098684710533982
}
```
speedup: 4.10x

## Comparison 1: 1.5B iGPU vs 7B iGPU (same machine, same backend — pure model-size dependence)

| config | measured prefix | speedup 1.5B | speedup 7B | treatment median 1.5B | treatment median 7B |
|---|---|---|---|---|---|
| prefix=50, hops=1 (control) | 27 | 1.00x | 0.99x | 3.593 s | 6.334 s |
| prefix=500, hops=4 | 363 | 1.22x | 1.34x | 10.507 s | 18.172 s |
| prefix=2000, hops=8 | 1491 | 2.13x (r10) | 2.46x | 12.899 s | 38.891 s |
| prefix=4000, hops=12 | 2979 | 3.41x | 4.10x | 28.691 s | 63.832 s |

Baseline medians for reference: 1.5B 3.595 / 12.851 / 27.427 / 97.733 s;
7B 6.259 / 24.383 / 95.746 / 261.626 s.

## Comparison 2: three-way summary (speedup)

| config | CPU 1.5B | iGPU 1.5B | iGPU 7B |
|---|---|---|---|
| prefix=50, hops=1 (control) | 1.08x | 1.00x | 0.99x |
| prefix=500, hops=4 | 2.14x | 1.22x | 1.34x |
| prefix=2000, hops=8 | 4.67x | 2.13x | 2.46x |
| prefix=4000, hops=12 | 7.23x | 3.41x | 4.10x |

## Interpretation (vs Expected)

Of the three pre-registered scenarios (higher / flat / lower), the PRIMARY
prediction realized: 7B coefficients are HIGHER than 1.5B on every non-control
config (1.34 vs 1.22, 2.46 vs 2.13, 4.10 vs 3.41), consistent with prefill cost
growing faster than decode cost as the model scales — the re-prefill baseline
pays that growing cost on every hop, the tool loop pays it once. The control
stayed at 0.99x (~1.0 as predicted for any model size), and TTFT medians remain
near-identical between arms in every config (e.g. 16.26 s vs 16.32 s at
4000/12), so the win still comes exclusively from the hop loop. Offload was
FULL in every run (29/29 layers — Qwen2.5-7B reports the same layer count as
1.5B), so no partial-offload caveat applies; memory never became the
bottleneck (minimum free RAM 7.3 GiB during the longest run, no swap), so the
"lower coefficients" scenario had no trigger. Spreads were tight throughout
(max min/max ratio 1.07x) — no repeats=10 re-run was needed this time. Same
standing caveat as the previous runs: this is a mechanism check on an
integrated GPU, not a representative discrete-GPU figure.
