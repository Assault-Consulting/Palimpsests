# v0.4 tool-loop measurement report — Intel iGPU (Vulkan)

## Expected (written BEFORE running)
- Control (prefix=50, hops=1): arms close, speedup within 0.9–1.2.
- Speedup >1 and grows with prefix/hops (the mechanism is hardware-independent).
- Coefficients expected LOWER than the CPU run (1.08 / 2.14 / 4.67 / 7.23) IF iGPU
  prefill is faster than CPU prefill (the baseline then loses less per hop).
- Open question stated honestly: integrated Arc with shared DDR5 memory may be
  comparable to or SLOWER than the 22-thread CPU for this workload; if absolute
  times are worse than the CPU run, that is a valid measured finding about this
  hardware, not a failure.
- The Vulkan path on an iGPU is a mechanism check, not a representative GPU
  figure (a discrete-CUDA run remains a separate item).

## Environment
- commit: ca33295a05cb0a2faaaa74a3b5e19638af176cab (main; includes the n_batch fix
  and the CPU-run report merged from PR #35)
- run mode: native Windows (no Docker) — Intel iGPU is not reliably passed into
  WSL2 containers, so this run trades the container isolation of the CPU run for
  direct hardware access
- GPU: Intel(R) Arc(TM) Graphics (integrated, Core Ultra 9 185H), Vulkan API
  1.4.328, driver 101.8331 (vulkaninfo --summary)
- llama-cpp-python: 0.3.33 (same version as the CPU run), built from source with
  CMAKE_ARGS=-DGGML_VULKAN=on; verified: llama_supports_gpu_offload() == True,
  "ggml_vulkan: Found 1 Vulkan devices: Intel(R) Arc(TM) Graphics ... uma: 1,
  fp16: 1"
- toolchain: MSVC 14.44.35207 (VS 2022 Build Tools), CMake 4.3.4, Vulkan SDK
  1.4.350.0, Python 3.12.10
- model file / quant / source: qwen2.5-1.5b-instruct-q4_k_m.gguf / Q4_K_M /
  https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF (same file as the CPU
  run, copied from the Docker volume)
- OS / CPU / RAM: Windows 11 Pro 10.0.26200; Intel Core Ultra 9 185H, 22 logical
  cores; 31.5 GiB RAM (shared with the iGPU)
- benchmark flags: --n-gpu-layers 999 everywhere; offload verified per run via
  llama.cpp stderr (ggml_vulkan device line + "offloaded N/N layers to GPU")

## Local patches
(none yet)

## Results

### config: prefix=50 hops=1 (control)
Offload verified: ggml_vulkan device = Intel(R) Arc(TM) Graphics; load_tensors: offloaded 29/29 layers to GPU.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-1.5b-instruct-q4_k_m.gguf",
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
    "total_seconds_median": 3.592819299985422,
    "total_seconds_min": 2.809496300003957,
    "total_seconds_max": 3.7243622000096366,
    "ttft_seconds_median": 0.11207679999643005
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 3.594678699999349,
    "total_seconds_min": 3.012750900001265,
    "total_seconds_max": 3.899487599992426,
    "ttft_seconds_median": 0.12158070001169108
  },
  "speedup_baseline_over_treatment": 1.0005175322939106
}
```
speedup: 1.00x

### config: prefix=500 hops=4
Offload verified: load_tensors: offloaded 29/29 layers to GPU.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-1.5b-instruct-q4_k_m.gguf",
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
    "total_seconds_median": 10.506626699992921,
    "total_seconds_min": 8.501569100015331,
    "total_seconds_max": 10.853946000017459,
    "ttft_seconds_median": 0.49176919998717494
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 12.850787000003038,
    "total_seconds_min": 10.043316600000253,
    "total_seconds_max": 13.616839100024663,
    "ttft_seconds_median": 0.4507271000184119
  },
  "speedup_baseline_over_treatment": 1.2231125523867423
}
```
speedup: 1.22x

### config: prefix=2000 hops=8 (repeats=5 — WIDE SPREAD, re-run below)
Offload verified: load_tensors: offloaded 29/29 layers to GPU.
Spread note: treatment min/max = 12.571/21.179 s (ratio 1.68x) — larger than any
CPU-run spread; iGPU is shared with the desktop/display. Re-run with --repeats 10
follows per protocol.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-1.5b-instruct-q4_k_m.gguf",
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
    "total_seconds_median": 19.55549970001448,
    "total_seconds_min": 12.570935299998382,
    "total_seconds_max": 21.17911140000797,
    "ttft_seconds_median": 2.323948000004748
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 34.727378999989014,
    "total_seconds_min": 29.283617099979892,
    "total_seconds_max": 40.55682699999306,
    "ttft_seconds_median": 2.06161139998585
  },
  "speedup_baseline_over_treatment": 1.7758369529142384
}
```
speedup: 1.78x

### config: prefix=2000 hops=8 (RE-RUN, repeats=10 — canonical for this config)
Offload verified: load_tensors: offloaded 29/29 layers to GPU.
Spread now tight: treatment min/max = 12.469/13.752 s (ratio 1.10x). The repeats=5
run above was inflated by desktop contention on the shared iGPU; this repeats=10
run supersedes it.
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "hops": 8,
    "prefix_tokens_requested": 2000,
    "prefix_tokens_measured": 1491,
    "n_ctx": 8192,
    "n_gpu_layers": 999,
    "repeats": 10,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 10,
    "total_seconds_median": 12.899141299989424,
    "total_seconds_min": 12.469283299986273,
    "total_seconds_max": 13.752052199997706,
    "ttft_seconds_median": 1.7426515500119422
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 10,
    "total_seconds_median": 27.4270405999996,
    "total_seconds_min": 25.257692400016822,
    "total_seconds_max": 30.707422200008295,
    "ttft_seconds_median": 1.7494503500056453
  },
  "speedup_baseline_over_treatment": 2.1262687152688287
}
```
speedup: 2.13x

### config: prefix=4000 hops=12
Offload verified: load_tensors: offloaded 29/29 layers to GPU.
No GGML_ASSERT this time — the n_batch fix is already in main (merged via PR #35).
```json
{
  "env": {
    "python": "3.12.10",
    "platform": "Windows-11-10.0.26200-SP0",
    "processor": "Intel64 Family 6 Model 170 Stepping 4, GenuineIntel",
    "model": "models\\qwen2.5-1.5b-instruct-q4_k_m.gguf",
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
    "total_seconds_median": 28.69142109999666,
    "total_seconds_min": 28.266121199994814,
    "total_seconds_max": 29.14284529996803,
    "ttft_seconds_median": 5.621454200008884
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 97.73309850000078,
    "total_seconds_min": 97.09787609998602,
    "total_seconds_max": 98.14004099997692,
    "ttft_seconds_median": 5.558186600042973
  },
  "speedup_baseline_over_treatment": 3.4063526571018174
}
```
speedup: 3.41x

## Comparison: CPU (Docker, previous run) vs iGPU-Vulkan (native, this run)

| config | measured prefix | speedup CPU | speedup iGPU | treatment median CPU | treatment median iGPU |
|---|---|---|---|---|---|
| prefix=50, hops=1 (control) | 27 | 1.08x | 1.00x | 2.654 s | 3.593 s |
| prefix=500, hops=4 | 363 | 2.14x | 1.22x | 9.964 s | 10.507 s |
| prefix=2000, hops=8 | 1491 | 4.67x | 2.13x (repeats=10) | 27.929 s | 12.899 s |
| prefix=4000, hops=12 | 2979 | 7.23x | 3.41x | 52.988 s | 28.691 s |

Baseline medians for reference: CPU 2.858 / 21.365 / 130.369 / 382.896 s;
iGPU 3.595 / 12.851 / 27.427 / 97.733 s.

## Interpretation (vs Expected)

All pre-registered expectations held. The control sits at 1.00x (dead parity,
inside 0.9-1.2), the speedup is >1 everywhere else and grows monotonically
(1.00x -> 1.22x -> 2.13x -> 3.41x), and every coefficient is LOWER than the CPU
run (1.08 / 2.14 / 4.67 / 7.23) — consistent with the stated mechanism: iGPU
prefill is cheaper, so the re-prefill baseline loses less per hop, while the
tool-loop advantage itself is hardware-independent in direction. Direct answer
to the pre-registered open question: on this machine the iGPU is FASTER than
the CPU in absolute wall time wherever prefill dominates (treatment 12.9 s vs
27.9 s at 2000/8, 28.7 s vs 53.0 s at 4000/12; baseline 97.7 s vs 382.9 s at
4000/12) and slightly slower on the tiny generation-dominated control
(3.59 s vs 2.65 s). One protocol deviation handled per the rules: the
repeats=5 pass at 2000/8 showed a 1.68x min/max spread from desktop contention
on the shared iGPU and was re-run at repeats=10, which tightened the spread to
1.10x; the repeats=10 result is canonical. As with the CPU run, these numbers
are a mechanism sanity check on a 1.5B Q4_K_M model — an integrated-GPU Vulkan
path, not a representative performance figure; a discrete-GPU CUDA run remains
a separate item.
