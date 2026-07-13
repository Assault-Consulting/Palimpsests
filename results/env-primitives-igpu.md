# Bench report — Run 0: environment bring-up & primitive validation — iGPU/Vulkan

- Run ID:            env-primitives-igpu
- Date / operator:   2026-07-10 / Oleksandr
- Config-hash:       9a68a724ef58b2b2

## Config (pinned)

```
llama-cpp-python: 0.3.33 (source build, CMAKE_ARGS=-DGGML_VULKAN=on; bundled llama.cpp commit not exposed at runtime — pinned via the 0.3.33 sdist)
llama-server: build 9990, commit 259ae1df8b5277a57a5092636bfcbcbb2f753219 (MSVC 19.44.35228.0, -DGGML_VULKAN=ON)
model 1.5B: qwen2.5-1.5b-instruct-q4_k_m.gguf Q4_K_M sha256=6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
model 7B part1: qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf Q4_K_M sha256=dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db
model 7B part2: qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf Q4_K_M sha256=539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a
vulkan driver: 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics
n_ctx: 8192  n_batch: 8192  ngl: 999 (effective: full offload 29/29 on both models)
sampling: greedy (temp 0)
```

The config-hash is sha256 (first 16 hex) of the block above, verbatim.

Palimpsests commit pinned for the whole 0.5 campaign:
`a0acfbd3e090f7e54ed7fc377571f73e2ff57d2c` (main). Relative to the 0.4 iGPU
runs' pin (ca33295a), the only change touching `src/palimpsests/providers/native/`
is 407c309 (H2: PALKV1 framing of the session-level state blob) — it wraps
`session.save_state`/`load_state`; the backend-level `state_get`/`state_set`
validated here are untouched by it. `benchmarks/` is unchanged.

## Hardware profile (plan §1)

| Field | Value |
|---|---|
| CPU | Intel Core **Ultra 9 185H** (22 logical cores). Note: the run plan says "Core i9" — the actual part is Core Ultra 9; corrected here rather than copied. |
| iGPU | Intel Arc Graphics (integrated in the 185H; Vulkan reports "Intel(R) Arc(TM) Graphics", uma:1, fp16:1, warp 32, no matrix cores) |
| System RAM | 31.5 GiB (shared with the iGPU; llama-server sees a 18384 MiB device budget) |
| OS | Windows 11 Pro 10.0.26200 |
| Vulkan driver / ICD | Intel 101.8331, Vulkan API 1.4.328 |
| Thermal note | laptop; sustained decode throttles ~14% after ~4 min (measured §4.3) |

## Pre-registration (written BEFORE running)

Expectation: all backend primitives green on the Vulkan backend, and a working
llama-server Vulkan baseline with confirmed slot reuse (`cache_prompt`).
Would disappoint if: any primitive fails, or `cache_prompt` does not actually
reuse the slot KV (that would undermine the honest-baseline design of runs 1–4).

## Baseline used

n/a (Run 0 is bring-up; the deliverable is a verified-working honest baseline
for runs 1–4, demonstrated below).

## Results

### 1. Primitive validation — 1.5B, full set (benchmarks/validate_primitives.py)

| # | primitive | status | detail |
|---|---|---|---|
| 0 | construction | PASS | n_ctx=2048, n_seq_max=2, Vulkan device up |
| 1 | tokenize round-trip | PASS | "Hello, world!" recovered exactly |
| 2 | single-token decode | PASS | logits length == n_vocab (151936) |
| 3 | multi-token prefill | PASS | one logits row (last token only) |
| 4 | two-sequence batch | PASS | logits demux by seq_id, distinct argmax |
| 5 | seq_copy + seed pos | PASS | greedy continuation from the copied slot token-identical to the source slot (16/16) |
| 6 | seq_remove + reuse | PASS | freed slot accepts a fresh prompt at pos 0 |
| 7 | state_get/state_set round-trip | PASS | 144120-byte blob; post-restore greedy continuation token-identical to uninterrupted run (16/16) |

Offload: `load_tensors: offloaded 29/29 layers to GPU` (from the validation
run's stderr).

Test-harness note (not a backend defect): the first version of the
state-round-trip check re-decoded a token into an already-occupied position;
this build returns `llama_decode == -1` for that. Diagnosis confirmed
`llama_state_seq_set_data` reads back exactly the saved byte count and decoding
at the next free position works, so the check was rewritten to continue at the
next position. The committed script contains the corrected check.

### 2. Primitive validation — 7B (split GGUF), basic set

construction / tokenize round-trip / single decode: all PASS
(n_vocab=152064; `offloaded 29/29 layers to GPU` — full offload; llama.cpp
loads the two-part split automatically from part 1).

### 3. Baseline server bring-up — llama-server (Vulkan)

| check | status | evidence |
|---|---|---|
| `--version` | PASS | `version: 9990 (259ae1df8)`, MSVC 19.44.35228.0 |
| Vulkan device used | PASS | `device_info: Vulkan0 : Intel(R) Arc(TM) Graphics (18384 MiB, 17616 MiB free)`; `llama_prepare_model_devices: using device Vulkan0` |
| Full offload | PASS | `load_tensors: offloaded 29/29 layers to GPU` |
| `/v1/chat/completions` | PASS | greedy answer "Hello." to "Say hello in one word." — coherent |
| `cache_prompt` slot reuse | PASS | identical request twice with `cache_prompt:true, id_slot:0`: request A `cache_n=0, prompt_n=38`; request B `cache_n=37, prompt_n=1`; server log: `n_past was set to 37`, `prompt eval time = 21.24 ms / 1 tokens` |

Server defaults observed: `n_slots = 4`, `kv_unified = true`, device memory
budget reported 18384 MiB (shared DDR5 slice).

### 4. Environment findings that constrain the campaign

1. **Per-sequence KV budget = n_ctx / n_seq_max** on this build. Probed
   directly: with `n_ctx=512, n_seq_max=2`, decode fails with rc=1 at exactly
   position 256 (= 512/2). Consequence for all 0.5 sweeps: with `n_ctx=8192`
   and `n_seq_max=2` each sequence holds 4096 positions — enough for the ~3000
   measured-prefix points; but N4 runs with 8 concurrent sessions must budget
   `n_ctx` accordingly (8192/8 = 1024 per sequence would NOT hold a ~3000
   prefix — raise n_ctx for those points and record it, per plan §3).
2. **Decoding into an occupied position returns llama_decode -1** (see
   test-harness note above) — relevant to any future harness code that replays
   tokens.
3. **Thermal throttling is real on this laptop.** Sustained single-stream
   decode on 1.5B (iGPU): stable ≈31.5 tok/s for the first ~3.5 min, then a
   decline to 27.0 tok/s by minute 4.5 — a ~14% drop. Caveat recorded honestly:
   a light background git clone ran during part of this test, so the drop may
   mix thermal and interference effects; the campaign rule remains "no other
   load during timed runs", and long sweeps should expect the throttled regime
   after ~4 minutes. Per-arm interleaving/cool-down should be considered when a
   single point runs long.

## Reproduce (llama-server Vulkan build, Windows)

```bat
git clone https://github.com/ggml-org/llama.cpp.git && cd llama.cpp
git rev-parse HEAD   :: this run: 259ae1df8b5277a57a5092636bfcbcbb2f753219
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set VULKAN_SDK=C:\VulkanSDK\1.4.350.0
cmake -B build -DGGML_VULKAN=ON
cmake --build build --config Release --target llama-server
build\bin\Release\llama-server.exe -m <model.gguf> --n-gpu-layers 999 --ctx-size 8192 --port 8080
```

Primitive validation:

```
python benchmarks/validate_primitives.py --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf --n-gpu-layers 999
python benchmarks/validate_primitives.py --model models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf --basic --n-gpu-layers 999
```

## Observation

Shape: matches the pre-registration — every primitive green on both models,
baseline server up on the same Vulkan device with slot reuse demonstrably
working (37/38 prompt tokens served from slot KV on the repeat request).
Anomalies: none blocking; the three environment findings above are constraints
to design around, not failures. The only mid-run correction was to the new
validation script itself (occupied-position decode), diagnosed and fixed within
the allowed two attempts; the backend needed zero patches.
Verdict: **confirmed** — environment is ready for runs 1–6.
