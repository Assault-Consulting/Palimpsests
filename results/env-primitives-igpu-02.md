# Bench report — Run 0.2: acceptance re-run on the 0.5.1 hot-path fix — iGPU/Vulkan

- Run ID:            env-primitives-igpu-02
- Date / operator:   2026-07-13 / Oleksandr
- Config-hash:       dd2e395be22675f1 (supersedes 45fe13f2fdde1f5f: the
  Palimpsests pin moved because the measured code changed — see pin chain)

## Config (pinned)

```
palimpsests: 7745853f3d5fdc40bef01c7fac46889eeb07e501 (0.5.1.dev0; hot-path fix 50d9789 backend numpy logits + b14e3ff scheduler numpy argmax)
llama-cpp-python: 0.3.33 (source build, CMAKE_ARGS=-DGGML_VULKAN=on; vendors llama.cpp 78d2f524682d9fee790a6460c93d018dafeb5229 per the v0.3.33 tag submodule)
llama-server: build 9874, commit 78d2f524682d9fee790a6460c93d018dafeb5229 (MSVC 19.44.35228.0, -DGGML_VULKAN=ON) — same llama.cpp commit as the backend (same-build discipline)
model 1.5B: qwen2.5-1.5b-instruct-q4_k_m.gguf Q4_K_M sha256=6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e
model 7B part1: qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf Q4_K_M sha256=dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db
model 7B part2: qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf Q4_K_M sha256=539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a
vulkan driver: 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics
n_ctx: 8192  n_batch: 8192  ngl: 999 (effective: full offload 29/29 on both models)
sampling: greedy (temp 0)
```

## Pin chain (documented per Run 0.1 precedent)

- `a0acfbd` — campaign pin for Run 0 / Run 0.1 (measured code), hash 9a68a724
  → 45fe13f2 (Run 0.1: baseline rebuild).
- `7745853` — NEW campaign pin (this run onward): main after merge of PR #63
  (`fix/decode-logits-numpy`, 0.5.1.dev0) — the maintainer's hot-path fix for
  the implementation confound root-caused in Run 0.1. Fix commits: `50d9789`
  (backend: decode wraps the C logits buffer as numpy — bulk memcpy, no
  per-token float boxing), `b14e3ff` (scheduler: `_argmax` over numpy — C
  argmax, no Python vocab loop), `981e44e`/`b7cb6ab` (TYPE_CHECKING import
  guards, CI-only). Diff vs `a0acfbd` verified to touch ONLY the logits/argmax
  hot path (+ protocol type annotation, version bump, and the maintainer's
  Python-level test `tests/test_native_argmax.py` covering tie-break and
  float32/64); nothing else in native/ changed, so the hardware revalidation
  scope is exactly the hot path.
- Run 0.1 PR #61: MERGED (2026-07-13).

## Pre-registration (written BEFORE running)

Expectation: with the 0.5.1 hot-path fix (argmax without per-token logits
boxing), raw decode through our backend closes most of the ~30% gap to
llama-server (was 31 vs 44.4 tok/s, same engine commit 78d2f524), and the
three-arm control (50x1, 5 repeats) lands within 0.9–1.2 pairwise. Residual
scheduler/session per-token overhead may keep ours slightly below the
server's raw speed. Would disappoint if: the gap persists near its prior
size — the cause is then not logits boxing; or any pairwise control ratio
stays outside 0.9–1.2. We commit to reporting whichever outcome occurs.

## Results

### 1. Hardware revalidation gate — primitives on 0.5.1 (BEFORE any timing)

1.5B, full set (`benchmarks/validate_primitives.py`): **8/8 PASS**. The
generation-identity evidence the maintainer could not produce without
hardware: `multi_token_prefill` argmax (12095), `two_sequence_batch` argmax
pair (12095/220), the `seq_copy_seed_pos` continuation text
(" Paris. The capital of Italy is Rome. …") and the `state_roundtrip`
144120-byte blob with token-identical 16/16 post-restore continuation are
ALL byte/token-identical to the pre-fix Run 0 outputs — the fix changed
speed, not generation.

7B, basic set: 3/3 PASS (construction / tokenize round-trip / single decode,
n_vocab 152064).

### 2. Raw decode, same engine commit (78d2f524), single stream, 1.5B

| path | method | tok/s |
|---|---|---|
| our backend, **pre-fix** (Run 0/0.1 reference) | sustained 30 s windows | ~31 |
| llama-server b9874 (target reference) | 128-tok burst | 44.4 |
| **our backend, 0.5.1** | 128-tok burst, 5 repeats | **52.4 median [51.0–52.9]** |
| **our backend, 0.5.1** | sustained 30 s windows ×3 | **51.8 / 51.6 / 51.4** |

The gap did not merely close — it inverted: in-process decode now beats the
same-engine server path by ~18% (no HTTP/SSE per-token emission). The ~40%
per-token cost removed by the fix (31 → 52 tok/s) exceeds the ~30% originally
attributed to logits boxing alone; the Python argmax loop over the 152k-entry
vocab, also removed, accounts for the rest.

### 3. Three-arm acceptance control (prefix=50, hops=1, 5 timed repeats, cool-downs between arms)

| arm | median [min–max] | TTFT |
|---|---|---|
| ours, 0.5.1 (live-KV tool loop) | 1.375 s [1.350–1.379] | 0.079 s |
| mechanism, 0.5.1 (re-prefill) | 1.350 s [1.342–1.356] | 0.079 s |
| honest (llama-server b9874 slot reuse) | 1.646 s [1.634–1.659] | 0.209 s |

Pairwise ratios (larger/smaller):

| pair | ratio | band 0.9–1.2 |
|---|---|---|
| ours vs mechanism | 1.02 | PASS |
| **server vs ours** | **1.197** | **PASS** (ours now the faster arm) |
| server vs mechanism | **1.219** | **FAIL — by 1.6%** |

For reference, ours was 2.392 s on this exact point before the fix
(ours/server 1.37); it is now 1.375 s. Slot-cache reset self-verified per
repeat; erase endpoint used (long-lived server).

## Observation

Verdict vs the pre-registration: **mixed, dominated by confirmation**.

- The core expectation is CONFIRMED emphatically: the raw-decode gap was the
  logits/argmax hot path. 31 → 52.4 tok/s; ours now exceeds the same-engine
  server's raw decode. The confound found in Run 0.1 is fixed and the fix is
  proven generation-identical on hardware (§1).
- The control band is NOT fully met, but the failing pair does not involve
  our treatment arm: both pairs with "ours" are in band (1.02, 1.197); the
  1.219 outlier is between the two BASELINES — the native mechanism arm vs
  the HTTP server arm at a tiny point where the server's fixed per-hop cost
  (HTTP + SSE streaming + template/tokenize round-trip; visible as TTFT
  0.209 s vs 0.079 s) is a large fraction of a 1.4-s total. This residual is
  a property of the server baseline's transport, not of our stack; it will
  shrink as points grow (fixed cost over larger totals).
- Per the pre-registered disappointment clause taken literally ("any
  pairwise control ratio stays outside 0.9–1.2"), this is reported as a
  band miss and the Run 1 go/no-go decision is the maintainer's. The
  residual tax is measured and documented: ~0.27 s per repeat at the control
  point, ~0.13 s per hop, attributable to the server arm's HTTP/SSE
  round-trip.

## Next step

STOP after this PR per protocol: the control did not fully land in band
(server-vs-mechanism 1.219). Decision on opening Run 1 with the current
environment — or on adjusting the band/point definition for baseline-pair
comparisons — belongs to the maintainer. Both pairs involving our arm are in
band; primitives are green and generation-identical; the environment is
otherwise ready.
