# v0.4 tool-loop measurement report

## Expected (written BEFORE running)
- Treatment (tool-loop) beats baseline (re-prefill) on wall time.
- The margin GROWS with --prefix-tokens and --hops.
- Control case (--prefix-tokens 50 --hops 1): arms should be CLOSE.
- A flat or <1x result at large prefix/hops = a REAL negative. Keep it.

## Environment
- commit: 55742b34ec20ca45a689e05bd1fbf6143c56a37f
- llama-cpp-python version: 0.3.33 (built from source, CPU wheel)
- model file / quant / source: qwen2.5-1.5b-instruct-q4_k_m.gguf / Q4_K_M / https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF (1.1 GB)
- GPU: CPU only (Docker, no GPU passthrough)
- OS / CPU / RAM: Debian 12.14 (bookworm) container on Docker Desktop (Windows 11 host); Intel(R) Core(TM) Ultra 9 185H, 22 threads visible; 15 GiB RAM in container VM

## Local patches

### Patch 1 — set ctx_params.n_batch = n_ctx (applied AFTER configs 50/1, 500/4, 2000/8; BEFORE config 4000/12)

Failure observed: config prefix=4000 hops=12 aborted with
`GGML_ASSERT(n_tokens_all <= cparams.n_batch) failed` inside `llama_decode`
(llama-context.cpp:1748). Cause: the backend never set the logical batch
size on context creation, so it stayed at the llama.cpp default (2048),
smaller than the ~4000-token single-call prefix prefill. This is a
context-creation shim fix in the one file patches are allowed in; the
measured decode logic is untouched. The earlier three configs never
exceeded 2048 tokens per decode call and were unaffected. The control
config was re-run after the patch as a consistency check (see Results).

```diff
diff --git a/src/palimpsests/providers/native/llamacpp_backend.py b/src/palimpsests/providers/native/llamacpp_backend.py
index ada17c0..2b120f8 100644
--- a/src/palimpsests/providers/native/llamacpp_backend.py
+++ b/src/palimpsests/providers/native/llamacpp_backend.py
@@ -122,6 +122,12 @@ class LlamaCppBackend:
         # single most likely first-run AttributeError — isolated here.
         ctx_params = _lib.llama_context_default_params()
         ctx_params.n_ctx = n_ctx
+        # First-run fix: llama.cpp asserts n_tokens_all <= n_batch inside
+        # llama_decode. The default logical batch (2048) is smaller than a
+        # large single-call prefill (e.g. a 4000-token prefix), which
+        # aborts the process. The logical batch must admit the largest
+        # prefill we can ever pass, which is bounded by n_ctx.
+        ctx_params.n_batch = n_ctx
         ctx_params.n_seq_max = n_seq_max
         if n_threads is not None:
             ctx_params.n_threads = n_threads
```

## Results

### config: prefix=50 hops=1 (control)
```json
{
  "env": {
    "python": "3.12.13",
    "platform": "Linux-6.6.114.1-microsoft-standard-WSL2-x86_64-with-glibc2.36",
    "processor": "",
    "model": "models/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "hops": 1,
    "prefix_tokens_requested": 50,
    "prefix_tokens_measured": 27,
    "n_ctx": 8192,
    "n_gpu_layers": 0,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 2.653555808996316,
    "total_seconds_min": 2.6362140150013147,
    "total_seconds_max": 2.7226224079931853,
    "ttft_seconds_median": 0.24276102300791536
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 2.8582721970014973,
    "total_seconds_min": 2.7734144240093883,
    "total_seconds_max": 2.8892509690049337,
    "ttft_seconds_median": 0.24616113099909853
  },
  "speedup_baseline_over_treatment": 1.0771479489186297
}
```
speedup: 1.08x

### config: prefix=500 hops=4
```json
{
  "env": {
    "python": "3.12.13",
    "platform": "Linux-6.6.114.1-microsoft-standard-WSL2-x86_64-with-glibc2.36",
    "processor": "",
    "model": "models/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "hops": 4,
    "prefix_tokens_requested": 500,
    "prefix_tokens_measured": 363,
    "n_ctx": 8192,
    "n_gpu_layers": 0,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 9.963734744000249,
    "total_seconds_min": 9.298966507994919,
    "total_seconds_max": 10.666480867002974,
    "ttft_seconds_median": 2.809733693007729
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 21.365218470004038,
    "total_seconds_min": 21.156695323996246,
    "total_seconds_max": 21.916646743004094,
    "ttft_seconds_median": 2.7792685000022175
  },
  "speedup_baseline_over_treatment": 2.144298199314197
}
```
speedup: 2.14x

### config: prefix=2000 hops=8
```json
{
  "env": {
    "python": "3.12.13",
    "platform": "Linux-6.6.114.1-microsoft-standard-WSL2-x86_64-with-glibc2.36",
    "processor": "",
    "model": "models/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "hops": 8,
    "prefix_tokens_requested": 2000,
    "prefix_tokens_measured": 1491,
    "n_ctx": 8192,
    "n_gpu_layers": 0,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 27.929358143010177,
    "total_seconds_min": 27.254383924999274,
    "total_seconds_max": 33.73429793698597,
    "ttft_seconds_median": 12.880698837005184
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 130.36884471800295,
    "total_seconds_min": 127.13015272399934,
    "total_seconds_max": 149.69166677499015,
    "ttft_seconds_median": 12.57922764099203
  },
  "speedup_baseline_over_treatment": 4.667806687517095
}
```
speedup: 4.67x

### config: prefix=50 hops=1 (control RE-RUN after Patch 1, consistency check)
treatment median 2.710s [2.642-2.751], baseline median 2.846s [2.838-2.947]
speedup: 1.05x (pre-patch control was 1.08x — patch did not perturb timings)

### config: prefix=4000 hops=12
```json
{
  "env": {
    "python": "3.12.13",
    "platform": "Linux-6.6.114.1-microsoft-standard-WSL2-x86_64-with-glibc2.36",
    "processor": "",
    "model": "models/qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "hops": 12,
    "prefix_tokens_requested": 4000,
    "prefix_tokens_measured": 2979,
    "n_ctx": 8192,
    "n_gpu_layers": 0,
    "repeats": 5,
    "sampling": "greedy"
  },
  "treatment": {
    "label": "treatment_l3_tool_loop",
    "repeats": 5,
    "total_seconds_median": 52.98757980600931,
    "total_seconds_min": 52.24437639499956,
    "total_seconds_max": 54.41689140400558,
    "ttft_seconds_median": 27.729450253988034
  },
  "baseline": {
    "label": "baseline_reprefill",
    "repeats": 5,
    "total_seconds_median": 382.8960489960009,
    "total_seconds_min": 373.2887125240086,
    "total_seconds_max": 398.8325429980032,
    "ttft_seconds_median": 27.187398303009104
  },
  "speedup_baseline_over_treatment": 7.22614715368783
}
```
speedup: 7.23x

Note: this config initially ABORTED with GGML_ASSERT(n_tokens_all <= cparams.n_batch)
before Patch 1 (see Local patches); the number above is from the re-run after the patch.

## Interpretation (vs Expected)

All four pre-registered expectations held. The control case (prefix=50, hops=1)
showed near-parity between the arms (1.08x pre-patch, 1.05x post-patch re-run),
which is what an un-rigged harness should show at negligible prefix. The margin
grew monotonically with prefix and hops: 1.08x (50/1) -> 2.14x (500/4) ->
4.67x (2000/8) -> 7.23x (4000/12), and the growth tracks the amount of prefix
re-prefill work the baseline repeats per hop, which is the mechanism the tool
loop is supposed to eliminate. TTFT medians are near-identical between arms in
every config, confirming the win comes from the hop loop, not from a first-fill
asymmetry. No negative result to record. Caveat: this was measured on CPU
(Docker, no GPU) with a 1.5B Q4_K_M model and greedy sampling — it is a sanity
check that the KV-reuse mechanism works and scales in the expected direction,
NOT a representative performance figure; GPU and larger-model runs are a separate
exercise. Also note prefix_tokens_measured < requested in every config (e.g.
2979 vs 4000), so the effective prefix sizes are somewhat smaller than the
nominal sweep labels.
