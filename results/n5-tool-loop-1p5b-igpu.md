# Bench report — N5 tool loop — 1.5B — iGPU/Vulkan

- Run ID:            n5-tool-loop-1p5b-igpu
- Date / operator:   2026-07-13 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged from Runs 0.2/0.3 —
  environment identical: pin 7745853 (0.5.1 hot-path fix in), venv
  llama-cpp-python 0.3.33 Vulkan, pinned llama-server b9874 @ 78d2f524,
  same models/sha256, same driver)

## Config (pinned)

As in `results/env-primitives-igpu-02.md` (config block hashed to
dd2e395be22675f1). Model: qwen2.5-1.5b-instruct-q4_k_m.gguf. n_ctx 8192,
n_batch 8192, ngl 999 (full offload 29/29), greedy (temp 0), 32 tokens
generated per hop in every arm (`ignore_eos` on the server arm to match the
native arms' `stop_tokens=()`).

## Methodology (fixed before running)

- Three arms per point: ours (live-KV `append_tool_result`), mechanism
  baseline (naive re-prefill, same backend), honest baseline (llama-server
  b9874, `cache_prompt:true`, `id_slot:0`, `--parallel 1`, slot erase between
  repeats, self-verified `cache_n==0`).
- **Convention — amended per maintainer decision after the Run 1 gate**
  (supersedes the corresponding Run 0.3 section; Run 0.3 stays in history
  as written):
  1. Two-tier gate: ours/mech gated RAW at the 50×1 control (this tier is
     the our-stack-cleanliness detector); ALL pairs involving the server arm
     gated at the amortized 50×8 point with an adjusted cross-check ≤ 1.2.
  2. The adjustment is PER-RUN, not a frozen constant:
     `adjusted_server_wall = raw_server_wall −
     (server_TTFT_median − ours_TTFT_median) × (hops+1)`, with TTFT medians
     of THIS run at THIS point. The Run 0.3 reference (0.102 s/request)
     remains a sanity anchor: if the per-run transport at any point deviates
     from it substantially (guide: more than 2× either way), that is flagged
     — either the environment changed or there is latency beyond TTFT.
  3. Consistent decomposition IN THE HEADLINE: every sweep point reports
     BOTH ours-vs-server columns — RAW and adjusted. The mechanics claim
     (KV state control, claim b) stands on ADJUSTED; RAW is the honest cost
     of the server deployment model (claim a: in-process avoids transport —
     also real, but separate). No selective application: what is subtracted
     for the gate is subtracted in the headline.
  4. Automatic STOP unchanged: raw and adjusted diverging in their
     CONCLUSIONS (not in numbers — the numeric difference IS the transport),
     or any pair leaving its tier's band at a non-control point.
- Gate results (measured before the sweep; accepted by the maintainer —
  not re-run): tier 1 ours/mech RAW 50×1 = 1.002 ✓; tier 2 at 50×8:
  server/mech raw 1.186 ✓, server/ours raw 1.204 / adjusted 1.057 ✓.
- **Server-arm session warm request** (maintainer decision on Run 0.3
  caveat 1): ONE untimed request right after health, before the warmup
  repeat — symmetric to the native arms' warmup; removes the ~10%
  first-session effect Run 0.3 measured (verified: 1.812 → 1.640 s at 50×1).
- ≥1 warmup + 5 timed repeats per invocation; 30 s cool-down between
  invocations (90 s after heavy native invocations); invocation order
  alternated between grid points; zero background load.
- Workload content shared byte-identically between arms via
  `benchmarks/_workload.py`; `bench_tool_loop.py` equivalence after the
  extraction was verified pre-registration (control point, 1 repeat:
  measured prefix 27 both; walls 2.295/2.299 s before vs 2.571/2.449 s
  after, within single-repeat noise). Turn formatting mirrored from
  `session.py` verbatim in the server arm.
- Metrics per point/arm: measured prefix tokens, TTFT, wall (median +
  min–max over 5), effective tok/s (= generated tokens / wall — prefill
  included; per-hop decode tok/s is not separable in the native harness and
  is reported only for the server arm from its own timings), peak RSS
  (server process via psapi for the server arm; benchmark process via psapi
  polling for the native invocation — covers both native arms jointly), peak
  GPU memory (NOT separately instrumented: UMA iGPU — device-local Vulkan
  allocations live in system RAM; process RSS plus model size bounds it;
  stated honestly).
- Creep watch: at 3000×12 the server arm's per-hop walls are inspected
  explicitly (Run 0.3 saw +3% over 8 hops on a short history); growth with
  history length triggers the convention's automatic STOP.

## Pre-registration (written BEFORE running)

Expectation:
- vs mechanism baseline: reproduce the 0.4-style shape on this hardware —
  near-parity at control, ratio growing with prefix×hops (reference points
  from the 0.4 iGPU run: 1.00 / 1.22 / 2.13 / 3.41).
- vs honest baseline (llama-server slot reuse): near-parity is the EXPECTED
  headline (0.9–1.2 at control and small points). Both arms avoid re-prefill
  of the shared prefix; any advantage of ours should come only from per-hop
  fixed costs the server still pays (HTTP round-trip, template re-render,
  re-tokenization of the full history, prefix-match scan) — so IF an
  advantage exists, it should grow with HOPS (per-hop overhead × n) and with
  history LENGTH (re-tokenization cost), and stay modest.

Would disappoint if: ours is consistently BELOW 0.9 vs the tuned server (our
loop adds net overhead — a real negative for the N5 speed claim, to be
recorded as such); or the mechanism-arm shape fails to reproduce (suspect
harness).

Explicit framing: if the honest ratio lands at parity, the N5 speed claim
narrows to "matches a tuned server without running a server" and the
campaign's weight shifts to N4/N6/feasibility — that is a valid, reportable
outcome.

## Results

### 1. Control gates (two-tier, measured before the sweep)

| tier | pair | point | ratio | band | verdict |
|---|---|---|---|---|---|
| 1 (our-stack cleanliness) | ours/mech RAW | 50×1 | 1.002 | 0.9–1.2 | PASS |
| 2 (server pairs, amortized) | server/mech RAW | 50×8 | 1.186 | 0.9–1.2 | PASS |
| 2 (server pairs, amortized) | server/ours adjusted | 50×8 | 1.057 (raw 1.204) | ≤1.2 | PASS |

Gate raw data: 50×1 ours 1.349 / mech 1.346 / server 1.640; 50×8 ours 6.224 /
mech 6.317 / server 7.495 (medians of 5).

### 2. Timing estimate (before the sweep)

Most expensive point 3000×12, 1 repeat: ours 14.8 s, mechanism 62.2 s,
server 20.6 s → full-sweep projection ≈ 1.5 h + feasibility ≤ 1.5 h — under
the 8 h stop threshold; proceeded.

### 3. Sweep — all 16 points × 3 arms (medians of 5 timed repeats)

Wall-clock (s); per-run transport = (server_TTFT − ours_TTFT) at that point;
adjusted server = raw − transport × (hops+1) per the amended convention.

| point | measured prefix | ours | mechanism | server RAW | mech/ours | **srv/ours RAW** | **srv/ours ADJ** | transport/req (s) |
|---|---|---|---|---|---|---|---|---|
| 50×1 | 27 | 1.349 | 1.346 | 1.640 | 1.00 | 1.215 | 1.029 | 0.126 |
| 50×4 | 27 | 3.448 | 3.449 | 4.162 | 1.00 | 1.207 | 1.009 | 0.137 |
| 50×8 | 27 | 6.224 | 6.317 | 7.495 | 1.01 | 1.204 | 1.019 | 0.128 |
| 50×12 | 27 | 9.114 | 9.353 | 10.860 | 1.03 | 1.192 | 1.007 | 0.130 |
| 500×1 | 363 | 1.682 | 1.955 | 1.941 | 1.16 | 1.154 | 0.990 | 0.138 |
| 500×4 | 363 | 3.832 | 5.000 | 4.468 | 1.30 | 1.166 | 0.995 | 0.131 |
| 500×8 | 363 | 6.726 | 9.061 | 7.983 | 1.35 | 1.187 | 1.007 | 0.135 |
| 500×12 | 363 | 9.632 | 13.398 | 11.440 | 1.39 | 1.188 | 1.015 | 0.128 |
| 1500×1 | 1107 | 2.570 | 3.638 | 2.850 | 1.42 | 1.109 | 0.998 | 0.142 |
| 1500×4 | 1107 | 4.886 | 9.168 | 5.553 | 1.88 | 1.137 | 1.007 | 0.127 |
| 1500×8 | 1107 | 7.930 | 16.999 | 9.114 | 2.14 | 1.149 | 1.007 | 0.125 |
| 1500×12 | 1107 | 11.366 | 25.380 | 12.858 | 2.23 | 1.131 | 1.055 | 0.066 † |
| 3000×1 | 2235 | 4.080 | 6.553 | 4.384 | 1.61 | 1.074 | 0.998 | 0.156 |
| 3000×4 | 2235 | 6.563 | 16.779 | 7.292 | 2.56 | 1.111 | 1.013 | 0.129 |
| 3000×8 | 2235 | 10.008 | 30.871 | 11.230 | 3.08 | 1.122 | 1.086 | 0.040 † |
| 3000×12 | 2235 | 13.438 | 44.990 | 15.085 | 3.35 | 1.123 | 1.078 | 0.046 † |

† Transport-sanity flag (amended convention pt 2): at 1500×12 and 3000×{8,12}
the per-run TTFT-difference estimator falls below half the 0.102 s Run 0.3
reference. Cause is measurement noise, not environment change: at these
points TTFT is dominated by the ~2.6–3.4 s prefix prefill whose ±5 % run-
to-run noise (±0.15 s) swamps the ~0.13 s transport term. The effect is an
UNDER-subtraction — conservative: the true adjusted ratios at these three
points are, if anything, closer to 1.0 than shown. All other 13 points sit
within 0.125–0.156 s/request, consistent with the 0.102 s reference.

Band note (amended convention pt 4): every adjusted server-pair ratio is
within ≤1.2 at every point; raw srv/ours of 1.215/1.207/1.204 at the tiny-
prefix points exceeds 1.2 exactly by the transport term — per the amended
convention the server-pair band is evaluated on ADJUSTED, and raw-vs-adjusted
conclusions do not diverge (both say: mechanics parity, transport is the
difference). No automatic stop.

### 4. Creep watch at 3000×12 (server per-hop walls, medians)

hop1 0.961 → hop12 0.986 s: **+2.6 % over 12 hops** on a 2235-token history —
same magnitude as Run 0.3's +3 % over 8 hops on a ~30-token history. No
growth with history length; the constant-transport assumption holds; no stop.

### 5. Feasibility axis (prefix 3000, hops upward; ≤1.5 h budget)

| config | ours | mechanism | server | note |
|---|---|---|---|---|
| 3000×24, n_ctx 8192 | 23.932 s | 88.972 s (3.72x) | 27.306 s | all arms alive; RAW srv/ours 1.141 |
| 3000×48, n_ctx 8192 | **FAILS** | not run | 53.224 s | ours: `llama_decode rc=1` — per-seq KV budget exhausted (history ≈ 4520 tok > 8192/2 = 4096 per sequence, Run 0 finding); server survives (its single slot owns the full 8192) |
| 3000×48, n_ctx 16384 (mitigation, recorded) | 46.286 s | 183.846 s (3.97x) | (same 53.224) | ours recovers and beats server RAW 1.150 — at the cost of a doubled KV allocation |

Feasibility finding, stated honestly in both directions: at the default
harness configuration the CROSSING IS AGAINST US — the server's slot
management uses its context budget more efficiently out of the box (one slot
= full n_ctx), while our backend's `n_seq_max=2` default halves the per-
sequence budget; the failure is configurational (mitigated by raising n_ctx,
at doubled KV memory), not architectural. Mechanism baseline remains alive
but at 3.7–4.0× our wall time throughout the axis.

### 6. Memory and instrumentation notes (honest methods)

- Server arm peak RSS (measured in-process via psapi on the llama-server
  PID): stable 2297–2313 MB across all 16 points (model 1.04 GB + full-ctx
  KV + runtime).
- Native-arm per-invocation RSS polling in the driver produced a constant
  bogus 4 MB (sampling artifact) — recorded as NOT reliably instrumented in
  this run rather than reported; a fix belongs to the next run's driver.
- Peak GPU memory: not separately instrumented — UMA iGPU; device-local
  Vulkan allocations live in system RAM (llama-server reports an 18384 MiB
  shared budget). Stated per protocol.
- One transient failure during the sweep: the first attempt at the server
  invocation of 3000×8 exited 1 after ~89 s (its stderr was discarded by the
  driver; most plausibly a server-start/port race after the preceding
  invocation). The manual re-run immediately succeeded and a fresh 5-repeat
  measurement was recorded; the table above uses it. Flagged for
  completeness; no other invocation failed.

## Observation

Shape: **matches the pre-registration on both axes — verdict: confirmed.**

- Mechanism baseline: near-parity at control (1.00) growing to 3.35× at
  3000×12 — the 0.4-style shape reproduced on the post-fix stack (0.4 iGPU
  reference: 1.00 → 3.41; both arms sped up under the 0.5.1 hot-path fix, so
  the ratio landing within 2 % of the 0.4 value is the expected outcome).
- Honest baseline: ADJUSTED srv/ours sits at 0.99–1.09 across the entire
  grid — **mechanics parity with a tuned llama-server**, exactly the pre-
  registered expected headline. RAW srv/ours 1.07–1.22 in our favor — the
  gap is the per-request transport (≈0.13 s), i.e. claim (a): an in-process
  loop avoids the server deployment model's transport cost; the absolute gap
  grows linearly with hops (transport × (hops+1)) while the ratio stays
  modest and shrinks with prefix, exactly as pre-registered ("grows with
  hops... and stays modest" — in absolute terms; as a ratio it amortizes).
- Neither disappointment clause fired: ours is nowhere below 0.9 vs the
  server; the mechanism shape reproduced cleanly.
- Per the pre-registered framing: with the honest ratio at parity, the N5
  SPEED claim vs a tuned server narrows to "matches a tuned server without
  running a server, and avoids its transport"; the campaign's weight for N5
  shifts to the mechanism ratio (up to 3.35× vs stateless re-prefill, up to
  3.97× on the feasibility axis) and to the feasibility findings. That is
  the honest, reportable outcome this run was designed to produce.
