# Bench report — Composite (Shared Prefix + Tool Loop + KV Persistence) — 7B — iGPU/Vulkan

- Run ID:            composite-7b
- Date / operator:   2026-08-02 / Oleksandr
- Config-hash:       50fc841146dfbf6f (unchanged from Run 7 1.5B — same
  post-#81 pin 3419ddb: `git diff 3419ddb..main -- src/palimpsests` empty,
  measured code identical; kv_unified first-class + guard enforced; model
  swapped to 7B)

## Capability name map (internal → public)

| public name | internal | mechanism |
|---|---|---|
| **Shared Prefix** (SP) | N4 | decode a shared system prompt once, `seq_cp` into each session |
| **Tool Loop** (TL) | N5 | live-KV hops; feed only the tool result, no conversation re-prefill |
| **KV Persistence** (KP) | N6 | resume a session from persisted KV instead of re-prefilling its history |

Public names throughout; N-numbers only here.

**Narrative rule (enforced):** the rung deltas are *mechanism* value (worth
of adding each feature to the stack, our own scheduler) — NEVER "vs
llama-server". The only external number is rung 0 (tuned server); the
composite headline is the FULL-STACK number, never a cherry-picked best.

## Scope (reduced, conditional per §8 — confirmation at model scale)

Both §8 conditions hold: the 1.5B composite (#82) was clean (gate PASS,
sub-additive, mechanisms compose), and the budget is checked by the
chronometry gate below. This run does NOT re-open the mechanism (Run 7
established composition, sub-additivity, and the Tool-Loop dominance). It
answers ONE new question at model scale: **does the composite pool pressure
that did NOT fire on 1.5B (41 % of the 32768-cell budget at M=12/resume 0.5)
fire on 7B**, where the KV cell is 2× heavier (56 vs 28 KiB/tok). Rung
design, corruption gate, and the sub-additivity question are identical to
Run 7 (`results/composite-1p5b.md` is the method reference).

## Config (pinned)

```
palimpsests: 3419ddb (0.5.1.dev0; kv_unified first-class + PrefixHolderInUseError guard, merge #81)
llama-cpp-python: 0.3.33 (Vulkan); vendors llama.cpp 78d2f524
llama-server: build 9874, commit 78d2f524 (-DGGML_VULKAN=ON)
model 7B: qwen2.5-7b-instruct-q4_k_m (split GGUF, 2 parts) Q4_K_M — sha256 of both parts in the Run 0 config block
vulkan driver: 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics
kv_unified: True (FIRST-CLASS NATIVE PARAM); prefix-holder guard: ACTIVE
n_ctx: 32768  n_batch: n_ctx  ngl: 999 (full offload 29/29)
sampling: greedy (temp 0)
```

n_ctx kept at 32768 (the same CELL pool as Run 7 1.5B) for a direct
cross-model comparison — the pool is CELL-based, so the workload's cell
count is model-independent; what changes on 7B is the BYTES per cell (2×).
Fit calc: 7B weights 4.36 GiB + KV 32768 × 56 KiB = 1.75 GiB + compute ≈
6.4 GiB of the ~18.4 GiB Arc budget (Run 4/6 confirmed).

Harness: the Run 7 scripts (`benchmarks/bench_composite.py`,
`bench_composite_server.py`) as merged in #82 — no harness change. Raw logs
`results/composite-sweep/7b-*` (untracked).

## Step 0.5 — Corruption gate on 7B — PASS (blocking)

The same self-session integrity gate as Run 7 (bystander-safety is proven
model-independently by the isolation suite; not re-checked). On 7B this is
more critical — heavier blobs, larger KV. Result at prefix 1500:

| check | path | L2 | token-identical |
|---|---|---|---|
| cold session | Shared Prefix copy + Tool Loop live feed | **0.0** | **yes** |
| resumed session | KV Persistence load + Tool Loop live feed | **0.0** | **yes** |
| guard raises | correct-order teardown | — | **0** |

**GATE PASS** — the composite is state-control correct on 7B; the three
mechanisms compose without corruption at the larger scale.

## Pre-registration (written BEFORE the rung numbers, 1.5B as the base)

Expectation: (1) the composite SHAPE reproduces on 7B — sub-additive
(Shared Prefix and KV Persistence partition by session type), Tool Loop
dominates, mechanisms compose without corruption (gate PASS, guard = 0).
(2) full-stack mechanism value (rung 1 → rung 4) SIMILAR-OR-HIGHER than
1.5B's 3.37–3.59× — heavier 7B prefill makes each avoided re-prefill worth
more (consistent with Run 6: KP ratio rose 5.44 → 7.58× on 7B). (3) THE new
question — pool pressure: 1.5B used 41 % of the pool at M=12/resume 0.5; the
7B cell is 2× heavier in BYTES, so the same workload doubles the KV memory
footprint. If eviction/admission failures appear on 7B where 1.5B had none —
OR if the device memory budget (18.4 GiB) is approached — that is the run's
primary new finding (a real feasibility limit of the composite on this
hardware). (4) vs server: parity-or-loss as on 1.5B (execution-model
caveat).

Would disappoint if: the corruption gate fails on 7B (STOP, defect — did
NOT fire); or the composite is worse than rung 2 (mechanisms fight at
scale); or the mechanism value COLLAPSES below 1.5B (the heavier model
somehow erodes the stack — would need explaining).

Note on the pool-pressure prediction: the KV pool is allocated in CELLS
(n_ctx), and the workload's cell count is token-based, hence
model-INDEPENDENT — so cell utilization may well be the SAME ~41 % on 7B,
and the real 7B cost is BYTES (2×) against the device budget, not cell
admission. The grid decides; whichever way it lands is reported as measured.

## Methodology

Identical to Run 7 (`results/composite-1p5b.md` §Methodology): native rungs
1-4 sequential per-session (clean rung-delta attribution; continuous
batching would compress every rung uniformly, so deltas are preserved;
absolute vs-server caveated); pool-pressure probe (all M base states held
concurrently → peak KV cells, admission failures, slot exhaustion); rung 0
tuned server (--parallel P, cache_prompt + slot-KV tool loop + slot
restore); L2-over-first-token detector; ≥1 warmup + repeats per §chronometry;
sleep disabled; guard raises must be 0 at every point.

## Results

### 0. Chronometry gate (§8 budget — run FIRST)

Heaviest-arm probes (1 repeat, M=12/resume 0.5/prefix 1500): rung 1
(stateless) **337 s**, rung 2 305 s, rung 4 (composite) 83 s; rung 1 at
M=4 is 113 s. 7B stateless re-prefill at M=12 is ~4× the 1.5B cost (80 s).

Projection (×6 = warmup + 5 repeats per invocation):
- **Full grid** M∈{4,8,12} × resume{0,0.5} × rungs 0-4 ≈ **~7.5 h > 6 h** →
  reduce per §8.
- **Reduced grid** M∈{4,12} (the borders — M<P and M>P) × resume{0,0.5} ×
  rungs 0-4, prefix 1500 ≈ **~5 h < 6 h** → proceed.

Reduction applied: M=8 dropped (the middle point; the borders M=4/M=12
carry the M<P vs M>P contrast the pool-pressure question needs). 5 timed
repeats retained (convention). This is the confirmation-at-scale scope
(§8), not a mechanism re-establishment.

### 1-6. (rung table, sub-additivity, composite value, pool pressure,
cross-model 1.5B vs 7B, memory — to be filled after the grid)

## Observation

(to be filled)
