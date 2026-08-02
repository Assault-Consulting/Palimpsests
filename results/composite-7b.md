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

### 1. Corruption gate — PASS (already run, §Step 0.5)

cold SP+TL L2 = 0.0, resumed KP+TL L2 = 0.0, guard raises = 0 at prefix
1500. The composite is state-control correct on 7B.

### 2. Rung table — wall (medians of 5), prefix 1500, reduced M∈{4,12}

Deltas are mechanism value (our scheduler) — NEVER "vs llama-server".

| M | resume | rung0 srv | rung1 none | rung2 +SP | rung3 +KP | rung4 +TL | Δ SP | Δ KP | Δ TL | value r1/r4 | srv r0/r4 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 4 | 0.0 | 19.3 | 138.2 | 120.2 | 118.2 | 36.5 | 18.00 | **1.99** | 81.66 | 3.78× | 0.53× |
| 4 | 0.5 | 16.9 | 109.9 | 99.4 | 88.4 | 26.4 | 10.51 | **11.08** | 61.99 | 4.17× | 0.64× |
| 12 | 0.0 | 60.3 | 410.7 | 351.1 | 350.4 | 112.1 | 59.66 | **0.70** | 238.33 | 3.67× | 0.54× |
| 12 | 0.5 | 55.3 | 326.3 | 299.2 | 264.8 | 79.2 | 27.15 | **34.38** | 185.55 | 4.12× | 0.70× |

### 3. Sub-additivity — CONFIRMED on 7B, same shape as 1.5B

Δ KP is ~0 at resume 0 (1.99 / 0.70 s at M 4/12 — nothing to resume) and
grows at resume 0.5 (11.08 / 34.38 s) — but is **11.1 % / 11.5 % of the
rung-2 wall it acts on**, the same ~11 % fraction as 1.5B (10.5–11 %).
Shared Prefix and KV Persistence partition by session type on 7B exactly as
on 1.5B (Δ SP largest at resume 0 where all sessions are cold: 18.0/59.7 s;
smaller at resume 0.5: 10.5/27.2 s). They ADD across subsets, do NOT
multiply. Tool Loop dominates (Δ 62–238 s, ~4× the 1.5B Δ — the per-hop
re-prefill is 4× more expensive on 7B). Pre-registration (1) holds.

### 4. Composite headline — full-stack value HIGHER than 1.5B

Full-stack mechanism value (rung 1 → rung 4): **3.67–4.17×**, above 1.5B's
3.37–3.59× — the heavier 7B prefill makes each avoided re-prefill worth
more (pre-registration (2), consistent with Run 6's KP 5.44 → 7.58× lift).
vs the tuned server (rung 0): 0.53–0.70× — server 1.4–1.9× faster via
continuous batching (execution-model caveat, same as 1.5B, NOT the
headline).

### 5. Pool pressure — did NOT fire on 7B either; the CELL pool is model-independent (the run's primary new finding)

The pre-registered worry — that the 2×-heavier 7B cell would push the
composite into pool pressure where 1.5B had none — did NOT materialize, and
the reason is clean:

| M | resume | held concurrent | peak KV cells | 1.5B peak cells | admission fails | slot exhaustion | guard |
|---|---|---|---|---|---|---|---|
| 12 | 0.5 | 12 | 13,578 | 13,578 | 0 | 0 | 0 |
| 12 | 0.0 | 12 | 13,284 | 13,284 | 0 | 0 | 0 |
| 4 | 0.5 | 4 | 4,526 | 4,526 | 0 | 0 | 0 |

**The peak KV cell count is IDENTICAL to 1.5B, cell-for-cell** — because
the KV pool is allocated in CELLS (n_ctx), and the workload's cell count is
token-based, hence model-INDEPENDENT. At M=12/resume 0.5 the composite uses
13,578 of 32,768 cells — the same **41 %** on both models. The 7B cost is
in BYTES, not cells: the same 41 % of cells is 2× the memory. But even the
byte footprint fits: peak WS **11.6 GB** at rung 4 M=12 (7B weights 4.36 GB
+ 32768-cell KV 1.75 GB + resident blobs + runtime) — **63 % of the
18.4 GiB Arc budget**, no device-memory pressure. Server rung-0 RSS 13.9 GB.

**So pool pressure is model-INDEPENDENT for this workload** (cell-based
admission), and the composite fits the device budget on 7B with headroom.
The pre-registered feasibility-limit hypothesis is a null result — reported
as measured, with the mechanistic reason (cell- not byte-based pool).

### 6. Cross-model comparison — 1.5B vs 7B composite

| metric | 1.5B (Run 7) | 7B (this run) | reads as |
|---|---|---|---|
| full-stack value r1/r4 | 3.37–3.59× | **3.67–4.17×** | HIGHER on 7B (heavier prefill saved) |
| Δ KP as % of rung 2 (resume 0.5) | 10.5–11 % | 11.1–11.5 % | same — sub-additive, model-independent |
| Δ TL (dominant) | 14–57 s | 62–238 s | ~4× — per-hop re-prefill costs more on 7B |
| peak KV cells @ M12 rf0.5 | 13,578 | 13,578 | IDENTICAL — cell pool is model-independent |
| peak WS @ rung4 M12 | 3.73 GB | 11.6 GB | 3.1× bytes; both fit the budget |
| admission / slot failures | 0 | 0 | no pool pressure on either |
| guard raises | 0 | 0 | release ordering correct on both |
| corruption gate | PASS | PASS | composition correct on both |

### 7. Guard, memory, incidents

- **guard_raises = 0 at every point** — the enforced guard never fired
  under the 7B composite.
- Memory (real-handle psapi): native peak WS 11.6 GB (rung 4 M=12), server
  RSS 13.9 GB; both within the ~18.4 GiB Arc budget.
- No incidents; no re-runs. Grid ran ~5.4 h (probe-based projection was
  ~5 h) — within the 6 h threshold after the §8 reduction to M∈{4,12}.

## Observation

Verdict vs the pre-registration: **confirmed on (1), (2), (4); the pool-
pressure hypothesis (3) is a NULL result with a clean mechanistic reason;
no disappointment clause fired.**

1. **Composite shape reproduces on 7B** — corruption gate PASS (guard 0),
   sub-additive (Δ KP ~0 at resume 0, ~11 % at resume 0.5 — the SAME
   fraction as 1.5B), Tool Loop dominates. The mechanisms compose at model
   scale exactly as at 1.5B.
2. **Full-stack value is HIGHER on 7B (3.67–4.17× vs 3.37–3.59×)** — the
   heavier prefill makes the avoided re-prefill worth more, as
   pre-registered and consistent with the isolated Run 6 lift.
3. **Pool pressure did NOT fire on 7B — the KV pool is cell-based, so
   utilization is model-independent (identical 13,578 cells, 41 % on both
   models).** The 2× cell weight doubles the BYTES (peak WS 3.7 → 11.6 GB)
   but not the cell count, and 11.6 GB fits the 18.4 GiB budget with
   headroom. The pre-registered feasibility limit is a null result; the
   composite is not memory-bound on this hardware at M≤12 / prefix 1500.
   This is the run's primary new finding: composite pool pressure is a
   function of token counts (cells), not model size (bytes), until the
   device budget itself is approached — which it is not here.
4. **vs server: 0.53–0.70× (server faster via continuous batching)** — the
   execution-model caveat, same as 1.5B; not the headline.

Net for consolidation: the composite is model-size-robust — it composes
correctly, stays sub-additive (SP/KP partition by session type on both
models), and is worth MORE at 7B (3.67–4.17×) while its pool cost is
model-independent (cell-based) and byte-bound only by a budget it does not
approach. This closes the 0.5 composite axis across both models.
