# Bench report — N4 shared-prefix KV — 7B — iGPU/Vulkan

- Run ID:            n4-shared-prefix-7b-igpu
- Date / operator:   2026-07-19 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged: pin 7745853 for measured
  code — `git diff 7745853..main -- src/palimpsests` empty, branch from the
  pin fast-forwarded to main d7f6eb9 for the merged Run 3 harness; same
  venv 0.5.1.dev0, llama-cpp-python 0.3.33 Vulkan, pinned llama-server
  b9874 @ 78d2f524, same models/sha256, same driver 101.8331)

## Config (pinned)

As Run 3, with the model swapped to
qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf (+ part 2, split GGUF;
sha256 of both parts in the Run 0 config block). ngl 999 (full offload
29/29), greedy (temp 0), 64 tokens per session, `ignore_eos` on the
server arm. Harness: the Run 3 scripts as merged into main (PR #71),
including the `kv_unified=true` wrapper around the backend's unchanged
`__init__` — same technique, declared here per the Run 3 precedent.
System sleep disabled for the whole run (Run 2 lesson;
`powercfg -standby-timeout-ac/dc 0`).

**Slot budget (maintainer decision, unchanged from Run 3):**

```
concurrency budget P = 8 (re-validated on 7B in §2)
server arm:  --parallel 8, --ctx-size 32768 (per-slot 4096), cache_prompt
             true, slot erase between repeats, session warm request.
ours arm:    n_ctx=32768, n_seq_max=9 (= P+1: 8 sessions + holder),
             max_active=8, kv_unified=true.
mech arm:    identical backend config, no holder (prefix+suffix prefill
             per session).
effective session budget: ours P=8, server P=8; holder slot accounted
             separately as a cost of our design.
total KV cell budget: 32768 cells in every arm — DELIBERATELY the same
             cell pool as Run 3 (1.5B) for direct cross-model density
             comparison. Fit calculation (7B): weights 4.36 GiB + KV
             32768 × 56.0 KiB = 1.79 GiB + compute buffers ≈ 6.7 GiB of
             the ~18.4 GiB shared device budget; host available-physical
             with the 32768-cell context loaded ≈ 6.2 GiB, no swap.
```

## 1. Step 0 — memory probe on 7B (confirmation, not discovery)

The Run 3 SHARE finding is NOT postulated on 7B — it is re-measured
(same method: capacity-to-failure as the cell-level instrument,
`llama_memory_seq_pos_max` verification, real-handle psapi RSS +
system-available at every step; K = {2, 4, 8} with short decodes into 2
copied slots as the not-COW check).

| scenario | config | result |
|---|---|---|
| 7B-S1 unified, capacity | pool 8192 cells, n_seq_max 9 | warm 1107-token prefix 5.03 s; 8 copies OK (0.1 ms each, pos_max 1106 verified); decodes into 2 slots OK; memory flat throughout (WS 9269.9 MB constant through all copies). **9 × 1107 = 9963 logical cells inside 8192 physical.** |
| 7B-S2 unified, boundary | pool 2048 cells (< 2 × prefix), n_seq_max 9 | **8 copies + decodes fit a 2048-cell pool** — copy semantics would fail at the FIRST copy (2214 > 2048). |

**Verdict: SHARE reproduces on 7B — flat in K, survives first decode
(not COW). The `seq_cp` sharing mechanism is model-size-independent, as
expected.** No stop condition; the run proceeds to the sweep.

**KV cell weight (the denominator of every density number in this run):**

| model | theoretical (config) | measured (commit delta / cells) | logical state, 1107 tok |
|---|---|---|---|
| 1.5B (Run 3) | 28 layers × 2 × 2 kv-heads × 128 × f16 = 28.0 KiB/tok | 28.0 KiB/tok | 31.75 MB |
| 7B (this run) | 28 layers × 2 × 4 kv-heads × 128 × f16 = 56.0 KiB/tok | **55.7 KiB/tok** (Δ 342.4 MB / 6144 cells between the S1/S2 pools) | 63.49 MB |

Exactly 2.0× per cell — the same 32768-cell pool costs 0.92 GiB on 1.5B
and 1.79 GiB on 7B.

## 2. Step 1 — server slot characterization on 7B (abbreviated)

Prefix ~1500 (1126 measured), M=8 concurrent unless stated; 2 repeats
per configuration (confirmation scope). Logs `results/n4-sweep/7b-char-*`.

- **No cross-slot prefix sharing on 7B either:** P=8, M=8 concurrent —
  every slot pays the full 1126-token prefill (cache_n = 0 on all 8),
  wall 54.1 s [52.6–55.7], server peak RSS 10.45 GB (the 32768-cell
  pool fits 7B as calculated in the config block).
- **Beyond the slot budget (M=12 > P=8):** freed-slot prefix cache
  serves ~half the sessions suffix-only (cache_n≈1111), wall 58.8 s —
  same qualitative behavior as 1.5B.
- **Honest-P re-check (the Run 3 finding, re-measured on 7B):** at
  M=8 the server's per-workload optimum is again FEWER slots —
  P=4/ctx 16384: 31.7 s [29.5–33.9]; P=2/ctx 8192: 37.3 s (too little
  decode parallelism); P=8: 54.1 s. The optimum did not shift below
  P=4 despite the heavier prefill. As in Run 3, the grid holds P=8 in
  both arms per the maintainer's budget-parity decision; the P=4
  number is reported alongside in §6.

Honest server config for the grid: --parallel 8, --ctx-size 32768,
default KV mode, cache_prompt true, slot erase between repeats, session
warm request.

## 3. Pre-registration (written AFTER step 0, BEFORE the sweep)

Expectation: (1) SHARE branch reproduces on 7B (flat memory in K,
survives first decode) — the seq_cp sharing mechanism is
model-size-independent; (2) absolute session ceilings DROP on both arms
(heavier KV cells), but the density RATIO holds or grows — the server
pays the heavier prefix per slot, we pay it once; (3) the binding
constraint may FLIP: on 1.5B our ceiling was the upstream 256-sequence
cap with memory to spare (~21.3k/32768 cells at 255 sessions); on 7B
memory may bind BEFORE the cap — if so, this run delivers the first
clean MEMORY-bound density ceiling of the campaign; (4) M=1 parity
holds with the holder cost in band (5–8% reference from 1.5B);
contention advantage within the slot budget grows with prefix,
saturating at M≈P as on 1.5B.

Would disappoint if: sharing does not reproduce on 7B (size-dependent
mechanism — bigger finding than the sweep); or the density ratio
collapses toward 1 (per-slot overhead stops dominating); or M=1 parity
breaks (holder cost scales with model size worse than linearly).

Note on expectation (1): step 0 has already CONFIRMED it before the
sweep (that is the point of the probe-first gate); it is retained here
verbatim as pre-registered so the sweep can still disappoint the rest.

## 4. Methodology

Identical to Run 3 (see `results/n4-shared-prefix-1p5b-igpu.md` §4):
three arms, all-M-arrive-at-t0 concurrent workload, wave admission
beyond P, wall includes the holder warm, ≥1 warmup + 5 timed repeats,
cool-downs (45 s / 90 s after 7B mech), arm order alternated, zero
background load, sleep disabled, two-tier gates (tier 1 ours/mech RAW
at 50×1; tier 2 server pairs at 50×8 adjusted ≤ 1.2), amended transport
estimator (M=1 server−mech TTFT per prefix, anchor sanity 0.102 ±2×,
clamped at 0, † flags), RAW/ADJUSTED conclusions must agree, memory per
point (real-handle psapi + system-available + cell accounting),
narrative rule (mechanism ratio is vs stateless per-session re-prefill
on our own scheduler — the value of shared-prefix seeding itself, never
an advantage over llama-server).

Grid (deliberately reduced — 7B is expensive; chronometry gate before
the sweep, STOP ~8 h): prefix {~1500, ~3000} × M {1, 2, 4, 8, 12} × 3
arms; the ~500 column is added only if the projection is ≤ 6 h.
Feasibility: prefix ~1500, M upward on both arms to failure (≤ ~2.5 h),
with the cross-model ceiling table vs Run 3.

## 5. Results

### 5.1 Control gates (two-tier, measured before the sweep)

| tier | pair | point | ratio | band | verdict |
|---|---|---|---|---|---|
| 1 (our-stack cleanliness) | ours/mech RAW | 50×1 | 1.117 | 0.9–1.2 | PASS |
| 2 (server pairs, amortized) | server/mech ADJ | 50×8 | 0.987 (raw 1.075) | ≤1.2 | PASS |
| 2 (server pairs, amortized) | server/ours ADJ | 50×8 | 1.017 (raw 1.108) | ≤1.2 | PASS |

Gate raw data (medians of 5): 50×1 ours 5.461 / mech 4.887 / server
4.929; 50×8 ours 10.145 / mech 10.452 / server 11.237. Transport
estimator at 50×1: server−mech TTFT = 0.450−0.335 = 0.115 s/req
(anchor 0.102 ✓). Two honest notes: (a) the holder cost at the control
is 1.117 on 7B vs 1.079 on 1.5B — larger, still in band; the
pre-registered "holder cost scales worse than linearly" clause is
watched at the sweep's M=1 points; (b) unlike the 1.5B run, the tier-2
adjusted ratios sit comfortably inside the band (1.017 vs 1.199) — the
concurrent-serving overhead that pushed 1.5B to the band edge amortizes
into 7B's heavier compute, exactly as Run 2 found for transport.

### 5.2 Chronometry estimate (before the sweep)

Most expensive point 3000×12, 1 repeat: ours 33.7 s, mechanism 161.8 s,
server 109.2 s → projection: priority grid {1500, 3000} × {1, 2, 4, 8,
12} × 3 arms × 6 repeats + loads/starts/cool-downs ≈ 3.3–3.8 h;
feasibility ≤ 2.5 h; total ≈ 6 h < the 8 h STOP. Adding the ~500 column
would put the total at ~7.5–8 h with no reserve — per the pre-agreed
rule (add 500 only if the projection stays ≤ 6 h) the ~500 column is
NOT run; the reduced grid is the deliberate scope of this run.

### 5.3 Grid — 10 points × 3 arms (medians of 5 timed repeats)

The mechanism ratio below is vs stateless per-session re-prefill (no
prefix reuse at all), same scheduler; **the mechanism ratio measures the
value of having shared-prefix seeding at all, not an advantage over
llama-server.** Transport/request per the amended estimator (M=1
server−mech TTFT of the same prefix): 0.140 / 0.153 s at prefix 1500 /
3000 — inside the anchor band, no † flags; adjusted = raw − transport ×
M (conservative in the server's favor). RAW and ADJUSTED agree in their
conclusions at every point — no automatic stop.

| point | measured prefix | ours | mechanism | server RAW | mech/ours | srv/ours RAW | srv/ours ADJ | transport/req (s) |
|---|---|---|---|---|---|---|---|---|
| 1500×1 | 1107 | 10.138 | 9.643 | 9.753 | 0.95 | 0.962 | 0.948 | 0.140 |
| 1500×2 | 1107 | 10.404 | 15.456 | 15.771 | 1.49 | 1.516 | 1.489 | 0.140 |
| 1500×4 | 1107 | 12.424 | 28.100 | 31.701 | 2.26 | 2.552 | 2.507 | 0.140 |
| 1500×8 | 1107 | 16.639 | 53.632 | 54.789 | 3.22 | 3.293 | 3.225 | 0.140 |
| 1500×12 | 1107 | 24.340 | 82.766 | 60.529 | 3.40 | 2.487 | 2.418 | 0.140 |
| 3000×1 | 2235 | 16.692 | 15.805 | 15.930 | 0.95 | 0.954 | 0.945 | 0.153 |
| 3000×2 | 2235 | 17.290 | 29.780 | 28.891 | 1.72 | 1.671 | 1.653 | 0.153 |
| 3000×4 | 2235 | 19.047 | 55.362 | 58.948 | 2.91 | 3.095 | 3.063 | 0.153 |
| 3000×8 | 2235 | 24.035 | 105.645 | 106.989 | 4.40 | 4.451 | 4.401 | 0.153 |
| 3000×12 | 2235 | 33.466 | 160.346 | 117.388 | 4.79 | 3.508 | 3.453 | 0.153 |

Shape vs pre-registration and vs Run 3 (1.5B):

- M=1 parity holds at every prefix (ADJ 0.945–0.948); the holder cost
  stays in band (mech/ours 0.95 at both prefixes — same as 1.5B's
  0.95–0.98; the "worse than linearly" disappointment clause did NOT
  fire at the sweep points, only the tiny-prefix control showed the
  larger 1.117).
- Advantage grows with M and prefix, peaking at **4.40 adjusted (4.45
  raw) at 3000×8 — HIGHER than 1.5B's 3.81 at the same point**, as
  pre-registered (the server's per-slot prefix prefill is heavier on
  7B; ours is paid once).
- The M=12 > P erosion reproduces (3000: 4.45 → 3.51 raw; 1500: 3.29 →
  2.49): the server's freed-slot prefix cache again caps the
  beyond-budget contention win — consistent with 1.5B, stated as-is.
- Per §2, a per-workload-tuned server at M=8 would run P=4 (31.7 s at
  1500×8 ≈ 1.9× ours instead of 3.29× at P=8) — both numbers reported;
  the honest competitive claim at M≈P vs the P-tuned server is ~1.9–2×,
  the equal-P budget-parity number is 3.2–4.4×.

### 5.4 Memory (grid points; method per Run 3 §4)

Flat across the grid, as expected for equal preallocated pools: ours
process peak WS 10653–10659 MB (7B weights 4.36 GiB + 32768-cell KV
1.79 GiB + runtime), server peak RSS 10441–10649 MB; system-available
floor ≈ 6.4 GiB, no swap events. The density difference lives in
cells-per-session (§5.5), not in bytes at fixed pool size.

### 5.5 Feasibility axis (prefix 1500, M upward to failure; equal 32768-cell budget)

Same protocol as Run 3 §5.5 (ours: max_active = M, n_seq_max = M+1, all
sessions concurrently live; server: --parallel M; 1 warmup + 1 timed
repeat).

| M live sessions | ours wall (s) | server wall (s) |
|---|---|---|
| 12 | 36.02 | 93.64 |
| 24 | 41.71 | 167.57 |
| 31 | — | **209.67 — server's last alive** |
| 32 | — | **FAILS** — HTTP 400 (`exceed_context_size_error`: per-slot partition 32768/32 = 1024 < 1126-token prefix; same arithmetic as 1.5B — model-size-independent) |
| 48 | 42.11 | — |
| 96 | 72.30 | — |
| 128 | 84.00 | — |
| 192 | 121.43 | — |
| 255 | **157.75 — ours' last alive** (255/255 completed) | — |
| 256 | **FAILS** — `llama_new_context_with_model failed` (n_seq_max = 257 > llama.cpp's 256-sequence cap; same error as 1.5B) | — |

**The run's key question is answered: memory did NOT bind before the
cap on 7B either.** At 255 live sessions ours uses ≈ 21.3k of 32768
cells (1107 shared prefix + 255 × ~79 unique cells; the heavier 7B cell
changes the BYTES — 1.19 GiB of pool in use vs 0.58 GiB on 1.5B — but
not the CELL arithmetic), process peak WS 10.97 GB, system-available
floor 6.37 GiB, no swap. Honest statement per the pre-registration:
**cap-bound, memory headroom ≈ 11.5k cells (0.63 GiB) + 6.4 GiB system
available.** The pre-registered possibility (3) — a first memory-bound
ceiling — did NOT materialize at this pool size; both arms' ceilings on
this hardware are STRUCTURAL (engine sequence cap vs per-slot context
arithmetic), not memory. That is itself the informative outcome: with
an equal cell budget the ceilings are model-size-INDEPENDENT, and only
the wall-clock at the ceiling scales with the model.

### 5.6 Cross-model ceiling table (this run vs Run 3)

| | ours ceiling | server ceiling | density ratio | ours binding constraint | server binding constraint |
|---|---|---|---|---|---|
| 1.5B (Run 3) | 255 live sessions (48.7 s) | 31 (52.2 s) | **8.2×** | 256-sequence engine cap (≈ 11.5k cells free) | per-slot partition < prefix |
| 7B (this run) | 255 live sessions (157.8 s) | 31 (209.7 s) | **8.2×** | 256-sequence engine cap (≈ 11.5k cells free, 0.63 GiB) | per-slot partition < prefix |

Pre-registered expectation (2) resolves as: the density RATIO held
exactly (8.2× on both models — the constraints are structural, so the
ratio is pool-arithmetic, not model arithmetic); the expected DROP in
absolute ceilings did not happen because the 32768-cell pool still fits
7B's 2× heavier cells within the device budget. At its own ceiling ours
serves 255 sessions in less wall time than the server needs for 31
(157.8 vs 209.7 s) — reproducing the 1.5B pattern.

### 5.7 Instrumentation notes

- Same real-handle psapi memory method as Run 3; native and server
  numbers are real readings at every point.
- No incidents: no system sleep (disabled up front), no transient
  failures, no re-runs; every grid invocation succeeded on first
  attempt; feasibility failures are the two intended terminal ones
  (documented above with their exact errors).

## 6. Observation

Verdict vs the pre-registration: **confirmed on (1), (4) and the ratio
half of (2); the ceiling-drop half of (2) and the memory-bound
possibility (3) did not materialize — resolved in the informative
direction (structural, model-size-independent ceilings); no
disappointment clause fired.**

1. **SHARE reproduces on 7B** (step 0, gate): flat in K, survives first
   decode, capacity-proven in 8192- and 2048-cell pools. The `seq_cp`
   sharing mechanism is model-size-independent.
2. **KV cell weight: 55.7 KiB/token measured (2.0× the 1.5B 28.0)** —
   theory-matching (4 kv-heads vs 2); the same 32768-cell pool costs
   1.79 GiB vs 0.92 GiB. This is the denominator of every density
   number above.
3. **Density: 255 vs 31 live sessions — 8.2× on BOTH models.** Both
   ceilings are structural (engine 256-sequence cap with 0.63 GiB of
   pool headroom vs per-slot context arithmetic), so the ratio carried
   over from 1.5B unchanged; only wall-clock at the ceiling scales with
   the model (157.8 s vs 48.7 s for ours' 255).
4. **Speed grid: peak 4.40 adjusted (4.45 raw) at 3000×8 — higher than
   1.5B's 3.81**, as pre-registered (heavier per-slot prefix prefill on
   the server side, paid once on ours). M=1 parity holds (0.945–0.948
   adjusted; holder cost in band — the worse-than-linear clause did not
   fire at sweep points). The mechanism ratio (vs stateless per-session
   re-prefill on our own scheduler — the value of shared-prefix seeding
   itself, not an advantage over llama-server) grows 0.95 → 4.79.
5. The M > P erosion reproduces on 7B (4.45 → 3.51 raw at 3000) — the
   server's freed-slot prefix cache remains effective beyond the slot
   budget; N4's contention advantage saturates at M ≈ P on both models.
   A per-workload-tuned server at M=8 would run P=4 (1.9× ours instead
   of 3.3× at 1500×8) — both numbers reported, consistent with Run 3.
6. Transport (0.140/0.153 s/req) amortizes into 7B compute — tier-2
   gates comfortably in band (1.017 vs 1.5B's edge 1.199), confirming
   Run 2's transport-share finding in the N4 workload.

Net framing for consolidation: N4's differentiation is model-size-
robust — session density 8.2× at the structural ceilings on an equal
cell budget (with memory headroom on both models at pool 32768), and
concurrent-arrival latency within the slot budget growing with model
size (3.81 → 4.40 adjusted at 3000×8). The beyond-slot-budget case
remains the server's strength on both models. The engine's 256-sequence
cap is now the measured upper bound of our density story on this
hardware — consolidation input alongside Run 3's kv_unified exposure
recommendation.

## 6. Observation

(to be filled)
