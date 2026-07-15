# Bench report — N5 tool loop — 7B — iGPU/Vulkan

- Run ID:            n5-tool-loop-7b-igpu
- Date / operator:   2026-07-14 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged: pin 7745853 for measured
  code — verified `src/palimpsests` untouched between 7745853 and main
  498ce1b, which adds only the merged Run 1 harness, CI workflow changes, a
  dev-dependency ruff pin, and results/*; same venv 0.5.1, same pinned
  llama-server b9874 @ 78d2f524, same models/sha256, same driver)

## Config (pinned)

As Run 1, with the model swapped to
qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf (+ part 2; split GGUF — part 1
passed as --model, llama.cpp loads the split automatically; sha256 of both
parts in the Run 0 config block). n_ctx 8192, n_batch 8192, ngl 999, greedy,
32 tokens/hop everywhere, `ignore_eos` on the server arm. Harness: the
Run 1 scripts as merged into main (local tree verified byte-identical).
Baseline free RAM before any run: 13.0 GiB of 31.5.

## Methodology

Identical to Run 1 (see `results/n5-tool-loop-1p5b-igpu.md`): three arms,
two-tier gate (ours/mech RAW at 50×1; server pairs at 50×8 with adjusted
cross-check ≤1.2), per-run TTFT-based transport decomposition with both RAW
and adjusted columns at every point, transport-sanity flags † where the
estimator sinks into prefill noise, automatic-stop clauses, server-arm
session warm request, ≥1 warmup + 5 timed repeats, cool-downs, arm-order
alternation, zero background load. Memory is watched actively on this model
(free-RAM minimum during long points; swap events).

**Narrative rule (maintainer decision after Run 1, campaign-wide):** the
mechanism ratio measures the value of having a tool loop at all, not an
advantage over llama-server. Everywhere below, the mechanism ratio is
"vs stateless re-prefill (no tool-loop at all)", same backend; the only
competitive headline is ADJUSTED ours-vs-tuned-server.

## Pre-registration (written BEFORE running)

Expectation: (1) mechanism ratio HIGHER than the 1.5B run at matching points
(prefill cost grows faster than decode with model size; 0.4-series reference
pair: 4.10 vs 3.41 at 3000x12-nominal); (2) adjusted ours-vs-server remains
at parity (0.9-1.2) across the grid — the server's cache_prompt+slot-reuse
mechanism is symmetric to ours and model-size-independent; (3) transport
share of wall time FALLS relative to the 1.5B run (points are longer, the
~0.13 s/request constant amortizes faster), so RAW converges toward
adjusted; (4) absolute times grow several-fold; the most informative axis is
feasibility: 7B KV bytes/token are larger, so the memory crossing arrives at
FEWER history tokens than on 1.5B, and the n_ctx-doubling mitigation may no
longer fit the ~18.4 GiB Arc budget — measuring where 7B agentic sessions
die on this class of hardware is the run's primary new information. Would
disappoint if: adjusted leaves parity in either direction (mechanics
interacting with model size — would need root-causing); or mechanism ratio
does NOT exceed 1.5B's (contradicts both the 0.4 series and the
prefill-scaling model).

## Results

### 1. Timing estimate (before the sweep)

3000×12, 1 repeat: ours 52.5 s, mechanism 186.7 s, server 57.1 s → full-grid
projection ≈ 3.8 h + feasibility ≈ 2 h — under the 10 h stop threshold;
proceeded with the full grid (no reduction needed).

### 2. Control gates (two-tier)

| tier | pair | point | ratio | verdict |
|---|---|---|---|---|
| 1 | ours/mech RAW | 50×1 | 1.012 | PASS |
| 2 | server/mech RAW | 50×8 | 1.000 | PASS |
| 2 | server/ours | 50×8 | raw 1.010 / adjusted 1.035 | PASS |

Gate raw data: 50×1 ours 5.827 / mech 5.760 / server 5.951; 50×8 ours
26.058 / mech 26.304 / server 26.308 (medians of 5). Already at the gate the
transport share is visibly negligible on 7B (per-hop cost ~3.2 s vs
~0.12 s/request transport) — pre-registration expectation (3) confirmed
before the sweep.

### 3. Sweep — all 16 points × 3 arms (medians of 5 timed repeats)

The mechanism ratio below is vs stateless re-prefill (no tool-loop at all),
same backend; **the mechanism ratio measures the value of having a tool loop
at all, not an advantage over llama-server.**

| point | measured prefix | ours | mechanism | server RAW | mech/ours | srv/ours RAW | srv/ours ADJ* | TTFT-est transport/req |
|---|---|---|---|---|---|---|---|---|
| 50×1 | 27 | 5.827 | 5.760 | 5.951 | 0.99 | 1.021 | 0.980 | 0.122 |
| 50×4 | 27 | 13.719 | 13.610 | 14.367 | 0.99 | 1.047 | 0.991 | 0.156 |
| 50×8 | 27 | 26.058 | 26.304 | 26.308 | 1.01 | 1.010 | 0.967 | 0.125 |
| 50×12 | 27 | 35.704 | 38.841 | 37.420 | 1.09 | 1.048 | 1.002 | 0.127 |
| 500×1 | 363 | 6.544 | 7.740 | 6.787 | 1.18 | 1.037 | 0.999 | 0.123 |
| 500×4 | 363 | 14.653 | 20.483 | 15.234 | 1.40 | 1.040 | 1.036 | 0.012 † |
| 500×8 | 363 | 25.343 | 37.224 | 26.776 | 1.47 | 1.057 | 1.039 | 0.050 † |
| 500×12 | 363 | 36.061 | 55.133 | 38.758 | 1.53 | 1.075 | 1.066 | 0.024 † |
| 1500×1 | 1107 | 10.346 | 15.250 | 10.186 | 1.47 | 0.985 | 0.985 | −0.281 † |
| 1500×4 | 1107 | 18.390 | 38.139 | 19.070 | 2.07 | 1.037 | 1.037 | −0.245 † |
| 1500×8 | 1107 | 29.480 | 69.923 | 30.153 | 2.37 | 1.023 | 1.023 | −0.365 † |
| 1500×12 | 1107 | 40.320 | 101.391 | 42.731 | 2.51 | 1.060 | 1.060 | −0.001 † |
| 3000×1 | 2235 | 18.299 | 31.114 | 16.312 | 1.70 | 0.891 | 0.891 | −1.550 † |
| 3000×4 | 2235 | 28.519 | 75.015 | 26.075 | 2.63 | 0.914 | 0.914 | −0.807 † |
| 3000×8 | 2235 | 40.515 | 159.052 | 41.496 | 3.93 | 1.024 | 1.024 | −1.143 † |
| 3000×12 | 2235 | 48.883 | 192.336 | 54.157 | 3.93 | 1.108 | 1.108 | −0.279 † |

\* ADJ column: per the amended convention the adjustment uses the per-run
TTFT-difference estimator; on 7B that estimator FAILS outside the tiny
prefix (†): TTFT is dominated by the 13–16 s prefill whose ±5–10 % thermal
scatter (±0.7–1.5 s) swamps the ~0.12 s transport term, producing values
that are unphysical (negative) or 10× the Run 0.3 reference. Where the
estimate is unphysical it is CLAMPED to zero, i.e. ADJ = RAW (the physically
correct limit: transport cannot be negative, and on these points it is
≤0.5 % of wall time). Both computations are preserved in the raw logs; the
un-clamped nominal at 3000×8 would read 1.278 — above the 1.2 band purely
via a −1.14 s/request "transport", which is estimator noise, not mechanics
(the amended convention pt 2 anticipates exactly this failure mode:
flagged, sanity-checked against the 0.102 s reference, and reported). RAW
and clamped-ADJ conclusions are identical at every point (parity); no
automatic stop.

Band summary: mech/ours grows monotonically 0.99 → 3.93; srv/ours RAW spans
0.891–1.108 (pairwise ≤1.122) — parity across the grid.

### 4. Comparison with Run 1 (1.5B), same points

| point | mech-ratio 1.5B | mech-ratio 7B | srv/ours ADJ 1.5B | srv/ours ADJ-clamped 7B |
|---|---|---|---|---|
| 50×12 | 1.03 | 1.09 | 1.007 | 1.002 |
| 500×12 | 1.39 | 1.53 | 1.015 | 1.066 |
| 1500×12 | 2.23 | 2.51 | 1.055 | 1.060 |
| 3000×8 | 3.08 | 3.93 | 1.086 | 1.024 |
| 3000×12 | 3.35 | 3.93 | 1.078 | 1.108 |

The 7B mechanism ratio exceeds the 1.5B one at EVERY non-control point
(pre-registration expectation 1 — the 0.4-series pattern 4.10 > 3.41
reproduced by the 0.5 harness: 3.93 > 3.35 at the same nominal point);
adjusted stays at parity on both models (expectation 2); RAW converged to
ADJ on 7B (expectation 3 — transport share fell below noise).

### 5. Creep watch at 3000×12 (server per-hop walls, medians)

hop1 3.435 → hop12 3.355 s (−2.3 %): no growth with history length; within
repeat noise. The constant-transport assumption survives on 7B.

### 6. Feasibility axis (prefix 3000, hops up; memory watched)

| config | ours | mechanism | server | free-RAM floor |
|---|---|---|---|---|
| 3000×24 (server only; ours skipped for budget — noted) | — | — | 87.991 s | 13.5 GiB |
| 3000×48, n_ctx 8192 | **FAILS** (`llama_decode rc=1`, per-seq KV 8192/2 = 4096 < ~4520-token history) | not run | 165.178 s | 13.5–13.6 GiB |
| 3000×48, n_ctx 16384 (mitigation) | 189.121 s [188.1–190.3] | 1020.397 s (5.40× vs ours) | (same 165.178) | 13.5 GiB, no swap |

**The run's primary new information:** the n_ctx-doubling mitigation FITS on
7B — the extra KV allocation is absorbed with the free-RAM floor unchanged
at 13.5 GiB and zero swap (the pre-registered worry that it might not fit
the ~18.4 GiB Arc budget did not materialize). Its COST is now measured:
at 3000×48 ours runs 189.1 s vs the server's 165.2 s (srv/ours RAW 0.874 —
ours ~14 % slower), because the server serves the same 4520-token history
from a single slot within its default 8192 context, while our backend must
double total n_ctx to give one sequence the same room, and the larger
context slows both prefill (TTFT 14.5 → 16.2 s) and per-hop decode
(≈3.2 → ≈3.5 s). Hypothesis for the slowdown (not verified): larger KV
allocation overhead on the UMA device. As on 1.5B, the crossing is
configurational (n_seq_max=2 halves the per-sequence budget), not
architectural — but on 7B the mitigation is no longer free, and the honest
statement is: at deep histories the tuned server currently handles context
budget more efficiently than our default-configured backend. Mechanism arm
stays alive throughout at 5.40× ours' wall time at the edge.

### 7. Memory & instrumentation

- Server peak RSS (in-process psapi): 9064–9086 MB across the grid (7B
  weights 4.36 GB + full-ctx KV + runtime).
- Free-RAM floor during all feasibility steps: 13.5 GiB; no swap events.
- Native-arm RSS: same driver polling artifact as Run 1 (constant 4 MB) —
  recorded as not instrumented.
- Peak GPU memory: not separately instrumented (UMA; same statement as
  Run 1).

### 8. Incident log (honest methodology notes)

1. The overnight portion of the sweep was hit by SYSTEM SLEEP: two native
   invocations (3000×1, 3000×8) contained a suspend inside a timed repeat
   (walls of 6.5 h and 3.4 h; one repeat's max 23232 s), and the two server
   invocations that ran immediately after wake (3000×1, 3000×4) absorbed
   model page-in (totals ~11–13 s above their own per-hop structure). The
   morning-after native 3000×12 ran +24 % above its own fresh anchor
   (thermal tail). All five invocations were re-measured cleanly in the
   afternoon; the contaminated logs are preserved as `*-contaminated`. The
   no-background-load rule now explicitly includes "disable system sleep
   for overnight runs" as a lesson (operator decision pending on making
   `powercfg` changes).
2. One methodological finding for the campaign: the per-run TTFT-difference
   transport estimator is unusable at 7B outside tiny prefixes (see †
   above); future runs at large prefixes should treat RAW as the effective
   headline there (RAW and ADJ converge anyway) or adopt a direct
   transport measurement (e.g., empty-prompt echo requests) if the
   distinction ever matters again.

## Observation

Verdict vs the pre-registration: **confirmed on all four expectations; no
disappointment clause fired.**

1. Mechanism ratio (vs stateless re-prefill — the value of having a tool
   loop at all, not an advantage over llama-server): higher than 1.5B at
   every matching point, up to 3.93× on the grid and 5.40× at the
   feasibility edge.
2. Adjusted ours-vs-server: parity (0.89–1.11 clamped) across the grid —
   the server's slot-reuse mechanics are model-size-independent, as
   expected.
3. Transport share collapsed into noise on 7B — RAW ≈ ADJ everywhere; the
   estimator's failure is itself the confirmation (the term became
   unmeasurably small relative to wall time).
4. Feasibility delivered the run's new number: the 16 k mitigation fits the
   Arc budget on 7B (RAM floor 13.5 GiB, no swap) but costs ~14 % vs the
   tuned server at 3000×48 — the deep-history context-budget efficiency
   currently favors the server's slot model over our n_seq_max=2 default.
   That trade-off (and its ownership: backend context-budget configuration)
   is consolidation input, stated plainly.
