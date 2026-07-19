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

(to be filled — cross-slot sharing check, beyond-slot-budget behavior,
honest P re-check including the P=4-vs-P=8 question from Run 3)

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

(to be filled after the sweep)

## 6. Observation

(to be filled)
