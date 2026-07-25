# Bench report — KV Persistence — 7B — iGPU/Vulkan

- Run ID:            kv-persistence-7b-igpu
- Date / operator:   2026-07-26 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged: pin 7745853 for measured
  code — `git diff 7745853..main -- src/palimpsests` empty; branch from the
  pin fast-forwarded to main 13895b4 for the merged Run 5 harness; same
  venv 0.5.1.dev0, llama-cpp-python 0.3.33 Vulkan, pinned llama-server
  b9874 @ 78d2f5246, same models/sha256, same driver 101.8331)

## Capability name map (internal → public)

| public name | internal | what it is |
|---|---|---|
| **KV Persistence** | N6 | `save_state`/`load_state` → backend `state_get`/`state_set` → `llama_state_seq_get/set_data`; restore a session's KV without re-prefill |
| Shared Prefix | N4 | referenced in the probe (composition confirmation) |

Public names throughout; N-numbers only in this block.

## Scope (reduced, per plan §4 — confirmation at scale, not discovery)

This run does NOT repeat Run 5's full probe battery, does NOT
re-characterize the server (slot save/restore already confirmed on this
exact b9874 build in Run 5 — carried as fact), and does NOT run the
concurrency sweep. It runs: probe-CONFIRMATION on 7B + the break-even
axis {1500, 3000} × M ∈ {1, 8}, three arms.

## Config (pinned)

Model qwen2.5-7b-instruct-q4_k_m (split GGUF, part 1 as --model; sha256 of
both parts in the Run 0 config block), ngl 999 (full offload 29/29),
greedy (temp 0), 64-token continuation, `ignore_eos` on the server arm.
`kv_unified=true` via the harness wrapper around the backend's unchanged
`__init__` (declared, same technique as Run 3/4/5). Sleep disabled
(`powercfg -standby-timeout-ac/dc 0`).

**Equal cell budget:** 32768 cells in every arm (same pool as Run 5 for a
direct cross-model comparison). Fit calc (7B): weights 4.36 GiB + KV
32768 × 56.0 KiB = 1.75 GiB + compute buffers ≈ 6.4 GiB of the ~18.4 GiB
shared device budget; M=8 × (2254 prefix + 64 gen) = 18544 cells < 32768.
Run 4 confirmed a 32768-cell pool fits 7B on this hardware. The in-memory
resume path additionally holds M blobs resident in host RAM (8 × 129 MB ≈
1.0 GiB at 3000×8) — accounted in §6.

Harness: the Run 5 scripts as merged into main
(`benchmarks/bench_persistence.py`, `bench_persistence_server.py`); no
harness change this run. Raw logs `results/kv-persist-sweep/7b-*`
(untracked, per campaign precedent).

## 1. Step 0 — Probe-confirmation on 7B

### Q1 — Round-trip integrity (corruption gate, blocking, run regardless): PASS

`save_state` → FRESH backend → `load_state` → continuation token-identical
at every prefix:

| prefix (nominal) | n_past | blob bytes | token-identical |
|---|---|---|---|
| 500 | 382 | 21,910,688 | **yes** |
| 1500 | 1126 | 64,583,552 | **yes** |
| 3000 | 2254 | 129,281,120 | **yes** |

No corruption on 7B; gate opens.

### Q2 — Unified-KV interaction on 7B: FULL-LOGICAL (reproduced)

A slot seeded from a prefix holder via `seq_cp` (shared cells) serialized
with `state_get`: n_past = 1126, blob = **64,583,552 bytes**. Against the
7B FULL-LOGICAL prediction (56.0 KiB/tok × 1126 = 64,528,384) the match is
**0.09%**; the UNIQUE-ONLY prediction (56.0 × 19 suffix = 1,089,536) is
59× off. Restorable WITHOUT the holder (fresh backend): **token-identical.**

**FULL-LOGICAL reproduced on 7B — the seq_cp/state semantics are
model-size-independent**, as expected. Shared Prefix and KV Persistence
compose on 7B too; each persisted shared session still costs a full-size
blob (the density saving does not survive serialization), now at 2× the
bytes per token.

### Q3 — Cell weight: 56.01 KiB/token (2.0× the 1.5B 28.01)

Measured blob bytes / n_past = 56.01 KiB/tok at 382 / 1126 / 2254 tokens —
matches the theoretical 56.0 (28 layers × 2 × 4 kv-heads × 128 × f16) and
the Run 4 commit-delta measurement (55.7) to within method noise. Exactly
2.0× the 1.5B cell (28.01). The blob at 1126 tokens is 64.58 MB vs 1.5B's
32.30 MB — the denominator of the break-even shift is confirmed at 2×.

## 2. Step 0.5 — Server slot restore: carried as fact from Run 5

The pinned b9874 exposes a real disk-backed slot save/restore
(`--slot-save-path` + `POST /slots/{id}?action=save|restore`), verified
live in Run 5 on this exact build (28.07 KiB/tok, symmetric to ours). Not
re-verified here (same binary); the server arm is its own slot restore — a
fair mechanism-vs-mechanism comparator, not a labeled re-prefill.

## 3. Pre-registration (written AFTER the probe, BEFORE the grid)

Probe branch: **FULL-LOGICAL** (confirmed). Server: exposes slot restore
(fact, Run 5).

Expectation: (1) blob size follows 56.0 KiB/token (2.0× the 1.5B cell); a
1107-token state ≈ 63.5 MB — CONFIRMED at step 0 (64.58 MB at 1126 tok),
retained so the grid blob column can still disappoint. (2) The break-even
sides move in OPPOSITE directions vs 1.5B — the 7B blob is 2× larger
(read/write cost up) while 7B prefill is also more expensive (re-prefill
cost up); which dominates is empirical. (3) Given the 1.5B crossover sat at
~30–40 tokens (two orders below any real prefix), 7B is NOT expected to
restore a crossover at measured prefixes — resume still wins across {1500,
3000}, though the RATIO vs re-prefill may shift as the heavier blob eats
into the heavier-prefill saving. (4) vs tuned server slot restore: parity,
as on 1.5B (symmetric mechanism); differentiator is in-process capability.

Would disappoint if: a crossover appears at a measured prefix on 7B (the
heavier blob dominates — a publishable reversal); or round-trip not
token-identical (STOP — did NOT fire); or blob size deviates from
56.0 KiB/tok (cost model size-dependent — did NOT fire, 56.01 measured).

## 4. Methodology

Identical to Run 5 (`results/kv-persistence-1p5b-igpu.md` §4): three arms
(ours-resume, ours-re-prefill = mechanism ratio on our scheduler NEVER "vs
llama-server", server slot-restore); resume measured BOTH in-memory (warm,
symmetric to the server's warm restore) and cold-disk (`CreateFileW` +
`FILE_FLAG_NO_BUFFERING`, page-cache bypassed — the honest product number;
residual NVMe controller cache declared, not claimed away); write / read /
state_set timed separately; TTFT isolates resume cost from the common
64-token generation; batched generation across M sessions (fair vs the
server's continuous batching); RAW + per-run adjusted; ≥1 warmup + 5
repeats, medians + min–max; cool-downs, arm-order alternation, zero
background load, sleep disabled; real-handle psapi memory; chronometry
gate before the grid.

## 5. Security note (product, per plan §7.2)

Unchanged from Run 5: benchmark blobs are self-produced (safe run); a
shipped disk-backed KV store makes `state_set` a real trust boundary
(SECURITY.md records it as not-yet-validated) — MAC + header validation
needed before release. Consolidation input, not a blocker. On 7B the blobs
are 2× larger, so the disk-store footprint doubles — a scaling note for
the same recommendation.

## 6. Results

(chronometry, grid, break-even, cross-model table — to be filled)

## 7. Observation

(to be filled)
