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

### 6.1 Chronometry (before the grid)

Corruption gate passed at step 0 (the cleanliness gate for KV Persistence,
per Run 5 — there is no near-parity control by construction). Heaviest
point re-prefill 3000×8 ≈ 130 s/repeat (batched prefill of 8 × 2254
tokens on 7B); reduced grid {1500,3000} × {1,8} × 4 arms × 5 repeats +
warmups + cool-downs ≈ 1.5–2 h, under the 6 h trim / 8 h STOP; full
reduced grid run, no trim.

### 6.2 Grid — wall clock (medians of 5), 4 arms

Mechanism ratio = re-prefill / resume-memory (reuse vs recompute on OUR
scheduler — never "vs llama-server").

| point | prefix tok | resume-mem | resume-disk | re-prefill | server | **mech ratio** | srv/resmem | srv/resdisk |
|---|---|---|---|---|---|---|---|---|
| 1500×1 | 1126 | 4.699 | 4.700 | 9.441 | 4.741 | 2.01 | 1.009 | 1.009 |
| 1500×8 | 1126 | 10.738 | 11.109 | 48.776 | 10.112 | 4.54 | 0.942 | 0.910 |
| 3000×1 | 2254 | 4.838 | 4.961 | 15.264 | 4.780 | 3.15 | 0.988 | 0.963 |
| 3000×8 | 2254 | 12.727 | 13.527 | 96.486 | 9.940 | 7.58 | 0.781 | 0.735 |

### 6.3 Break-even — TTFT (resume cost isolated from the common 64-token generation)

| point | resmem TTFT | resdisk TTFT | re-prefill TTFT | server TTFT | read (s) | state_set (s) | write (s) | blob (MB) |
|---|---|---|---|---|---|---|---|---|
| 1500×1 | 0.100 | 0.154 | 4.862 | 0.329 | 0.057 | 0.022 | 0.038 | 61.6 |
| 1500×8 | 0.347 | 0.766 | 38.422 | 0.960 | 0.052 | 0.023 | 0.042 | 61.6 |
| 3000×1 | 0.121 | 0.233 | 10.534 | 0.368 | 0.108 | 0.044 | 0.087 | 123.3 |
| 3000×8 | 0.548 | 1.359 | 84.293 | 0.924 | 0.102 | 0.043 | 0.073 | 123.3 |

**Break-even: NO crossover on 7B — resume wins at every measured prefix,
by a WIDER margin than 1.5B.** Re-prefill TTFT / resume-memory TTFT is
49× (1500×1) → 154× (3000×8); even cold-disk resume beats re-prefill 32×
(1500×1) → 62× (3000×8). No crossover appears — the pre-registered
"publishable reversal" did NOT happen.

### 6.4 Cross-model comparison — did the 2× blob shift the ratio? (the run's question)

| point | blob 1.5B / 7B (MB) | read 1.5B / 7B (s) | state_set 1.5B / 7B (s) | mech ratio 1.5B / 7B (wall) | reprefill/resmem TTFT× 1.5B / 7B |
|---|---|---|---|---|---|
| 1500×1 | 30.8 / 61.6 | 0.043 / 0.057 | 0.021 / 0.022 | 1.95 / 2.01 | 33× / 49× |
| 1500×8 | 30.8 / 61.6 | 0.046 / 0.052 | 0.020 / 0.023 | 3.50 / 4.54 | 54× / 111× |
| 3000×1 | 61.7 / 123.3 | 0.078 / 0.108 | 0.024 / 0.044 | 3.82 / 3.15 | 77× / 87× |
| 3000×8 | 61.7 / 123.3 | 0.053 / 0.102 | 0.023 / 0.043 | 5.44 / 7.58 | 71× / 154× |

**Answer: the ratio shifted, and it shifted UPWARD (in resume's favor) —
the heavier prefill dominates the heavier blob, decisively.** The pre-
registered "opposite directions, which dominates is empirical" resolves
cleanly: the 2× blob added only ~0.01–0.05 s to read and ~0.02 s to
state_set (both scale ~2× as predicted, but from a tens-of-milliseconds
base), while the heavier 7B prefill added TENS OF SECONDS (re-prefill
TTFT 3000×8: 30.3 s → 84.3 s). The blob-cost side is dwarfed. On the
clean TTFT signal the 7B advantage is uniformly larger (49–154× vs
33–71×). The one place the WALL mech ratio is lower on 7B (3000×1: 3.15
vs 3.82) is generation dilution — the common 64-token generation is more
expensive on 7B and, at M=1 with no batching to amortize it, it shrinks
the wall ratio even though the TTFT ratio grew (87× vs 77×).

### 6.5 vs the tuned server (honest baseline): parity, reproduced

srv/resmem RAW 0.78–1.01 — parity, with the server slightly ahead at
3000×8 (0.781) via its mature continuous batching, exactly the 1.5B
pattern (0.83 at that point). The server's `restore_ms` scales with blob
(18.2 / 37.2 ms at 1500/3000 ×8) as our `state_set` does (0.023 / 0.043 s)
— symmetric. RAW carries the conclusion; the transport adjustment only
moves the server faster (already at parity/ahead), so it cannot change
the reading. srv/resdisk (server warm vs our unbuffered cold) still lands
at parity (0.74–1.01). The differentiator remains in-process capability,
not raw speed.

### 6.6 Blob metrics, checkpoint cost, memory

- Blob 56.01 KiB/tok confirmed on the grid (61.6 / 123.3 MB at 1126 /
  2254 tok) — 2× the 1.5B, cost model holds.
- Checkpoint (write) cost, separate: ours `fsync`'d 0.038–0.087 s; the
  server's `save_ms` 336.6 / 751.0 ms at 1500/3000 ×8 (2× its 1.5B save,
  it serializes the whole slot). Amortized over many resumes.
- Memory (real-handle psapi): the in-memory resume path holds M resident
  blobs — peak WS 11257 → 12740 MB (1500×1 → 3000×8; ≈ +1.0 GiB of
  resident blobs at 3000×8, 2× the 1.5B +0.5 GiB); re-prefill flat
  (~10658 MB, no blobs); server RSS 10544–11442 MB. Free-RAM floor held,
  no swap. The in-memory path's RAM cost doubles with the model, as
  expected; the disk path stays flat.

## 7. Observation

Verdict vs the pre-registration: **confirmed on all four expectations;
the disappointment clauses (crossover on 7B; non-token-identical;
size-dependent cost model) did NOT fire.**

1. **Probe (gate + confirmation):** round-trip token-identical at every
   prefix; FULL-LOGICAL reproduced on 7B (blob self-contained, restorable
   without the holder); cell weight 56.01 KiB/tok = 2.0× the 1.5B. The
   `seq_cp`/state semantics are model-size-independent.
2. **Break-even: no crossover — resume wins at every measured prefix,
   MORE strongly than on 1.5B** (mechanism ratio to 7.58× wall / 154×
   TTFT vs 5.44× / 71×). The heavier blob did NOT reverse anything.
3. **The run's question answered:** the 2× blob shifted the ratio UPWARD,
   not downward — the heavier prefill (tens of seconds) dwarfs the heavier
   blob read+state_set (tens of milliseconds). KV Persistence gets MORE
   valuable as the model grows, because prefill cost scales faster than
   state-transfer cost.
4. **vs the tuned server: parity reproduced** (srv/resmem 0.78–1.01,
   symmetric mechanism, server ahead at the largest batched point). The
   differentiator is in-process capability, not speed.
5. **Honest costs recorded:** the in-memory path's resident-blob RAM cost
   doubles with the model (+1.0 GiB at 3000×8); the cold-disk path
   (unbuffered) is the product number and still wins everywhere; the NVMe
   controller cache is the declared residual.

Net for consolidation: KV Persistence is a clean, model-size-robust win —
resume beats re-prefill at every prefix on both models, and the advantage
GROWS with model size (the state-transfer cost is dominated by the prefill
it replaces). Parity with the tuned server's slot restore holds on both
models; the product value is the in-process capability (an agent survives
a process restart with its context intact, no server). The FULL-LOGICAL
composition result (Shared Prefix persists standalone, at full blob size,
2× the bytes on 7B) and the `state_set` trust-boundary note (§5, doubled
disk footprint on 7B) are the forward-looking inputs, alongside Run 5.
