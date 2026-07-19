# Bench report — N4 shared-prefix KV — 1.5B — iGPU/Vulkan

- Run ID:            n4-shared-prefix-1p5b-igpu
- Date / operator:   2026-07-19 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged: pin 7745853 for measured
  code — `git diff 7745853..main -- src/palimpsests` is empty, branch created
  from the pin and fast-forwarded to main 617a2d8 for the Run 1 harness
  files only; same venv 0.5.1.dev0 (editable), same llama-cpp-python 0.3.33
  Vulkan, same pinned llama-server b9874 @ 78d2f524, same models/sha256,
  same driver 101.8331)

## Config (pinned)

As Runs 0.2–2 (config block hashed to dd2e395be22675f1). Model:
qwen2.5-1.5b-instruct-q4_k_m.gguf, ngl 999 (full offload 29/29), greedy
(temp 0), 64 tokens generated per session (`GEN_TOKENS_N4`, plan §3),
`ignore_eos` on the server arm to match the native arms' `stop_tokens=()`.

**Slot budget (maintainer decision, applied):**

```
concurrency budget P = 8 (chosen from step 1, not a default; see §2)
server arm:  llama-server b9874, --parallel 8, --ctx-size 32768
             (per-slot n_ctx = 32768/8 = 4096 — verified via /slots),
             cache_prompt: true, slots erased between repeats (verified
             cache_n == 0), one untimed session warm request after health.
ours arm:    LlamaCppBackend n_ctx=32768, n_seq_max=9 (= P+1: 8 session
             slots + 1 prefix holder), max_active=8, kv_unified=true (see
             memory-probe: sharing is architecturally impossible in the
             default split mode) — one context-flag deviation from the
             pinned backend defaults, applied by the harness through the
             backend's own unchanged __init__; generation-identity
             verified split-vs-unified (24/24 greedy tokens identical
             after copy_prefix_to_slot).
mech arm:    identical backend config to ours (n_ctx=32768, n_seq_max=9,
             kv_unified=true, max_active=8); no holder — every session
             prefills prefix+suffix from scratch on the same scheduler.
effective session budget: ours P=8, server P=8; holder slot accounted
             separately as a cost of our design (its sequence id and its
             prefix cells are inside our arm's memory column).
total KV cell budget: 32768 cells in every arm (equal-budget discipline);
             1.5B KV ≈ 28.0 KiB/token measured (commit delta 783 MB for
             28672 extra cells between probe configs).
```

Harness: `benchmarks/bench_shared_prefix.py` (probe + ours + mech),
`benchmarks/bench_shared_prefix_server.py` (characterize + server arm),
workload content in `benchmarks/_workload.py` (`session_suffix`,
`GEN_TOKENS_N4` added; existing N5 content untouched). Raw logs:
`results/n4-sweep/` (untracked, per Run 1 precedent).

## 1. Step 0 — MEMORY-PROBE: does `seq_copy` copy or share? (gate, run first)

Question: `llama_memory_seq_cp` (our `seq_copy` / `copy_prefix_to_slot`) —
does it COPY the prefix KV cells into the destination sequence or SHARE
them (ref/COW)? Probed on OUR backend config (not the server), prefix
~1500 nominal (1107 measured), copies K = 1..8, then short decodes into
copied slots (a COW copy would materialize on first write), then
capacity-to-failure. Process RSS/commit + system-available recorded at
every step (psapi / GlobalMemoryStatusEx); llama.cpp preallocates the
whole KV buffer at context creation, so byte-level counters cannot decide
the cell question alone — the decisive evidence is capacity (what fits in
a fixed cell pool). No used-cell API is exposed by these bindings;
`llama_memory_seq_pos_max` verified every copy landed (pos_max 1106).

**The memory mode is itself the finding.** The pinned backend creates
contexts with llama.cpp's default `kv_unified=false` — per-sequence KV
streams:

| scenario | config | result |
|---|---|---|
| S1 split (default), tight | n_ctx 8192, n_seq_max 9 | warm of 1107-token prefix **FAILS** (`llama_decode rc=1`): per-seq budget = n_ctx/n_seq_max = 910 < 1107. The pool is hard-partitioned per sequence — sharing is architecturally impossible; each stream's cells are reserved at construction regardless of content. |
| S2 split, roomy | n_ctx 36864, n_seq_max 9 | warm 1.32 s; 8 copies OK (0.1–0.2 ms each, pos_max verified); decodes in 3 slots OK; RSS/commit flat throughout (expected: buffer preallocated — flatness proves nothing here). |
| S3 unified, capacity test | n_ctx 8192 (shared pool), n_seq_max 9, kv_unified | warm + **8 copies + decodes in 3 slots all fit: 9 sequences × 1107 tokens = 9963 logical cells inside 8192 physical cells.** Memory flat after first decodes (survives first write — not COW-materialize). |
| S4 unified, boundary | n_ctx 2048 (pool < 2 × prefix), n_seq_max 9, kv_unified | **8 copies + decodes fit in a 2048-cell pool.** Copy semantics would have failed at the FIRST copy (2 × 1107 = 2214 > 2048). |

**Verdict: in the unified-KV mode `seq_cp` SHARES the prefix cells (flat
in K, surviving first decode) → the SHARE branch of the pre-registration
is activated.** In the pinned default (split) mode, per-sequence streams
are hard-partitioned and pre-reserved — the memory cost of a session is
its full stream regardless of sharing, i.e. copy semantics in practice.
Consequence for the grid: the ours/mech arms run with `kv_unified=true`
(one context flag, declared above, generation-identity verified);
consolidation input: the backend should expose this flag first-class,
since N4's design intent (`share_prefixes`) is only real in this mode.

`seq_copy` cost: 0.1–0.2 ms at prefix 1107 in both modes (vs ~1.3 s to
prefill the same prefix — four orders of magnitude).
`llama_state_seq_get_size` reports the LOGICAL size (31.75 MB for the
1107-token sequence in both modes) and cannot distinguish share from
copy; recorded as supporting data only.

## 2. Step 1 — server slot mechanics characterization (pinned b9874)

Protocol: shared prefix ~1500 (1126 measured with the session suffix
boundary), M different sessions (unique short suffixes), on
--parallel 8 / --ctx-size 32768 unless stated. Full logs in
`results/n4-sweep/char-*.log`.

- **(а) Prefix reuse across slots: NO — cross-slot sharing does not
  exist.** M=8 sessions fired concurrently: every session lands on its
  own slot and pays the FULL prefix prefill (prompt_n=1126, cache_n=0 on
  all 8 slots; wall 19.6–19.9 s; TTFT staircase 1.9 → 15.4 s — slot
  prefills serialize through the shared pipeline). Sequentially the
  picture inverts: the similarity router sends every next session to the
  SAME slot, which serves it from the prefix cache up to the branch point
  (cache_n=1111, prompt_n=15 — suffix only; 2.73 s first session, ~1.6 s
  each subsequent).
- **(б) Beyond the slot budget (M=12 > P=8): eviction does NOT punish
  this workload with full re-prefill.** Queued sessions are routed to
  freed slots whose cache shares the prefix up to the branch point →
  suffix-only prefill (~half the M=12 sessions show cache_n≈1111,
  the rest 0; wall 21.7–23.0 s).
- **(в) --parallel P effect: per-slot context = n_ctx/P (verified via
  /slots: 4096 at P=8), server peak RSS ≈ 2.99 GB at P=8/32768 (model
  1.04 GB + full-ctx KV ≈ 0.92 GB + runtime).**
- **Variants tried (strong-opponent duty):** `--kv-unified`: no behavior
  change, slightly worse wall (20.4–20.7 s), same RSS — the server does
  not share prefix cells across slots in either mode. `--cache-reuse
  256`: no change (19.8–20.0 s) — the mechanism targets shifted chunks,
  not identical prefixes. **`--parallel 4` at M=8: wall 12.5–12.8 s —
  BETTER than P=8**, because only 3–4 slots pay the full prefill and the
  rest reuse freed slots' prefix cache. Recorded as an honest finding:
  the server's per-workload optimum is FEWER slots than sessions. The
  grid nonetheless holds P=8 in both arms per the maintainer's
  budget-parity decision (same concurrency capacity in both arms; a
  P<M server serves M sessions with LESS concurrency, which is a
  different deployment promise); the P=4 number is reported alongside in
  §6 so the comparison cannot be accused of a handicapped opponent.

Honest server config for the grid (from this step): **--parallel 8,
--ctx-size 32768, default KV mode, cache_prompt: true, slot erase between
repeats, one untimed warm request per server session.**

## 3. Pre-registration (written BEFORE the grid; step 0 + step 1 done, grid not started)

Branch declared by the probe (step 0): **SHARE**.

- **Branch SHARE (ACTIVATED):** seq_cp shares prefix cells (flat memory
  in K, surviving first decode). N4 thesis = DENSITY: more concurrent
  sessions in the same KV budget at speed parity or better. Expectation:
  memory advantage O(1) prefix vs server's per-slot prefix copies;
  feasibility crossing in sessions favors us; adjusted speed parity
  within the slot budget, advantage under contention (M > P) and under
  concurrent arrival (server pays per-slot prefix prefills — step 1
  showed cache_n=0 on all slots concurrently).
- Branch COPY (recorded, NOT activated): seq_cp copies cells (linear
  memory in K). N4 thesis = LATENCY UNDER CONTENTION only: prefill paid
  once vs re-prefill per evicted slot; the memory axis honestly reports
  no density win. Expectation: advantage only at sessions > slot budget,
  growing with M × prefix; memory parity.
- Shared clauses: (3) mech-vs-ours (both on our scheduler, only
  reuse-vs-recompute differs) is the CLEAN mechanism signal; srv-vs-ours
  is the competitive comparison, and beyond the slot budget it mixes
  mechanism with scheduler (ours vs theirs) — stated as a methods caveat;
  adjusted removes transport only. (4) Would disappoint if: the server
  reuses the shared prefix across slots efficiently at any M
  (differentiation dies — record it; step 1 already shows it does NOT
  cross-slot-share, but DOES recover prefix via freed-slot routing beyond
  the budget, which caps our contention win — recorded); or seq_copy cost
  grows with prefix enough to eat the contention win (step 0: 0.2 ms —
  it does not, but the grid re-checks at 3000); or the holder cost
  negates the session budget at small P; or ours loses adjusted parity
  (<0.9) anywhere within the slot budget.

Quantitative expectations, falsifiable: near-parity (0.9–1.2 adjusted)
at M=1 for every prefix; srv/ours growing with M at fixed prefix and
with prefix at fixed M for concurrent arrival (server: ~M_slots × prefix
prefills serialized; ours: 1 prefill + M copies at 0.2 ms); mech/ours
similarly growing (mech pays M prefills on our own scheduler — the
mechanism-only ratio); feasibility (prefix 1500, same 32768-cell KV
budget): ours holds MORE live sessions than the server's slot model
(server per-slot partition must fit prefix+suffix+gen per slot →
~27 slots max at 32768; ours shares the prefix across sessions —
bounded by n_seq_max / pool remainder, expected well beyond 27).

## 4. Methodology (fixed before the grid)

- Three arms per point (§Config); M sessions all "arrive" at t0
  concurrently in every arm: native arms admit up to P into the batched
  scheduler, the rest queue and enter freed slots (ours: re-seeded by
  holder copy; mech: full re-prefill); server arm fires M parallel HTTP
  requests. Per-session TTFT is measured from t0 — queue wait is part of
  TTFT by design (that IS the contention signal at M > P).
- ≥1 warmup + 5 timed repeats per invocation; medians + min–max; 30 s
  cool-down between invocations (60 s after heavy ones); arm order
  alternated between grid points; zero background load; system sleep
  disabled for the sweep (Run 2 incident lesson).
- Wall includes the ours-arm's holder warm (the prefill paid once) —
  nothing is amortized away outside the measurement.
- RAW + per-run ADJUSTED per the Run 1 amended convention, estimator and
  clamping per Run 2 — **estimator definition amended at the gate, BEFORE
  the sweep (both computations preserved in the logs):** the per-point
  TTFT-difference estimator is contaminated at M > 1 concurrent (at 50×8
  it measured 0.421 s/req — 4× the anchor; that is batch-admission +
  per-stream SSE serving overhead, not transport, and ×M it
  over-subtracts into absurdity — adj ratio 0.36). Amended per-run
  estimator: transport/request = (server TTFT − mechanism TTFT) at the
  M=1 point of the SAME prefix — the two arms with the structurally
  identical single-prefill-to-first-token path (ours' M=1 TTFT contains
  the holder warm + copy as a separate decode and is not a clean
  transport comparator). Measured at the gate: 0.119 s/req at prefix 50 —
  consistent with the 0.102 anchor. adjusted_server_wall = raw −
  transport × M is an UPPER BOUND on transport's wall contribution
  (concurrent requests overlap compute), i.e. conservative in the
  server's favor; † flags where the M=1 estimator itself deviates from
  the anchor by more than 2× either way (clamped to 0 if negative).
  Conclusions must agree between RAW and ADJUSTED or the run STOPS.
- Two-tier gates as Runs 1–2: tier 1 ours/mech RAW at the 50×1 control
  (our-stack cleanliness), band 0.9–1.2; tier 2 server pairs at the
  amortized 50×8 point, adjusted cross-check ≤ 1.2.
- Narrative rule (campaign-wide): the mechanism ratio is "vs stateless
  re-prefill per session (no prefix reuse at all), same scheduler" — it
  measures the value of having shared-prefix seeding at all, never an
  advantage over llama-server. The only competitive headline is
  ADJUSTED ours-vs-tuned-server.
- Memory per point, both native arms and server: process peak working
  set + commit (psapi, real-handle path) and system available-physical
  (GlobalMemoryStatusEx); UMA iGPU — device-local Vulkan allocations
  live in system RAM; no separate GPU counter exists (stated per Run 1
  precedent). Cell-level accounting from the equal 32768-cell budget and
  the step-0 semantics. Server RSS via psapi on the server PID.
- Chronometry estimate before the sweep; STOP threshold ~8 h with the
  pre-agreed reduction priority (1500 × all M; M=8 × all prefixes;
  control).

## 5. Results

### 5.1 Control gates (two-tier, measured before the sweep)

| tier | pair | point | ratio | band | verdict |
|---|---|---|---|---|---|
| 1 (our-stack cleanliness) | ours/mech RAW | 50×1 | 1.079 | 0.9–1.2 | PASS |
| 2 (server pairs, amortized) | server/mech ADJ | 50×8 | 1.140 (raw 1.453) | ≤1.2 | PASS |
| 2 (server pairs, amortized) | server/ours ADJ | 50×8 | **1.199** (raw 1.529) | ≤1.2 | PASS — at the band edge |

Gate raw data (medians of 5): 50×1 ours 1.402 / mech 1.299 / server 1.446;
50×8 ours 2.891 / mech 3.041 / server 4.419. Transport estimator at 50×1:
server−mech TTFT = 0.202−0.083 = 0.119 s/req (anchor 0.102 ✓). The
tier-2 server/ours pass at 1.199 is at the edge of the band: the residual
above one-request transport is the server's concurrent-serving overhead
(8 parallel SSE streams + batch admission; apparent 0.421 s/req at M=8),
which the amended estimator deliberately does NOT subtract — recorded
plainly, monitored across the sweep, and discussed in §6.

At the control the ours-arm is ~8% SLOWER than mech at M=1 (holder warm +
copy as separate decode calls vs one prefill) — the holder cost the
pre-registration's disappointment clause watches; it buys the M>1 wins.

### 5.2 Chronometry estimate (before the sweep)

Most expensive point 3000×12, 1 repeat: ours 11.7 s, mechanism 57.3 s,
server 42.6 s → full-grid projection (18 points × 3 arms × 6 repeats +
36 native model loads + 18 server starts + cool-downs) ≈ 2.0–2.5 h,
feasibility ≤ ~1.5 h — well under the 8 h stop threshold; proceeded with
the full grid, no reduction needed.

### 5.3 Grid — 18 points × 3 arms (medians of 5 timed repeats)

The mechanism ratio below is vs stateless per-session re-prefill (no
prefix reuse at all), same scheduler; **the mechanism ratio measures the
value of having shared-prefix seeding at all, not an advantage over
llama-server.** Transport/request per the amended §4 estimator (M=1
server−mech TTFT of the same prefix): 0.127 / 0.129 / 0.090 s at prefix
500 / 1500 / 3000 — all inside the anchor sanity band, no † flags;
adjusted = raw − transport × M (upper bound, conservative in the
server's favor). RAW and ADJUSTED agree in their conclusions at every
point — no automatic stop.

| point | measured prefix | ours | mechanism | server RAW | mech/ours | srv/ours RAW | srv/ours ADJ | transport/req (s) |
|---|---|---|---|---|---|---|---|---|
| 500×1 | 363 | 1.701 | 1.613 | 1.757 | 0.95 | 1.033 | 0.958 | 0.127 |
| 500×2 | 363 | 1.809 | 2.217 | 2.482 | 1.23 | 1.372 | 1.231 | 0.127 |
| 500×4 | 363 | 2.314 | 4.416 | 4.734 | 1.91 | 2.046 | 1.826 | 0.127 |
| 500×6 | 363 | 2.945 | 6.665 | 7.496 | 2.26 | 2.545 | 2.286 | 0.127 |
| 500×8 | 363 | 3.470 | 8.281 | 8.463 | 2.39 | 2.439 | 2.146 | 0.127 |
| 500×12 | 363 | 7.080 | 12.928 | 10.277 | 1.83 | 1.452 | 1.236 | 0.127 |
| 1500×1 | 1107 | 2.620 | 2.483 | 2.627 | 0.95 | 1.003 | 0.954 | 0.129 |
| 1500×2 | 1107 | 2.765 | 5.279 | 4.474 | 1.91 | 1.618 | 1.525 | 0.129 |
| 1500×4 | 1107 | 3.346 | 10.325 | 10.095 | 3.09 | 3.017 | 2.863 | 0.129 |
| 1500×6 | 1107 | 5.120 | 14.427 | 15.246 | 2.82 | 2.978 | 2.827 | 0.129 |
| 1500×8 | 1107 | 6.196 | 17.873 | 18.324 | 2.88 | 2.957 | 2.791 | 0.129 |
| 1500×12 | 1107 | 6.815 | 21.087 | 15.200 | 3.09 | 2.230 | 2.004 | 0.129 |
| 3000×1 | 2235 | 4.079 | 4.001 | 4.108 | 0.98 | 1.007 | 0.985 | 0.090 |
| 3000×2 | 2235 | 4.418 | 7.243 | 7.038 | 1.64 | 1.593 | 1.552 | 0.090 |
| 3000×4 | 2235 | 5.184 | 14.909 | 14.210 | 2.88 | 2.741 | 2.671 | 0.090 |
| 3000×6 | 2235 | 6.283 | 20.815 | 20.632 | 3.31 | 3.284 | 3.198 | 0.090 |
| 3000×8 | 2235 | 6.833 | 27.909 | 26.744 | 4.08 | 3.914 | 3.809 | 0.090 |
| 3000×12 | 2235 | 9.361 | 42.541 | 29.263 | 4.54 | 3.126 | 3.011 | 0.090 |

Shape notes (vs pre-registration):

- **M=1 near-parity everywhere** (mech/ours 0.95–0.98 — the holder cost;
  srv/ours ADJ 0.954–1.015): control behavior as pre-registered.
- **Growth with M at fixed prefix and with prefix at fixed M**, peaking
  at 3000×8: mech/ours 4.08, srv/ours RAW 3.914 / ADJ 3.809. The
  concurrent server pays its prefix prefill per slot (step 1 (а));
  ours pays one warm + 0.2 ms copies.
- **The M=12 > P dip is real and honest**: at every prefix the M=12
  srv/ours ratio DROPS vs M=8 (e.g. 1500: 2.96 → 2.23; 3000: 3.91 →
  3.13) — beyond the slot budget the server's freed-slot prefix cache
  (step 1 (б)) serves queued sessions with suffix-only prefills, while
  our wave-2 sessions wait for generation slots. The contention win
  does NOT grow past the slot budget on this workload — it saturates at
  M≈P and partially erodes beyond it. Recorded exactly as measured;
  this is the pre-registered disappointment clause firing PARTIALLY
  (the server recovers the shared prefix efficiently beyond the budget
  via slot-cache routing — differentiation narrows but does not die:
  2.0–3.0 adjusted at M=12).
- Per §2, at M=8 a per-workload-tuned server would prefer P=4
  (12.5–12.8 s ≈ 2.0× ours instead of 2.96× at P=8, prefix 1500) — the
  equal-P comparison is the maintainer's budget-parity design; both
  numbers are in this report and the honest competitive claim at M≈P
  is the ~2× of the P<M-tuned server, not the ~3× of the equal-P one.

### 5.4 Memory (grid points; method per §4)

Flat across all points in every arm, as pre-registered for equal
preallocated pools: ours/mech process peak WS 3267–3278 MB (model
1.04 GB + 32768-cell KV ≈ 0.92 GB + runtime; identical config in both
native arms — the holder adds no measurable bytes, its prefix cells are
shared), server peak RSS 2993–3096 MB (same pool, no Python driver in
the process). System-available floor stable ≈ 13.0–13.3 GiB, no swap.
The byte columns CANNOT differentiate the arms at fixed pool size — the
density difference is in cells-per-session and is measured by the
feasibility axis (§5.5): the same 32768-cell pool holds P=8 slot-bound
server sessions vs our shared-prefix sessions bounded by
n_seq_max/suffix cells.

### 5.5 Feasibility axis (prefix 1500, M upward to failure; equal 32768-cell KV budget)

Configuration for this axis (differs from the grid deliberately): ours
runs ALL M sessions concurrently live (max_active = M, n_seq_max = M+1 —
the density claim is about live KV, not wave scheduling); server runs
--parallel M. 1 warmup + 1 timed repeat per step (runs-vs-fails axis).

| M live sessions | ours wall (s) | server wall (s) |
|---|---|---|
| 12 | 10.36 | 24.06 |
| 16 | 11.18 | 29.30 |
| 24 | 11.85 | 41.01 |
| 28 | — | 47.03 |
| 31 | — | **52.22 — server's last alive** |
| 32 | 12.53 | **FAILS** — HTTP 400 `exceed_context_size_error`: "request (1126 tokens) exceeds the available context size (1024 tokens)" — per-slot partition 32768/32 |
| 48 | 13.13 | — |
| 64 | 14.63 | — |
| 96 | 21.82 | — |
| 128 | 26.29 | — |
| 192 | 39.99 | — |
| 255 | **48.74 — ours' last alive** (255/255 sessions completed) | — |
| 256 | **FAILS** — `llama_new_context_with_model failed`: n_seq_max = 257 exceeds llama.cpp's sequence cap (256) | — |

**Who fell first, and on what: the server, at 32 sessions, on per-slot
context arithmetic** (slot ctx = n_ctx/P, padded to a 256 granularity —
measured: 1280 at P=30/31, 1024 at P=32; the 1126-token shared prefix no
longer fits a slot). **Ours fell at 256 sessions on llama.cpp's sequence
cap** (n_seq_max ≤ 256), NOT on memory: at 255 live sessions the shared
pool held ≈ 21.3k of 32768 cells (1107 shared prefix + 255 × ~79 unique
suffix+generation cells) and process peak WS grew only 3.27 → ≈3.5 GB
(~1.2 MB/sequence of runtime bookkeeping); system-available floor never
moved (≈13.6 GiB of the ~18.4 GiB shared budget still free). Cell
arithmetic says ~395 sessions would fit the pool if the sequence cap
were lifted — the recorded bound is the engine's, not the design's.

**Headline (SHARE branch, pre-registered): 255 vs 31 live sessions on
the SAME 32768-cell KV budget — an 8.2× session-density crossing in our
favor** — and at its own edge ours serves 255 sessions in less wall time
(48.7 s) than the server needs for its 31 (52.2 s). Every step of both
columns completed all its sessions (no silent partial service; ours'
per-step session counts verified from the per-session completion lists).

### 5.6 Instrumentation notes (honest methods)

- The Run 1 native-RSS polling artifact is fixed in this harness (psapi
  through a real OpenProcess handle; the pseudo-handle truncates through
  bare ctypes and fails silently) — native memory numbers in this report
  are real readings.
- `llama_state_seq_get_size` reports logical (not physical) bytes and
  cannot see sharing; capacity-to-failure is the cell-level instrument.
- Server per-slot context is padded (measured 1280 at P=30/31 where
  n_ctx/P = 1092/1057) — the acceptance edge is therefore 31, not the
  naive floor(32768/1126) = 29.
- One methodological amendment was made between the gate and the sweep
  (transport estimator, §4) — before any sweep number existed; both
  estimator computations are preserved in the raw logs.

## 6. Observation

Verdict vs the pre-registration (SHARE branch): **confirmed on the
density thesis and the within-budget speed axis; one pre-registered
disappointment clause fired partially and is reported as measured.**

1. **Memory probe (the campaign's load-bearing finding):** `seq_cp`
   SHARES prefix KV cells in llama.cpp's unified-KV mode — flat in K,
   surviving first decode (not COW), proven by capacity (9 × 1107
   logical cells inside a 2048-cell pool). In the pinned backend's
   default split mode sharing is architecturally impossible (hard
   per-sequence partition, n_ctx/n_seq_max). N4's `share_prefixes`
   design intent is only real with `kv_unified=true` — consolidation
   input: the backend should expose this flag first-class.
2. **Density (the SHARE-branch headline): 255 vs 31 live sessions on
   the same 32768-cell budget (8.2×)**, ours bounded by the engine's
   sequence cap with ~11.5k cells still free, the server bounded by its
   per-slot context partition. The O(1)-prefix memory expectation held:
   session marginal cost ≈ 79 cells (suffix + 64 generated) vs the
   server's ≥ 1280-cell slot.
3. **Speed grid:** near-parity at M=1 everywhere (ADJ 0.954–1.015;
   the ~5–8% holder cost at the control is the pre-registered price of
   the design and stays in band); the advantage grows with M and prefix
   to **3.81 adjusted (3.91 raw) at 3000×8 — within the slot budget,
   where the comparison is scheduler-clean**. The mechanism ratio (vs
   stateless per-session re-prefill on our own scheduler — the value of
   shared-prefix seeding itself, not an advantage over llama-server)
   grows 0.95 → 4.54.
4. **The partial disappointment, reported plainly:** beyond the slot
   budget (M=12 > P=8) the server's freed-slot prefix cache serves
   queued sessions with suffix-only prefills and the ratio RECEDES
   (3.91 → 3.13 raw at 3000; 2.96 → 2.23 at 1500) — the contention win
   saturates at M ≈ P instead of growing with M as the COPY-branch
   logic would have predicted. Additionally, a per-workload-tuned
   server would run P < M (P=4 at M=8: 12.5–12.8 s ≈ 2.0× ours) — the
   honest competitive claim at M ≈ P is ~2× vs that tuned
   configuration, ~2.9–3.8× only under the equal-P budget-parity
   design. Both numbers are in this report.
5. `seq_copy` cost does NOT grow into relevance with prefix (0.07 /
   0.31 / 0.35 ms median at 363 / 1107 / 2235 tokens vs 0.37 / 1.59 /
   2.60 s warm) — that disappointment clause did not fire.
6. Transport: 0.127 / 0.129 / 0.090 s/request (M=1 estimator, anchor-
   consistent); RAW vs ADJUSTED conclusions agree at every point.

Net framing for consolidation: N4's differentiation on this hardware is
(a) session DENSITY on a fixed KV budget (8.2× at the measured edge,
engine-capped, not memory-capped) and (b) concurrent-arrival latency
within the slot budget (up to ~3.8 adjusted at equal P, ~2× vs the
P-tuned server); it is NOT a beyond-slot-budget contention win — the
server's slot-cache routing already handles that case well for
identical-prefix workloads.
