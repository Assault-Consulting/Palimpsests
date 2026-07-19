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
  clamping per Run 2: transport/request estimated per point as
  (server first-session TTFT median − ours first-session TTFT median);
  adjusted_server_wall = raw − transport × M (one request per session);
  estimator sanity vs the Run 0.3 anchor 0.102 s/request — flagged †
  and clamped to 0 where unphysical (negative) or sunk in prefill noise
  (adjusted = raw, the physically correct limit). Conclusions must agree
  between RAW and ADJUSTED or the run STOPS.
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

(to be filled after the grid — sections 5.x reserved: gates, chronometry,
grid table, feasibility, memory)

## 6. Observation

(to be filled after the grid)
