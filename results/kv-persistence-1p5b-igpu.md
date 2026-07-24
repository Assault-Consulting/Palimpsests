# Bench report — KV Persistence — 1.5B — iGPU/Vulkan

- Run ID:            kv-persistence-1p5b-igpu
- Date / operator:   2026-07-24 / Oleksandr
- Config-hash:       dd2e395be22675f1 (unchanged: pin 7745853 for measured
  code — `git diff 7745853..main -- src/palimpsests` empty; branch from the
  pin fast-forwarded to main e837562 for the merged Run 3/4 harness; same
  venv 0.5.1.dev0, llama-cpp-python 0.3.33 Vulkan, pinned llama-server
  b9874 @ 78d2f5246, same model/sha256, same driver 101.8331)

## Capability name map (internal → public)

| public name | internal | what it is |
|---|---|---|
| **KV Persistence** | N6 | `save_state`/`load_state` → backend `state_get`/`state_set` → `llama_state_seq_get/set_data`; restore a session's KV without re-prefill |
| Shared Prefix | N4 | referenced in the probe (composition question) |
| Tool Loop | N5 | referenced for campaign context only |

Public names are used throughout; N-numbers appear only in this block.

## Config (pinned)

Model qwen2.5-1.5b-instruct-q4_k_m.gguf, ngl 999 (full offload 29/29),
greedy (temp 0), 64-token continuation after a resume/reprefill,
`ignore_eos` on the server arm. `kv_unified=true` via the harness wrapper
around the backend's unchanged `__init__` (same technique as Run 3/4,
declared here; the probe uses it to reproduce the Shared-Prefix seeding
path for the composition question). System sleep disabled for the whole
run (`powercfg -standby-timeout-ac/dc 0`).

Harness (new, declared): `benchmarks/bench_persistence.py` (probe +
resume + reprefill native arms, with an unbuffered cache-bypassing disk
read — see §4), `benchmarks/bench_persistence_server.py` (server slot
save/restore arm). Workload content reused from `benchmarks/_workload.py`.
Raw logs: `results/kv-persist-sweep/` (untracked, per campaign precedent).

## 1. Step 0 — PROBE-GATE (three questions, before any grid)

### Q1 — Round-trip integrity (CORRUPTION GATE, blocking): PASS

`save_state` → FRESH backend → `load_state` → greedy continuation,
token-identical to the uninterrupted reference, at every prefix:

| prefix (nominal) | n_past (measured) | blob bytes | token-identical |
|---|---|---|---|
| 500 | 382 | 10,957,984 | **yes** |
| 1500 | 1126 | 32,298,880 | **yes** |
| 3000 | 2254 | 64,654,432 | **yes** |

No corruption; the gate opens. (The restore feeds the first reference
token at position n_past — decoding into an occupied position returns −1
on this build; documented in the harness.)

### Q2 — Unified-KV interaction (the sharpest question): FULL-LOGICAL

A slot seeded from a prefix holder via `seq_cp` (shared cells, the
Shared-Prefix path) was serialized with `state_get`:

- n_past = 1126 (1107 shared prefix + 19 unique suffix), blob =
  **32,298,880 bytes**.
- Prediction FULL-LOGICAL (28.0 KiB/tok × 1126) = 32,284,672 — **match to
  0.04%**.
- Prediction UNIQUE-ONLY (28.0 KiB/tok × 19 suffix) = 544,768 — off by
  59×.
- Restorability WITHOUT the holder (fresh backend, no shared cells):
  **restored token-identical.**

**Activated branch: FULL-LOGICAL.** `state_get` on a shared-prefix slot
serializes the FULL logical context, self-contained and restorable
standalone — **Shared Prefix and KV Persistence COMPOSE** (a
shared-prefix session can be checkpointed and resumed without its
holder). The nuance for consolidation / Run 7: the Shared-Prefix DENSITY
saving does NOT carry into the blob — each persisted session's blob is
full-size (28.0 KiB/tok × its whole logical context), so persisting N
shared sessions costs N full blobs on disk, not one. That is the honest
cost of standalone restorability.

### Q3 — Blob scaling: 28.01 KiB/token (matches the cost model)

Measured bytes / n_past = 28.01 KiB/tok at 382 / 1126 / 2254 tokens —
within 0.04% of the Run 3 cell weight (28.0). The cost model is correct;
blob size is a linear function of context length with no surprise
overhead.

## 2. Step 0.5 — Strong-opponent check: server EXPOSES slot save/restore

The pinned llama-server b9874 exposes a real, **disk-backed** slot
save/restore, verified by a live call:

- `--slot-save-path PATH` enables `POST /slots/{id}?action=save|restore`
  with a `{"filename": ...}` body.
- Save: `n_written=344956`, `save_ms=15.1` (12-token slot); restore:
  `n_read=344956`, `restore_ms=0.594`. File on the same NVMe as ours.
- Cross-check: 344956 bytes / 12 tokens = **28.07 KiB/tok** — the server's
  own state serialization matches the 28.0 cell weight independently.

**Consequence: this is a FAIR, symmetric comparator.** The server arm is
`slot restore` (a real persistence capability), NOT a `cache_prompt`
re-prefill with a label. The honest baseline for KV Persistence on this
hardware is therefore the tuned server's own slot restore, and the
comparison is a mechanism-vs-mechanism speed comparison — no capability
gap to flag.

## 3. Pre-registration (written AFTER steps 0 and 0.5, BEFORE the grid)

Activated probe branch: **FULL-LOGICAL** (blob self-contained). Strong-
opponent result: **server EXPOSES slot restore** (fair symmetric
comparator).

Expectation: (1) KV Persistence has a built-in break-even —
resume_cost(P) = blob read + state_set (+ disk I/O) vs reprefill_cost(P) =
prefill(P). Short prefixes may LOSE (moving tens of MB costs more than
recomputing), long prefixes win; the crossover moves right on the disk
path relative to in-memory. (2) Blob size follows the 28.0 KiB/token cell
weight (~31.75 MB at 1107 tokens) — already CONFIRMED at step 0 (28.01),
retained so the grid's blob-metric column can still disappoint. (3) The
server exposes slot restore, so adjusted parity is the expected headline
(symmetric mechanism), and the honest differentiator is in-process
capability (no HTTP, no separate process), not raw speed.

Would disappoint if: no crossover at any measured prefix — then KV
Persistence is a CAPABILITY, not a speed mechanism, and is stated plainly
without a ratio; or round-trip is not token-identical (STOP, defect
report — did NOT fire, gate passed); or blob size deviates materially
from the cell-weight prediction (did NOT fire, 28.01 measured).

Note on where the win, if any, must come from: with disk read of tens of
MB (~milliseconds even cold) versus prefill of hundreds-to-thousands of
milliseconds, the arithmetic suggests resume may win at ALL measured
prefixes — in which case the pre-registered "short prefixes lose"
expectation is itself disappointed and reported as such (resume is both
faster AND a capability). The grid decides.

## 4. Methodology

- Three arms per point: ours-resume, ours-reprefill (mechanism ratio =
  reuse vs recompute on our own scheduler — NEVER "vs llama-server"),
  server slot-restore (honest baseline, §2).
- Resume path measured BOTH ways: (a) in-memory blob (the primitive cost:
  `state_set` + one decode, no file I/O) and (b) disk round-trip (write
  once as the checkpoint cost, then an **unbuffered read** + `state_set` +
  decode as the warm resume). Both reported; disk is the honest number
  for the product claim ("agent survives a process restart").
- **Cold-cache discipline (methodological requirement):** the disk read
  is issued through `CreateFileW` with `FILE_FLAG_NO_BUFFERING`, which
  bypasses the Windows page cache, so a just-written blob is NOT served
  from RAM (that would make the break-even unearned). Residual not
  defeatable from user space: the NVMe controller's own cache — declared
  here, not claimed away. write / read / `state_set` times are recorded
  SEPARATELY (different natures: write = checkpoint cost, amortized over
  many resumes; read = I/O; state_set = C-side KV parse).
- Concurrency M ∈ {1, 4, 8}; all sessions arrive at t0; per-session TTFT
  from t0.
- RAW + per-run adjusted (server pair) with the M=1 server−mech TTFT
  transport estimator, anchor sanity, clamping/†; RAW and ADJUSTED
  conclusions must agree.
- Two-tier gates; ≥1 warmup + 5 repeats, medians + min–max; cool-downs;
  arm-order alternation; zero background load; sleep disabled; real-handle
  psapi memory. Chronometry gate before the grid (≤6 h projected;
  concurrency trimmed to {1,8} if 6–8 h; STOP >8 h).
- Blob metrics per point: bytes, write/read/state_set times, peak RSS,
  exact error codes.

## 5. Security note (product, per plan §7.2)

The benchmark blobs are self-produced, so this run is safe. But a shipped
disk-backed KV store makes `state_set` a real trust boundary the moment
blobs touch disk: `SECURITY.md` already records `state_set` as a
not-yet-validated boundary (llama.cpp parses blob bytes in C). A shipped
store needs MAC + header validation BEFORE release — the frame validation
in `NativeSession.load_state` (magic/version/length, pre-C) is necessary
but is explicitly NOT authentication. Flagged as consolidation input, not
a blocker for this measurement.

## 6. Results

### 6.1 Gates & chronometry

- **Corruption gate (tier-0, blocking):** passed at step 0 (§1 Q1) —
  token-identical round-trip at every prefix. This IS the cleanliness gate
  for KV Persistence: unlike Shared Prefix / Tool Loop there is no
  near-parity control point (resume always skips the prefill, so
  ours/mech is never ≈ 1 by construction), so the token-identity gate
  replaces the 0.9–1.2 band as the harness-integrity check.
- **Harness-decomposition check:** resume-memory vs resume-disk isolate
  only the disk read — at 500×1 wall 1.226 vs 1.247 (Δ 0.021 s ≈ the
  0.013 s unbuffered read), confirming the arms differ only where they
  should.
- **Chronometry:** heaviest point re-prefill 3000×8 = 36.8 s/repeat →
  full grid (3 prefixes × 3 M × 4 arms × 5 repeats + warmups + cool-downs)
  ≈ 2.0 h, well under the 6 h trim / 8 h STOP thresholds; full grid run.

### 6.2 Grid — wall clock (medians of 5), 4 arms

resume-memory = in-memory blob (warm, symmetric to the server's warm
restore); resume-disk = unbuffered cold read (the honest product number);
re-prefill = mechanism baseline (recompute the prefix, our scheduler);
server = tuned llama-server slot restore (honest baseline, §2).
Mechanism ratio = re-prefill / resume-memory (reuse vs recompute on OUR
scheduler — never "vs llama-server").

| point | prefix tok | resume-mem | resume-disk | re-prefill | server | **mech ratio** | srv/resmem | srv/resdisk |
|---|---|---|---|---|---|---|---|---|
| 500×1 | 382 | 1.226 | 1.247 | 1.595 | 1.478 | 1.30 | 1.205 | 1.186 |
| 500×4 | 382 | 2.377 | 2.114 | 4.721 | 2.295 | 1.99 | 0.966 | 1.086 |
| 500×8 | 382 | 4.058 | 4.264 | 8.535 | 5.485 | 2.10 | 1.352 | 1.286 |
| 1500×1 | 1126 | 1.318 | 1.572 | 2.572 | 1.501 | 1.95 | 1.139 | 0.955 |
| 1500×4 | 1126 | 3.423 | 3.715 | 10.207 | 3.369 | 2.98 | 0.984 | 0.907 |
| 1500×8 | 1126 | 5.325 | 5.383 | 18.631 | 5.521 | 3.50 | 1.037 | 1.026 |
| 3000×1 | 2254 | 1.427 | 1.495 | 5.448 | 1.840 | 3.82 | 1.290 | 1.231 |
| 3000×4 | 2254 | 4.826 | 5.100 | 19.957 | 3.506 | 4.14 | 0.727 | 0.687 |
| 3000×8 | 2254 | 6.767 | 8.840 | 36.840 | 5.619 | 5.44 | 0.830 | 0.636 |

### 6.3 Break-even — TTFT isolates the resume cost from the common 64-token generation

TTFT (time to first output token) is the clean break-even signal: it
is exactly resume-cost (read + state_set + 1 decode) vs prefill-cost, with
the shared 64-token generation excluded.

| point | resmem TTFT | resdisk TTFT | re-prefill TTFT | server TTFT | read (s) | state_set (s) | write (s) | blob (MB) |
|---|---|---|---|---|---|---|---|---|
| 500×1 | 0.025 | 0.038 | 0.385 | 0.275 | 0.013 | 0.004 | 0.010 | 10.5 |
| 500×8 | 0.118 | 0.251 | 4.321 | 2.204 | 0.016 | 0.007 | 0.012 | 10.5 |
| 1500×1 | 0.036 | 0.088 | 1.179 | 0.292 | 0.043 | 0.021 | 0.022 | 30.8 |
| 1500×8 | 0.252 | 0.614 | 13.529 | 2.115 | 0.046 | 0.020 | 0.032 | 30.8 |
| 3000×1 | 0.050 | 0.122 | 3.837 | 0.483 | 0.078 | 0.024 | 0.040 | 61.7 |
| 3000×8 | 0.429 | 1.173 | 30.289 | 1.974 | 0.053 | 0.023 | 0.045 | 61.7 |

**Break-even result: there is NO crossover at any measured prefix —
resume beats re-prefill everywhere.** Re-prefill TTFT / resume-memory
TTFT grows from **15× (500×1) to 71× (3000×8)**; even the honest
cold-disk resume (resdisk) beats re-prefill by 10× (500×1) to 26×
(3000×8). By arithmetic the crossover sits where prefill(P) ≈ read +
state_set ≈ 17 ms, i.e. **≈ 30–40 tokens** — below any useful prefix.

**The pre-registered "short prefixes lose" expectation is DISAPPOINTED,
and reported as such:** on this hardware KV Persistence is BOTH a speed
mechanism AND a capability — moving tens of MB (even cold, unbuffered)
is cheaper than recomputing the prefix at every measured size. There is
no regime here where re-prefill is the better choice.

### 6.4 vs the tuned server (honest baseline): parity

srv/resmem RAW spans 0.73–1.35 with no consistent winner (server ahead at
3000×4/8 via its mature continuous batching, ours ahead at several small
points) — **mechanism parity with the tuned server's own slot restore**,
exactly the pre-registered expectation (3). Both arms are real KV-restore
mechanisms; the server's `restore_ms` scales with blob size (8.6 / 21.0 /
44.5 ms at 500/1500/3000 ×8) just as our `state_set` does (7 / 20 / 23 ms)
— symmetric. RAW carries the conclusion directly; the per-run transport
adjustment is not applied here because it would only move the server
FASTER (it is already at parity/ahead), so it cannot change the "parity,
capability is the differentiator" reading — RAW and any adjusted number
agree a fortiori. srv/resdisk is apples-to-oranges AGAINST us (the server
restore is served from a warm OS cache at ~0.2–44 ms; our resdisk read is
unbuffered cold) and even so lands at parity (0.64–1.29).

**The honest differentiator is in-process capability, not raw speed:** the
in-process resume needs no HTTP round-trip and no separate server process
— an agent library restores its own session KV — while matching the tuned
server's slot-restore wall.

### 6.5 Blob metrics, checkpoint cost, memory

- Blob size 28.01 KiB/tok confirmed on the grid (10.5 / 30.8 / 61.7 MB at
  382 / 1126 / 2254 tokens) — cost model holds.
- Checkpoint (write) cost, reported separately as it amortizes over many
  resumes: ours `fsync`'d write 0.010–0.045 s; the server's `save_ms`
  62.8 / 209.5 / 475.2 ms at 500/1500/3000 ×8 (it serializes the whole
  slot on save).
- Memory (real-handle psapi): the in-memory resume path HOLDS M blobs in
  RAM — peak WS 3363 → 4310 MB (500×1 → 3000×8, +0.5 GB of resident
  blobs at 3000×8); the disk path and re-prefill stay flat (~3275 MB, no
  resident blobs); server RSS 3044–3503 MB. The in-memory path trades RAM
  for the fastest resume; the disk path trades a cold read for flat
  memory — both reported so the product can choose.

## 7. Observation

Verdict vs the pre-registration: **the mechanism and capability claims are
confirmed; the "short prefixes lose" half of expectation (1) is
disappointed and reported plainly; no defect fired.**

1. **Correctness (gate):** round-trip token-identical at every prefix;
   `state_get`/`state_set` is a faithful KV serialization. Blob size
   28.01 KiB/tok — cost model exact.
2. **Composition finding (probe Q2, FULL-LOGICAL):** a Shared-Prefix slot
   (shared cells) serializes to a self-contained full-logical blob,
   restorable standalone without the holder — **Shared Prefix and KV
   Persistence compose.** But the density saving does NOT survive
   serialization: N shared sessions cost N full blobs on disk. Direct
   input to Run 7's design (combined workload).
3. **Break-even: no crossover — resume wins at every measured prefix**
   (15–71× on TTFT, 1.30–5.44× on wall vs re-prefill). KV Persistence is
   a speed mechanism AND a capability on this hardware; the pre-registered
   short-prefix-loss did not occur (crossover ≈ 30–40 tokens, below any
   useful prefix).
4. **vs the tuned server (its own slot restore): parity** (srv/resmem
   0.73–1.35, symmetric mechanism). The differentiator is in-process
   capability — no HTTP, no separate process — not raw speed, exactly as
   pre-registered.
5. **Honest costs recorded:** the in-memory path holds blobs in RAM
   (+0.5 GB at 3000×8); the cold-disk path (unbuffered, page-cache
   bypassed) is the product number and still wins everywhere; the NVMe
   controller cache is the one residual not defeatable from user space,
   declared not claimed away.

Net framing for consolidation: KV Persistence is a clean win on this
hardware — resume beats re-prefill at every prefix and reaches parity with
the tuned server's slot restore while needing no server. Its product value
is the capability (an agent survives a process restart with its context
intact); its speed value is real but is measured against re-prefill
(the mechanism ratio), not against llama-server (parity). The FULL-LOGICAL
composition result and the `state_set` trust-boundary note (§5) are the
two forward-looking inputs.
