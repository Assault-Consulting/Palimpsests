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

(gates, chronometry, grid, break-even — to be filled after the sweep)

## 7. Observation

(to be filled)
