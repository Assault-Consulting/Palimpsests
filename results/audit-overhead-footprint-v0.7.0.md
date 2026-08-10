# Bench report — audit overhead & footprint — v0.7.0 — Arc iGPU

Benchmark of the **PALA-1 writer**, not the inference engine. The variable under
test is the *presence of audit emission* during a realistic serving session — not
the level of control (L1/L2/L3 comparisons are out of scope here). Rig continuity:
the same Arc iGPU as the 0.5 / 0.6 campaigns (`results/env-primitives-igpu.md`).

## Config (pinned)

| | |
|---|---|
| `palimpsests` | `v0.7.0` — SHA `7940dc3ae3fca5a24b7e941b280741d558119f6a` |
| Python | 3.12.10 |
| OS | Windows 11 (10.0.26200) |
| Inference runtime | **native in-process engine** via `llama-cpp-python` 0.3.33 (source build, `-DGGML_VULKAN=on`; bundled llama.cpp commit not exposed at runtime — pinned via the 0.3.33 sdist). *Not* `llama-server`; this campaign drives `palimpsests.providers.native.NativeEngine` directly. |
| GGUF | `qwen2.5-1.5b-instruct-q4_k_m.gguf`, Q4_K_M, sha256 `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` (same file as 0.5 / 0.6) |
| Vulkan driver | Intel 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics |
| Sampling | engine default (greedy); token counts recorded per run to confirm determinism |
| Context budget | engine default; `max_tokens = 48` per generation, `max_sessions = 4`, `share_prefixes = True` |
| Warm-up | first timed run per arm discarded (recorded as such); ≥ 5 timed runs kept per arm |

## Hardware profile

| | |
|---|---|
| CPU | Intel Core Ultra 9 185H (22 logical cores) |
| iGPU | Intel Arc Graphics (integrated in the 185H; Vulkan `uma:1`, `fp16:1`, warp 32, no matrix cores) |
| System RAM | 31.5 GiB (shared with the iGPU) |
| Vulkan driver / ICD | Intel 101.8331, Vulkan API 1.4.328 |

## Pre-registration (written BEFORE running)

Per `docs/BENCHMARKING.md` Rule 0 — a benchmark is only worth running if it is
allowed to disappoint us. Committed **before** any result (see git history: this
section lands in its own commit, ahead of the results commit).

**Expected overhead: `< ~1%` tokens/s.** Rationale: emissions are lifecycle-level
(`model_load`, span open/close, `kv_save`/`kv_restore`, guard, `anchor`), **not
per-token**; generation itself emits zero records. If measured noise ≥ effect,
that IS the result and is reported as such (overlapping distributions), not
dressed as a precise percentage.

**"audit off" is an honest no-op, not a crippled path.** The baseline disables
only the writer: `NativeEngine(audit=None)`. The engine's serving path is
byte-identical between arms — every audit hook in the engine is guarded
`if self._audit is not None:` — so `off` differs from `on` *only* by the absence
of emission (verified against the public engine API before running; noted in
Methodology). If `off` differed by anything other than missing emission, the
number would be worthless.

**Expected bytes/record per kind (estimate before measuring).** From the §2.1
fixed header (156 B) plus the TLV/body each kind is described to carry. These are
deliberately rough — the point is to see afterward where the intuition missed.

| Kind | Pre-registered estimate (B) | Reasoning |
|---|---|---|
| GENESIS | 156 | fixed header only, no body |
| BOOT | 156 | fixed header only |
| SPAN_START (`session_start`) | ~173 | header + origin role-TLV (`engine.native`, 13 B → ~17 B TLV) |
| SPAN_END (`session_end`) | ~156 | header only |
| EVENT+origin (`model_load`) | ~255 | header + role-TLV + model_digest(32) + config_digest(32) TLVs + EVT_KIND body |
| KV_SAVE / KV_RESTORE | ~200 | header + EVT_KIND + blob_digest(32) body |
| SAFETY (guard) | ~166 | header + EVT_KIND [+ short detail] body |
| ANCHOR | ~196 | header + anchor body (head digest ~32 B) |

**`open_existing` expected linear in file size** (an `O(file)` walk to adopt the
tail head+seq). A torn trailing record must be **TRUNCATED** and the recovery
itself recorded (`RECOVERY_TRUNCATED_TAIL`); **mid-stream** damage (a flipped bit
inside the file, not the tail) must be **REJECTED**, not auto-healed. Super-linear
scaling would be a finding.

## Methodology (fixed before running)

- **One variable.** Same machine, same GGUF, same prompts/seed/context, nothing
  else running; `time.sleep` disabled in harnesses; no background load.
- **Point 1 (tokens/s on/off).** One fixed workload function, run with
  `audit=PalaWriter(file)` (on) vs `audit=None` (off). Workload: `model_load`
  (origin triplet) → N=8 sessions, each `session_start` → shared-prefix
  warm/copy → 3 generations → `kv_save` → `session_end` → one warm `kv_restore`
  → one legitimate guard refusal (`guard_state_reject`, a corrupt KV blob fed to
  `load_state`) → final `anchor`. Arms **alternated** (on/off/on/off…), warm-up
  discarded, ≥ 5 timed runs each; cool-down between runs. Report median + IQR of
  both arms, overhead %, and an honest statement of whether the distributions
  overlap. Per-run token counts recorded to confirm both arms perform
  identical generation work.
- **Point 2 (bytes/record by kind).** Deterministic, no timing: emit one record
  of each kind through the public `PalaWriter` API and take `len()` of the
  returned encoded bytes. Weighted mix computed from the actual kind-counts of a
  real Point-1 session (`Track D WS5` input).
- **Point 3 (records/s writer isolated).** A loop emitting a representative kind
  mix to disk with no model; steady-state records/s and bytes/s, warm-up
  discarded, ≥ 5 runs, variance.
- **Point 4 (`open_existing` scaling).** Synthetic logs at 0.01 / 0.1 / 0.5 / 1 GB
  (fixed mix + seed); wall time of `PalaWriter.open_existing()` per size, ≥ 5 runs,
  median + variance, **cold** (file-cache evicted) and **warm** (repeated) split
  and labelled; slope checked for linearity. Torn-tail and mid-stream-damage
  behaviour checks alongside.
- **Honest reporting** (`docs/BENCHMARKING.md` §6): variance shown everywhere
  there is timing; nothing tuned after seeing a result; unfavourable outcomes
  reported as-is.

## Results

*Pending — filled in the results commit, after this pre-registration is committed.*

### 1. tokens/s end-to-end, audit on/off

### 2. bytes/record by kind (+ weighted mix)

### 3. records/s writer isolated

### 4. open_existing scaling (+ torn tail)

## Reproduce

*Pending.*

## Observation

*Pending.*
