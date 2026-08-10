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

Raw per-run data (CSV/JSON) and the measurement scripts are under
`results/audit-overhead-raw/`.

### 1. tokens/s end-to-end, audit on/off

7 kept runs per arm (1 warm-up discarded), arms alternated on/off/on/off. The
generation work is identical across every run and arm: **all 16 runs produced
exactly 1225 tokens** (greedy determinism confirmed), so the only difference
between arms is the presence of audit emission.

| Arm | median tok/s | IQR (Q1–Q3) | min–max | stdev | median wall |
|---|---|---|---|---|---|
| audit **on** | 32.37 | 32.31 – 32.44 | 31.53 – 32.54 | 0.31 | 37.85 s |
| audit **off** | 32.54 | 32.37 – 32.64 | 31.83 – 32.68 | 0.27 | 37.64 s |

**Median overhead: 0.55 %** (off nominally faster). The two distributions
**overlap** — both min–max ranges overlap and each arm's median sits inside the
other arm's min–max span. The per-arm run-to-run stdev (~0.3 tok/s, ~0.9 %) is
**larger than the 0.55 % median gap**. There is therefore **no measurable
throughput cost**: the audit writer's effect is indistinguishable from noise.
Stated as a bound rather than a point estimate: **overhead ≤ ~1.5 % (the noise
band); best estimate ≈ 0 %.** Peak working set was ~1815 MB in both arms (the
model dominates; the writer's footprint is not distinguishable at this
resolution — the iGPU is UMA, so this RSS also covers the "VRAM").

This matches the pre-registration (`< ~1 %`) and is explained quantitatively by
Points 2–3: audit records are lifecycle-level, and the session emits ~47 of them
across ~38 s (~1.2 records/s) against a writer ceiling ~10⁵× higher.

### 2. bytes/record by kind (+ weighted mix)

Deterministic, measured from the public encoder (file-growth per record; the
emit methods return a hash handle, not the record, so size is `Δ` file size).

| Kind | measured B | pre-registered B | Δ |
|---|---|---|---|
| GENESIS | 156 | 156 | 0 |
| BOOT | 156 | 156 | 0 |
| SPAN_START (`session_start`) | 173 | 173 | 0 |
| SPAN_END (`session_end`) | 156 | 156 | 0 |
| EVENT+origin (`model_load`) | 251 | 255 | −4 |
| KV_SAVE | 210 | 200 | +10 |
| KV_RESTORE | 210 | 200 | +10 |
| SAFETY (guard) | 186 | 166 | +20 |
| ANCHOR | 192 | 196 | −4 |
| PREFIX_WARM | 183 | — | — |
| PREFIX_COPY | 183 | — | — |
| MODEL_UNLOAD | 179 | — | — |

Pre-registration was **exact** on the header-only kinds (the 156-B fixed header
and the role-TLV arithmetic held). The body-carrying kinds were **slightly
under-estimated** — the guard and KV bodies carry more than the bare
`EVT_KIND` + digest I assumed (a length-prefixed detail / origin fields). That is
the intended value of pre-registering: the miss is on bodies, not headers.

**Weighted mix — the number for retention math (Track D WS5).** From the actual
kind-counts of a real Point-1 session (47 records: `SPAN_START`×10, `PREFIX_COPY`×10,
`KV_SAVE`×8, `SPAN_END`×10, `ANCHOR`×2, and one each of GENESIS/BOOT/`model_load`/
`PREFIX_WARM`/`KV_RESTORE`/guard/`MODEL_UNLOAD`):

- **weighted ≈ 181 bytes/record**
- **≈ 8.5 KB per full agentic session** (8 sub-sessions + restore + guard + anchor)
- cross-check against the real session file on disk: 8583 B / 47 = **182.6 B/record**
  (the isolated-per-kind weighting agrees to ~1 %).

A single averaged bytes/record is **181 B**, but retention guidance should use the
per-kind table above against a deployment's own kind mix — e.g. a chain that emits
`MERKLE` aggregation or large `EVT_DETAIL` strings will skew heavier.

### 3. records/s writer isolated

Writer hammered with the representative mix, no model, 6 kept runs (1 warm-up
discarded), 20 000 records/run.

| metric | median | stdev | min – max |
|---|---|---|---|
| records/s | **116 666** | 5 297 | 106 086 – 120 093 |
| throughput | **21.1 MB/s** | — | — |

The writer's ceiling is **~116 k records/s**. Under inference the chain emits
lifecycle events at **~1.2 records/s** (47 records / ~38 s, Point 1) — the writer
runs at ~**10⁻⁵ of its ceiling** during serving. This is the mechanism behind the
~0 % overhead in Point 1: the audit subsystem is almost entirely idle; emission is
never on the generation hot path.

### 4. open_existing scaling (+ torn tail)

Synthetic logs (fixed representative mix, deterministic content), 5 kept warm runs
per size (1 warm-up discarded) + one cold-approx.

| Log size | actual bytes | records ≈ | warm median | warm stdev | cold-approx | walk MB/s |
|---|---|---|---|---|---|---|
| 0.01 GB | 10.7 MB | 59 k | 0.035 s | 0.0008 | 0.034 s | 306 |
| 0.1 GB | 107 MB | 593 k | 0.366 s | 0.0029 | 0.376 s | 294 |
| 0.5 GB | 537 MB | 2.97 M | 1.946 s | 0.042 | 1.847 s | 276 |
| 1 GB | 1074 MB | 5.93 M | 3.982 s | 0.035 | 3.862 s | 270 |

**Linear fit** (warm median vs bytes): slope **3.99 s/GB**, intercept ≈ 0
(−0.026 s), residuals within **±0.02 s** — the walk is cleanly **O(file)**, as
expected for a tail-adopting scan; no super-linear surprise. Resume of a **1 GB**
chain (≈ 5.9 M records) costs **~4 s**.

**Cold vs warm.** cold-approx ≈ warm at every size (e.g. 1 GB: 3.86 vs 3.98 s).
True cold (cross-boot, file not in the OS cache) needs an admin cache flush, which
was **not available**; the 4 GiB dummy-read pressure did not reliably evict a
GB-scale file, so **cold-approx should be read as ≈ warm, not as a guaranteed cold
number** (labelled honestly). The walk is CPU/bandwidth-bound at ~270–306 MB/s;
a genuinely cold read would be bounded below by NVMe read bandwidth, which on this
class of disk is of the same order, so the ~4 s/GB figure is a reasonable estimate
for the cross-boot case pending a true-cold rerun.

**Torn tail.** A valid log with an incomplete trailing record appended
(`b"PALA"` + 5 stray bytes, 9 B):
`open_existing(recover_torn_tail=True)` reports `recovered_tail_bytes = 9`
(exactly the torn bytes), truncates them, and — after the required `BOOT` — the
caller's `recovery_truncated_tail()` writes a `RECOVERY_TRUNCATED_TAIL` record
(EVENT, `EVT_KIND = 7`), confirmed present right after `BOOT` by an independent
record walk. Matches the spec/CHANGELOG.

**Mid-stream damage.** A byte flipped in the **magic** of a mid-stream record
(record 301 of 603, 301 valid records after it) is **refused**, not auto-repaired:

```
ValueError: damage at offset 54097 is followed by further record magic —
mid-stream damage, not a torn tail; refusing to truncate (investigate with the verifier)
```

Note the scope: `open_existing` does a **structural** resume — it walks to the
last complete record and refuses when a break has valid framing after it. It is
**not** a cryptographic integrity check: a bit flipped inside a record *body*
(the body is not covered by `record_hash`, which is `SHA-256(header)`) or a pure
link mismatch with framing intact is not `open_existing`'s job — that is what the
separate `pala verify` path is for. Resume and verification are deliberately
distinct.

## Reproduce

All scripts under `results/audit-overhead-raw/`, run with the pinned
`.venv-vulkan` interpreter (llama-cpp-python 0.3.33, Vulkan) from the repo root:

```
# Point 1 — tokens/s on/off (16 alternated isolated runs)
python results/audit-overhead-raw/point1_driver.py
# Point 2 — bytes/record by kind + weighted mix
python results/audit-overhead-raw/measure_bytes_by_kind.py
# Point 3 — writer throughput ceiling
python results/audit-overhead-raw/measure_writer_throughput.py
# Point 4 — open_existing scaling + torn-tail / mid-stream behaviour
python results/audit-overhead-raw/measure_open_existing.py
python results/audit-overhead-raw/check_recovery.py
```

Model: `models/qwen2.5-1.5b-instruct-q4_k_m.gguf` (sha256 pinned in Config).
Audit on/off is the `audit=` argument to `NativeEngine` — a real `PalaWriter`
vs `None`; the serving path is otherwise byte-identical.

## Observation

- **For deployers / the CHANGELOG claim.** Running the PALA-1 audit log during
  inference has **no measurable throughput cost** on this rig — the on/off
  distributions overlap and the median gap (0.55 %) is smaller than run-to-run
  noise (~0.9 %). "Not worse than v0.7 within noise" holds; the honest bound is
  **≤ ~1.5 %**, best estimate **≈ 0 %**. The reason is structural, not incidental:
  emission is lifecycle-level (~1 record/s under load) against a writer that
  sustains ~116 k records/s, so the audit path is ~5 orders of magnitude from
  saturation.
- **For retention (Track D WS5).** A full agentic session costs **~8.5 KB**
  across ~47 records, **~181 B/record weighted**. Retention math should use the
  per-kind table, not a flat average — the header floor is 156 B and body kinds
  run 179–210 B, so the mix (how many `KV_*`, `EVENT`, `MERKLE`) sets the real
  cost.
- **For large logs (cross-boot resume).** `open_existing` is linear in file size
  at **~4 s/GB** (warm; cold-approx ≈ warm here — true cold not achievable without
  an admin cache flush, so treat as an estimate). A 1 GB / ~6 M-record chain
  resumes in ~4 s — fine for a boot-time path, but a deployment that lets a single
  chain grow to tens of GB will pay tens of seconds per resume, which is the
  argument for chain rotation / anchoring cadence rather than an unbounded log.
  Recovery is safe: a torn tail is truncated and recorded
  (`RECOVERY_TRUNCATED_TAIL`); mid-stream structural damage is refused and pushed
  to the verifier, never silently auto-healed.
- **Pre-registration scorecard.** Overhead `< ~1 %` → **confirmed** (≈ 0 %,
  ≤ ~1.5 % bound). bytes/record header-only kinds → **exact**; body kinds →
  **under-estimated by 4–20 B**. `open_existing` linear → **confirmed**; torn-tail
  truncate+record and mid-stream refuse → **confirmed**.
