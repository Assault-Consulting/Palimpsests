# Bench report — Composite (Shared Prefix + Tool Loop + KV Persistence) — 1.5B — iGPU/Vulkan

- Run ID:            composite-1p5b
- Date / operator:   2026-08-02 / Oleksandr
- Config-hash:       50fc841146dfbf6f (NEW — the measured code changed: this
  is the first run on the post-#81 pin, with kv_unified shipped first-class
  and the PrefixHolderInUseError guard enforced; pin chain 7745853 → 3419ddb)

## Capability name map (internal → public)

| public name | internal | mechanism |
|---|---|---|
| **Shared Prefix** (SP) | N4 | decode a shared system prompt once, `seq_cp` into each session |
| **Tool Loop** (TL) | N5 | live-KV hops; feed only the tool result, no conversation re-prefill |
| **KV Persistence** (KP) | N6 | resume a session from persisted KV instead of re-prefilling its history |

Public names throughout; N-numbers only here.

**Narrative rule (enforced):** the rung deltas are *mechanism* value — the
worth of adding each feature to the stack on our own scheduler. They are
NEVER "vs llama-server". The only external number is rung 0 (the tuned
server), and the composite headline is the FULL-STACK number, never a
cherry-picked isolated best.

## Config (pinned)

```
palimpsests: 3419ddb (0.5.1.dev0; kv_unified first-class + PrefixHolderInUseError guard + isolation suite, merge #81)
llama-cpp-python: 0.3.33 (source build, CMAKE_ARGS=-DGGML_VULKAN=on; vendors llama.cpp 78d2f524)
llama-server: build 9874, commit 78d2f524 (MSVC 19.44.35228.0, -DGGML_VULKAN=ON)
model 1.5B: qwen2.5-1.5b-instruct-q4_k_m.gguf Q4_K_M sha256=6a1a2eb6...9407e
vulkan driver: 101.8331 (Vulkan API 1.4.328), device Intel(R) Arc(TM) Graphics
kv_unified: True (FIRST-CLASS NATIVE PARAM, not the wrapper) — verified on construction
prefix-holder guard: ACTIVE (PrefixHolderInUseError) — must never raise in the composite
n_ctx: 32768  n_batch: n_ctx  ngl: 999 (full offload 29/29)
sampling: greedy (temp 0)
```

kv_unified is now constructed directly (`LlamaCppBackend(..., kv_unified=True)`),
not via the Run 3-6 monkeypatch wrapper — the flag shipped first-class in #81.

Harness (new, declared): `benchmarks/bench_composite.py` (gate + native rungs
1-4), `benchmarks/bench_composite_server.py` (rung 0, tuned server). Workload
content from `benchmarks/_workload.py`. Raw logs `results/composite-sweep/`
(untracked, per campaign precedent).

## What this run measures (§5)

Every prior run isolated ONE mechanism. This asks whether the three COMPOSE
under a realistic agentic workload — do they ADD or OVERLAP. The hypothesis
is already sharpened by Run 5 probe Q2 (a persisted blob is FULL-LOGICAL: it
re-persists the shared prefix). So SP saves the COLD sessions' prefix decode
and KP saves the RESUMED sessions' history decode — different session subsets,
so we expect SUB-ADDITIVE composition (the rung-3 KP delta << KP's isolated
ratio).

**Rungs (incremental-cumulative; each delta vs the PREVIOUS rung):**

| rung | stack | delta measured against |
|---|---|---|
| 0 | tuned llama-server (P-tuned) | external anchor |
| 1 | ours, no mechanisms (stateless re-prefill) | rung 0 |
| 2 | + Shared Prefix | rung 1 |
| 3 | + KV Persistence | rung 2 ← **sub-additivity heart** |
| 4 | + Tool Loop | rung 3 |

**Workload:** M parallel sessions sharing a system prompt (~1500 tok), each
running HOPS=4 tool hops (GEN=24 tokens/hop). A resume-fraction of sessions
start resumed from persisted KV (PRIOR_HOPS=2 already done). M ∈ {4, 8, 12}
(M<P, M≈P, M>P); resume-fraction ∈ {0, 0.5} (0 isolates SP+TL; 0.5 is the
composite). 1.5B.

## Step 0 — Corruption gate (BLOCKING; narrowed, run before any number)

The isolation suite (merged #81) already PROVED bystander-safety (argmax
invariant 21/21 under the holder-release defrag), so this gate does NOT
re-check "release touches bystanders" — that is closed. It checks ONLY
self-session composition integrity: a session reaching the SAME final
conversation with the full mechanism stack must produce first-token logits
BIT-IDENTICAL to the same content prefilled statelessly (its own cells →
L2 = 0 expected). Method: one token stream tokenized ONCE, sliced at
arbitrary indices to drive the SP-copy and KP-restore paths, so any
difference is state-control corruption, not a tokenisation artifact. Both
session types are checked because SP and KP are ALTERNATIVES per session:

| check | path | L2 | token-identical |
|---|---|---|---|
| cold session | Shared Prefix copy + Tool Loop live feed | **0.0** | **yes** |
| resumed session | KV Persistence load + Tool Loop live feed | **0.0** | **yes** |
| guard raises during composite | correct-order teardown | — | **0** |

**GATE PASS** (prefix 500 validation point; re-confirmed at the grid prefix).
The three mechanisms compose without corruption; the guard never raises on a
correct-order teardown. The run proceeds to the rungs.

## Pre-registration (written BEFORE the rung numbers)

Expectation: **sub-additive** — the rung-3 marginal delta (adding KV
Persistence) is much smaller than KV Persistence's isolated ratio (Run 5),
because the prefill it saves for the resumed sessions is already partly saved
by Shared Prefix for the cold sessions, and the resumed sessions' full-logical
blobs re-persist the shared prefix (probe Q2) — the two prefill-saving
mechanisms cover DIFFERENT session subsets, so their savings do not multiply.
Tool Loop's rung-4 delta should be the LARGEST (it removes the per-hop
conversation re-prefill, which dominates a multi-hop session). Pool pressure
is expected at M>P with resume 0.5 (resumed sessions hold full-logical blobs —
their own cells, not shared — so concurrent residency grows; eviction/
admission-failure or slot exhaustion is a finding about the default context
budget, not a bug to hide).

Would disappoint if: the corruption gate fails (STOP — defect, not a
benchmark; did NOT fire); or deltas MULTIPLY cleanly (surprising — needs
explanation before believed); or the composite is WORSE than rung 2 alone
(the mechanisms actively fight and should not ship together by default).

## Methodology

- Native rungs (1-4): sequential per-session execution — each session
  establishes its base (SP copy / KP load / cold prefill) and runs its hops,
  then frees its slot. This measures the rung's TOTAL decode work (the clean
  sub-additivity signal); continuous batching would compress every rung
  uniformly, so the rung-to-rung deltas are preserved. The absolute wall vs
  rung 0's continuous batching is a caveat, not the headline (the headline is
  the rung-delta attribution and the full-stack composite).
- Pool-pressure probe (separate from the timed wall): all M sessions' base
  states admitted and HELD concurrently — resumed sessions load full-logical
  blobs (own cells), cold sessions copy the shared prefix — recording peak KV
  cells resident, admission failures (cell budget), and slot exhaustion
  (M > n_seq_max).
- rung 0: tuned llama-server, --parallel P (P-tuned), cache_prompt for the
  shared prefix + slot-KV tool loop, slot restore for the resumed fraction.
- Detector standard: L2-over-first-token (the campaign standard since the
  isolation suite); gate epsilon 1e-6 (own cells, churn floor 0).
- ≥1 warmup + 5 repeats, median + min–max; sleep disabled; warm request;
  cool-downs; zero background load. Guard raises must be 0 at every point.
- Chronometry estimate before the grid (≤6 h / STOP 8 h).

## Results

### 1. Corruption gate — PASS at the grid prefix (blocking)

Re-confirmed at prefix 1500 (and at the 500 validation point): cold
session (SP copy + TL live feed) L2 = **0.0**; resumed session (KP load +
TL live feed) L2 = **0.0**; guard raises = **0**. The composite is
state-control correct; the run proceeds.

### 2. Rung table — wall (medians of 5), prefix 1500

Deltas are the **mechanism** value (worth of adding each feature to the
stack, our own scheduler) — NEVER "vs llama-server". rung 0 is the tuned
server; d(i→j) is rung i wall − rung j wall.

| M | resume | rung0 srv | rung1 none | rung2 +SP | rung3 +KP | rung4 +TL | Δ SP (1→2) | Δ KP (2→3) | Δ TL (3→4) |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 0.0 | 6.25 | 33.81 | 29.16 | 29.00 | 10.03 | 4.65 | **0.17** | 18.96 |
| 4 | 0.5 | 5.57 | 26.69 | 24.28 | 21.66 | 7.44 | 2.41 | **2.62** | 14.22 |
| 8 | 0.0 | 10.62 | 66.93 | 57.84 | 57.74 | 19.92 | 9.09 | **0.10** | 37.82 |
| 8 | 0.5 | 8.97 | 53.49 | 48.96 | 43.83 | 15.40 | 4.53 | **5.13** | 28.43 |
| 12 | 0.0 | 25.04 | 100.91 | 87.11 | 87.18 | 29.96 | 13.80 | **−0.07** | 57.22 |
| 12 | 0.5 | 16.12 | 80.21 | 73.36 | 65.64 | 22.82 | 6.84 | **7.72** | 42.82 |

### 3. Sub-additivity verdict (rung-3 delta) — CONFIRMED

**KV Persistence's rung-3 marginal delta is ~0 at resume 0 and small
(~10% of rung 2) at resume 0.5** — it helps ONLY the resumed subset:

- resume 0 (nothing to resume): Δ KP = 0.17 / 0.10 / −0.07 s at M
  4/8/12 — statistically zero. KV Persistence contributes nothing when no
  session resumes, by construction.
- resume 0.5 (half resumed): Δ KP = 2.62 / 5.13 / 7.72 s — grows with the
  resumed count, but is only ~10.5–11 % of the rung-2 wall it acts on
  (2.62/24.28, 7.72/73.36).

This is exactly the pre-registered sub-additive shape. Shared Prefix and
KV Persistence **partition by session type** — SP saves the COLD sessions'
prefix decode (Δ SP is largest at resume 0, where all sessions are cold:
4.65/9.09/13.80; smaller at resume 0.5 where half are resumed:
2.41/4.53/6.84), KP saves the RESUMED sessions' history decode. They ADD
(each on its own subset) but neither covers the other's subset, so they do
NOT multiply: a persisted blob is full-logical (re-persists the shared
prefix, Run 5 probe Q2), so a resumed session gets no benefit from the
holder and a cold session gets no benefit from persistence. **The two
prefill-saving mechanisms save different resources for different sessions —
sub-additive, as pre-registered.**

Tool Loop's rung-4 delta DOMINATES (14.2–57.2 s) — it removes the per-hop
conversation re-prefill that the stateless rungs pay on every hop, which is
the bulk of a 4-hop session. Pre-registered "largest delta = Tool Loop"
holds.

### 4. Composite headline — the FULL STACK, not a cherry-picked isolated best

The headline is rung 4 (full stack), reported against rung 1 (mechanism
value) and rung 0 (external anchor):

- **Full-stack mechanism value (rung 1 → rung 4): 3.37–3.59×** across all
  M and resume fractions — the composite is ~3.5× faster than running the
  same agentic workload with no mechanisms. This is the number a
  full-stack deployment gets, not the "Shared Prefix alone 4.4×" the
  campaign refused to cherry-pick (at these hop counts SP alone is only
  1.1–1.5× — most of the win is Tool Loop, and it only appears with the
  full stack).
- vs the tuned server (rung 0): rung0/rung4 = 0.53–0.84× — the server is
  1.2–1.9× faster than our full-stack composite. **Caveat (methods):** the
  native rungs execute sessions SEQUENTIALLY (clean rung-delta attribution)
  while the server does continuous batching; the absolute vs-server gap
  mixes execution model with mechanism and is NOT the headline. The clean
  competitive picture per mechanism is in the isolated runs (Runs 1–6); the
  composite's job is the DELTA attribution and the full-stack value, both
  above.

### 5. Pool pressure — did NOT materialize at these sizes (honest)

The pre-registered pool pressure at M > P with resume 0.5 did NOT appear.
Concurrent-residency probe (all M sessions' base states held at once):

| M | resume | held concurrent | peak KV cells | admission fails | slot exhaustion | guard raises |
|---|---|---|---|---|---|---|
| 12 | 0.5 | 12 | 13,578 | 0 | 0 | 0 |
| 12 | 0.0 | 12 | 13,284 | 0 | 0 | 0 |
| 8 | 0.5 | 8 | 9,052 | 0 | 0 | 0 |
| 4 | 0.5 | 4 | 4,526 | 0 | 0 | 0 |

At M=12 / resume 0.5 the resumed sessions' full-logical blobs (6 × ~1.2k
cells) plus the shared-prefix cold sessions total **13,578 of 32,768 pool
cells — 41 % used, no pressure**. With n_seq_max=13 all 12 sessions reside
concurrently (no slot exhaustion). The default 32,768-cell budget is
generous for this workload at 1.5B; pool pressure would need a larger M, a
longer prefix, or a smaller budget. Reported as measured — the expectation
did not fire.

### 6. Guard & memory

- **guard_raises = 0 at every point** — the enforced PrefixHolderInUseError
  guard never fired under the composite; the scheduler's release ordering
  is correct under the concurrent workload.
- Memory (real-handle psapi): native peak WS 3731 MB at rung 4 M=12
  (model 1.04 GB + 32768-cell KV + runtime); server rung-0 RSS 4676 MB.
- No incidents; no re-runs; grid ran under the chronometry budget (~2 h,
  ended within the 6 h threshold).

## Observation

Verdict vs the pre-registration: **confirmed on every axis; no
disappointment clause fired.**

1. **Corruption gate PASS** — the three mechanisms compose without
   self-session corruption (cold SP+TL and resumed KP+TL both bit-identical
   to a stateless reference), and the guard never raises. Composition is
   correct, not just fast.
2. **Sub-additive, confirmed** — KV Persistence's rung-3 delta is ~0 with
   no resume and ~10 % with half resumed; Shared Prefix and KV Persistence
   partition by session type (cold vs resumed) and add without multiplying,
   exactly as the Run 5 full-logical-blob finding predicted. The mechanisms
   do NOT fight (the composite is far better than any earlier rung), so they
   ship together by default — but the honest expectation for a deployment is
   ADDITIVE-across-subsets, not multiplicative.
3. **Tool Loop dominates the composite** (Δ 14–57 s) — the per-hop
   conversation re-prefill is the largest cost in a multi-hop agent, and
   removing it is where most of the full-stack 3.5× comes from.
4. **Pool pressure did not materialize** at M≤12 / prefix 1500 on the
   32768-cell budget (41 % used at the top point) — the pre-registered
   worry is a non-event at this scale; a finding about the generous default
   budget, honestly reported rather than manufactured.
5. **Composite headline = 3.5× full-stack mechanism value** (rung 1 →
   rung 4), reported as the full stack, not a cherry-picked isolated best;
   the vs-server number is caveated as execution-model-mixed and is not the
   headline.

Net for consolidation: the level-3 mechanisms COMPOSE — correct (gate),
sub-additive (they cover different session subsets), and dominated by Tool
Loop for multi-hop agents. The composite is the honest deployment number
(3.5× vs no mechanisms); the campaign's per-mechanism competitive numbers
(Runs 1–6) remain the external comparison. This closes the 0.5 measurement
campaign.
