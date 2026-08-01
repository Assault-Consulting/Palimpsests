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

(rung table with attributed deltas, sub-additivity verdict, pool pressure,
memory — to be filled after the grid)

## Observation

(to be filled)
