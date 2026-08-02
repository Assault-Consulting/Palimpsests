# Campaign 0.5 — Consolidation

Aggregate of the 0.5 iGPU/Vulkan campaign: **six isolated-mechanism runs plus
the composite**. This document produces **no new data**; every number traces to
a merged run report in `results/`. The six isolated runs share config-hash
**dd2e395be22675f1** (pin 7745853, llama-cpp-python 0.3.33 Vulkan, pinned
llama-server b9874 @ 78d2f5246, Qwen2.5 Q4_K_M 1.5B / 7B, driver 101.8331); the
composite (#82) is on **50fc841146dfbf6f** — the post-#81 stack, where
`kv_unified` ships first-class and the prefix-holder release-ordering guard is
enforced. Where a run amended a convention, the amendment lives in that run's
report; this file cites the resulting number only.

## Capability name map (internal → public)

| public name | internal | mechanism |
|---|---|---|
| **Tool Loop** | N5 | live-KV agentic `generate → tool → continue`; feed only the tool result, no re-prefill |
| **Shared Prefix** | N4 | decode a shared system prompt once into a holder; `seq_cp` into each session's slot |
| **KV Persistence** | N6 | `save_state`/`load_state` — serialize a session's KV and restore it without re-prefill |

Public names throughout; N-numbers only in this block.

**Narrative rule (campaign-wide, enforced here):** a *mechanism ratio* is
always **vs stateless re-prefill on our own scheduler** — the value of
having the feature at all. It is **never** "vs llama-server". The only
competitive number vs the ecosystem is the **adjusted ratio vs the honest
tuned baseline** (llama-server with the feature's best-tuned equivalent).
The two are separate columns everywhere below.

## Source runs

| # | PR | public name | model | report |
|---|---|---|---|---|
| 1 | #68 | Tool Loop | 1.5B | `results/n5-tool-loop-1p5b-igpu.md` |
| 2 | #69 | Tool Loop | 7B | `results/n5-tool-loop-7b-igpu.md` |
| 3 | #71 | Shared Prefix | 1.5B | `results/n4-shared-prefix-1p5b-igpu.md` |
| 4 | #72 | Shared Prefix | 7B | `results/n4-shared-prefix-7b-igpu.md` |
| 5 | #76 | KV Persistence | 1.5B | `results/kv-persistence-1p5b-igpu.md` |
| 6 | #77 | KV Persistence | 7B | `results/kv-persistence-7b-igpu.md` |
| 7 | #82 | Composite (SP+TL+KP) | 1.5B | `results/composite-1p5b.md` |

All seven MERGED. The six isolated runs cut from pin 7745853 (`src/palimpsests`
verified byte-identical to the pin across the campaign); the composite cut from
3419ddb — the post-#81 stack (`kv_unified` first-class + enforced guard), a new
config-hash by design.

---

## 1. Headline table — competitive ratio (adjusted, vs tuned baseline) with mechanism ratio alongside

The **headline column is the adjusted ratio vs the honest tuned
llama-server baseline** (the number that must survive expert scrutiny).
The mechanism column (vs stateless re-prefill, our scheduler) is context —
it measures the feature's value at all, not an advantage over llama-server.

| feature | model | key point | **headline: adjusted vs tuned server** | mechanism ratio (vs stateless re-prefill) | source |
|---|---|---|---|---|---|
| Tool Loop | 1.5B | 3000×12 | **parity** (adjusted srv/ours 0.99–1.09 across grid) | up to 3.35× | #68 |
| Tool Loop | 7B | 3000×8/12 | **parity** (adjusted srv/ours 0.89–1.11 clamped) | up to 3.93× (5.40× at feasibility edge) | #69 |
| Shared Prefix | 1.5B | 3000×8, M=8 | **3.81× adjusted** (raw 3.91) within slot budget¹ | up to 4.08× (mech/ours) | #71 |
| Shared Prefix | 7B | 3000×8, M=8 | **4.40× adjusted** (raw 4.45) within slot budget¹ | up to 4.79× (mech/ours) | #72 |
| KV Persistence | 1.5B | {500..3000}×{1,8} | **parity** (srv/resume-mem 0.73–1.35) | 1.30–5.44× wall (15–71× TTFT) | #76 |
| KV Persistence | 7B | {1500,3000}×{1,8} | **parity** (srv/resume-mem 0.78–1.01) | 2.01–7.58× wall (49–154× TTFT) | #77 |

¹ **Shared Prefix is the one feature whose adjusted competitive number is
a large advantage, not parity** — because the tuned server does not
cross-slot-share an identical prefix (it re-prefills the prefix per slot
under concurrent arrival), so it behaves close to the mechanism arm. Two
mandatory caveats travel with the 3.81/4.40 number (both in the run
reports, restated in §2 and §6): (a) it is measured at **equal P=8** in
both arms; a workload-tuned server at P<M (P=4 at M=8) reaches ~2× instead
of ~3.8–4.4×, so the honest competitive claim at M≈P is **~2× vs a
P-tuned server, ~3.8–4.4× vs an equal-P server**; (b) the advantage
**saturates at M≈P and erodes beyond the slot budget** (M>P), where the
server's freed-slot prefix cache serves queued sessions suffix-only.

Difference between the two ratio columns, stated plainly: **mechanism
ratio = "is this feature worth having vs recomputing"; adjusted headline =
"do we beat/match what a tuned llama-server already gives".** Tool Loop and
KV Persistence match a tuned server (parity) while adding an in-process
capability; Shared Prefix additionally out-runs an equal-budget tuned
server within the slot budget, and delivers a density crossing (§3) no
slot-based server matches.

---

## 2. Shape finding per feature — where parity holds, where the win grows, and with what

### Tool Loop (#68, #69)
- **Control behaves:** near-parity at the 27-token/1-hop control (1.00× /
  0.99×) — the un-rigged-harness signal.
- **Adjusted vs the tuned server: parity across the entire grid on both
  models** (0.99–1.09 at 1.5B; 0.89–1.11 clamped at 7B). Both arms avoid
  re-prefilling the shared prefix; the server's `cache_prompt` + slot
  reuse is a symmetric mechanism. The residual RAW gap (up to ~1.22 at
  tiny prefixes) is the per-request HTTP/SSE transport (~0.13 s/req), not
  mechanics — it amortizes to nothing on 7B (RAW ≈ ADJ everywhere).
- **Mechanism ratio (vs stateless re-prefill) grows with prefix×hops and
  with model size:** 1.00 → 3.35× (1.5B), → 3.93× (7B); the model-size
  lift (prefill scales faster than decode) was pre-registered and held.
- **Net:** the Tool Loop speed claim vs a tuned server is "matches a tuned
  server without running a server, and avoids its transport"; its value
  vs *no* tool loop is up to ~4× (mechanism).

### Shared Prefix (#71, #72)
- **M=1 near-parity with a measured price:** mech/ours 0.95–0.98 at M=1 —
  the prefix-holder costs **5–8%** (holder warm + copy as separate decode
  calls vs one prefill). This is the honest cost of the design and stays
  in band.
- **Advantage grows with M (concurrent arrival) and prefix, peaking within
  the slot budget:** adjusted **3.81× (1.5B) / 4.40× (7B)** at 3000×8. The
  server pays the shared prefix per slot under concurrent arrival
  (verified: cache_n=0 on all slots); ours pays it once + 0.1–0.2 ms
  copies.
- **Saturation and erosion beyond the budget:** at M=12>P the adjusted
  ratio recedes (3.91→3.13 raw at 3000, 1.5B; 4.45→3.51 raw, 7B) — the
  server's freed-slot cache handles the beyond-budget case well. The
  contention win **does not grow past M≈P**; it is a within-budget win.
- **Model-size independent:** the same shape and the same density crossing
  (§3) on both models.

### KV Persistence (#76, #77)
- **Probe gates (both models): round-trip token-identical; FULL-LOGICAL
  composition** — a Shared-Prefix slot (shared cells) serializes to a
  self-contained full-logical blob, restorable standalone without the
  holder. Shared Prefix and KV Persistence **compose**, but the density
  saving does NOT survive serialization (N shared sessions = N full
  blobs).
- **No break-even crossover — resume beats re-prefill at every measured
  prefix, on both models.** Mechanism ratio (reprefill/resume-mem) 1.30 →
  5.44× wall (1.5B), 2.01 → 7.58× (7B); on the clean TTFT signal 15–71×
  (1.5B), 49–154× (7B). The arithmetic crossover sits at ≈30–40 tokens,
  below any useful prefix.
- **NEW cross-model finding: the ratio GROWS with model size** (5.44→7.58×
  wall; 71→154× TTFT) because the 2× heavier blob adds only tens of
  milliseconds to read+state_set while the heavier prefill it replaces
  adds tens of seconds. State-transfer cost is dominated by the prefill it
  avoids — KV Persistence gets *more* valuable as the model grows.
- **Adjusted vs the tuned server's own slot restore: parity** (0.73–1.35
  at 1.5B, 0.78–1.01 at 7B) — a symmetric mechanism (the server exposes a
  real disk-backed slot save/restore on this build). The differentiator is
  **in-process capability** (no HTTP, no separate process), not raw speed.

---

## 3. Feasibility crossings (the runs-vs-fails numbers)

| finding | measure | source |
|---|---|---|
| **Session density (Shared Prefix)** | **255 vs 31 live sessions on an equal 32768-cell KV budget = 8.2×**, on BOTH models | #71, #72 |
| Density ceilings are STRUCTURAL, not memory | ours: llama.cpp's **256-sequence cap** (with ≈0.63 GiB pool headroom on 7B); server: **per-slot context split** (HTTP 400 `exceed_context_size_error` at P=32, slot ctx 1024 < 1126-tok prefix) | #71, #72 |
| Ceilings are model-size independent | 255 vs 31 identical on 1.5B and 7B (pool arithmetic, not model arithmetic); only wall-at-ceiling scales (48.7 s → 157.8 s for ours' 255) | #72 |
| **KV cell weight** | **28.0 KiB/tok (1.5B) / 56.0 KiB/tok (7B)** — measured 28.01 / 55.7–56.01 (two methods), exactly 2.0× | #71, #72, #76, #77 |
| Deep-history context-budget tax (Tool Loop) | the n_ctx-doubling mitigation fits the Arc budget on 7B but costs **~14%** vs the tuned server at 3000×48; the crossing is configurational (`n_seq_max=2` default halves per-seq budget), not architectural | #69 |
| Tool Loop feasibility edge (vs stateless) | mechanism ratio up to **3.97× (1.5B) / 5.40× (7B)** at 3000×48 on the deep-history axis | #68, #69 |
| KV Persistence blob footprint | full-logical blob = 28.0/56.0 KiB/tok × context; persisting N shared sessions costs N full blobs (density does not survive serialization); 7B doubles the disk footprint | #76, #77 |

---

## 4. Keep / cut per feature (measured win vs complexity on this profile)

| feature | verdict | justification (from the numbers) |
|---|---|---|
| **Tool Loop** | **KEEP** | Matches a tuned server (adjusted parity, both models) with no server process and avoids ~0.13 s/req transport; worth up to ~4× vs no tool loop. The mechanism is low-complexity (feed-only-the-result) and already the campaign's most-validated path. Cost side is negligible. |
| **Shared Prefix** | **KEEP-WITH-CAVEAT** | The only feature with a competitive *speed* advantage (3.8–4.4× adjusted within the slot budget) AND a density crossing (8.2×). Caveats that must ship with the claim: within-budget only (erodes at M>P); ~2× (not ~3.8×) vs a workload-tuned P<M server; a 5–8% holder cost at M=1; **and the density requires unified-KV mode — now shipped first-class in #81 (§7.1 closed), so the density is a product property, no longer gated.** Keep. |
| **KV Persistence** | **KEEP** | No crossover — resume beats re-prefill at every measured prefix on both models, and the advantage grows with model size (up to 7.58× wall / 154× TTFT). Parity with the tuned server's own slot restore, plus the in-process capability (agent survives a process restart). Complexity is contained (`state_get`/`state_set` + a validated frame). One release gate: `state_set` as a trust boundary once blobs are disk-backed (§7). |

No feature is a **cut** on this profile: each clears its complexity by a
measured margin. Two carry release gates (§7), not measurement doubts.

---

## 5. Reconcile against the external targets in POSITIONING.md (no edit here — table only)

The current `docs/POSITIONING.md` lists external targets and — in "What we
have measured ourselves" — the **0.4-series** tool-loop numbers (CPU +
earlier iGPU, `results/report*.md`), which predate this campaign. This
table reconciles those against the 0.5 measured results. **No POSITIONING
edit is made in this document** (Stage 2, pending operator decisions).

### 5a. POSITIONING's own "measured" section (0.4 tool-loop) vs 0.5 re-measurement

| POSITIONING today | 0.5 measured | status |
|---|---|---|
| Tool loop 1.22×/2.13×/3.41× (iGPU 1.5B) and 1.34×/2.46×/4.10× (7B), framed as "vs re-prefill" | Reproduced as the **mechanism ratio** (vs stateless re-prefill) — up to 3.35× (1.5B) / 3.93× (7B) on the 0.5 stack; **BUT vs a tuned llama-server the adjusted ratio is parity** (0.89–1.11) | **REVISED** — the "vs re-prefill" numbers are the mechanism ratio, not a win over a tuned server; the honest tuned-baseline headline is parity. POSITIONING should relabel these as mechanism ratios and add the tuned-server parity finding. |

### 5b. External KV-persistence targets vs measured

| external target (POSITIONING) | 0.5 measured | status |
|---|---|---|
| TTFT 172 s → 1.3 s (**≈136×**) at 32K, hot cache; 15.7 s → 577 ms restore at 4K (Gemma 3 12B) | resume vs re-prefill TTFT **15–154×** (1.5B/7B) at 382–2254 tokens; direction and mechanism confirmed | **CONFIRMED-DIRECTION, magnitude context-specific** — our max 154× is at 2.3K/7B, not 32K/12B; the 136× at 32K is still-open (we did not measure 32K context) |
| 1.9× TTFT reduction / 23% wall in a 5-phase multi-agent workflow | not a matched workload (single-session resume here) | **STILL-OPEN** (different workload) |
| 12 agents vs 3 (Q4 vs FP16) capacity at 8K/24 GB | we measured Shared-Prefix density (8.2×), not Q4-vs-FP16 persistence capacity | **STILL-OPEN** (different axis) |

### 5c. External shared-prefix targets vs measured

| external target (POSITIONING) | 0.5 measured | status |
|---|---|---|
| Up to **15×** throughput on shared-prefix multi-round Q&A (server-class, LMCache) | up to **4.4× adjusted speed** within the slot budget + **8.2× session density** on edge | **PARTIALLY-CONFIRMED** — density 8.2× measured; the 15× throughput is server-class and remains still-open (different metric + hardware class) |
| TTFT reduced ~two orders of magnitude via prefix caching (long inputs) | within-budget adjusted wall advantage 3.8–4.4×; not two orders at measured sizes | **STILL-OPEN** (their setting: much longer inputs, server-scale prefix caching) |

### 5d. Sleep-time compute
Roadmap, not built; not part of this campaign. **UNCHANGED** (still a
target).

---

## 6. Honesty guardrails

- **Headline is the tuned-baseline adjusted ratio, never the naive
  re-prefill ratio.** Every §1 headline cell is the adjusted-vs-tuned-
  server number; the mechanism (vs stateless) column is explicitly labeled
  as context, per the narrative rule.
- **Absolute magnitudes are iGPU-specific and the direction is
  disclosed.** This profile is a **weak-compute integrated GPU**: it
  *flatters every prefill-saving mechanism* (Tool Loop, Shared Prefix, KV
  Persistence all win by avoiding prefill, and prefill is expensive here
  relative to decode). On a discrete GPU with fast prefill these ratios
  **compress**. The mechanism ratios and the speed advantages are edge
  claims; we measured that direction (CPU→iGPU already lowered the Tool
  Loop coefficient) rather than guessing it, and do not extend past it.
  The **density crossing (8.2×) and the structural ceilings** are
  memory/arithmetic facts less sensitive to compute speed, but are still
  measured on one machine.
- **Every number traces to a merged run PR + a config-hash.** The six
  isolated runs are on dd2e395be22675f1; the composite is on
  50fc841146dfbf6f (the post-#81 stack). No number originates outside the
  seven reports.
- **Named limits of this campaign:** single operator, single machine, one
  quant (Q4_K_M), two models (1.5B/7B), integrated GPU only. **No
  discrete-GPU (CUDA) run; no N>1 independent operator; no independent
  replication.** The transport estimator is a per-run TTFT-difference
  bound, flagged where it sinks into prefill noise. The Shared-Prefix
  density requires unified-KV mode, now shipped first-class (§7.1 closed).

---

## 7. Product gates (NOT benchmark issues — these block public claims until closed)

These are separate from measurement. Each blocks a specific public claim
until a product PR closes it.

1. **Shared-Prefix density (8.2×) requires unified-KV — CLOSED by #81.**
   Originally a gate: the pinned `LlamaCppBackend` created contexts in the
   default split-KV mode (where prefix sharing is architecturally
   impossible), and the isolated runs measured the density by wrapping the
   unchanged `__init__` to set `kv_unified=true`. **#81 shipped
   `kv_unified` as a first-class, tested `LlamaCppBackend` parameter**
   (default split), with a generation-identity check and an isolation
   suite; the release-ordering constraint the isolation test found
   (releasing a holder under live consumers perturbs their logits) is now
   **enforced in code** (`PrefixHolderInUseError`). The 8.2× is therefore a
   **product property**, no longer a benchmark wrapper, and enters
   POSITIONING (§8a lifted). The composite (#82) ran on this shipped stack
   (config-hash 50fc841) with the guard active and never raising.
2. **`state_set` is a trust boundary once KV blobs are disk-backed.**
   Benchmark blobs are self-produced, so the runs are safe; but a shipped
   disk-backed KV store hands attacker-influenceable bytes to llama.cpp's C
   state parser. `SECURITY.md` already records `state_set` as a
   not-yet-validated boundary; `NativeSession.load_state`'s frame check
   (magic/version/length, pre-C) is necessary but is **not
   authentication**. A shipped store needs **MAC + header validation
   before release**. On 7B the blob (and thus the disk footprint) doubles.

---

## 8. Stage-2 POSITIONING scope (operator decisions taken)

The two decisions have been made and are recorded here so the POSITIONING
diff is auditable against them:

- **(a) The 8.2× density → HOLD.** Not entered into POSITIONING at this
  stage; it waits for the unified-KV product PR (gate §7.1). The
  Shared-Prefix row in POSITIONING stays a target / still-open until then.
  **→ Update (post-#81/#82): HOLD LIFTED.** The unified-KV product PR
  merged (#81, §7.1 closed), shipping `kv_unified` first-class with the
  enforced guard. The 8.2× density now enters POSITIONING as a measured
  product property, with the §4 caveats (within-budget speed; ~2× vs a
  P-tuned server; erodes at M>P). See §9.
- **(b) External targets → REPLACE with measured, but ONLY for Tool Loop
  and KV Persistence** (the features the campaign measured AND decision (a)
  clears for publication). Specifically:
  - Tool Loop: relabel the existing 1.22–4.10× numbers as the **mechanism
    ratio** (vs stateless re-prefill), NOT an advantage over a tuned
    server, and add the 0.5 finding that adjusted vs a tuned llama-server
    is **parity** (fixes §5a REVISED).
  - KV Persistence: enter the measured 0.5 result — resume beats
    re-prefill at every measured prefix (no crossover), parity with the
    tuned server's own slot restore, in-process capability — with the
    honest note that the external 32K / multi-agent / capacity targets
    remain still-open (unmeasured regimes).
  - Shared Prefix: NO measured claim in POSITIONING; its external targets
    stay as targets, annotated "awaiting unified-KV product PR".

Stage 2 makes the **minimal** POSITIONING diff matching exactly these
decisions — measured numbers only, with the §6 disclaimers and §7 gates,
and nothing beyond them.

---

## 9. Composite — do the three mechanisms compose (#82), and this closes the campaign

The six isolated runs each measure one mechanism. The composite (#82, 1.5B, on
the post-#81 shipped stack, config-hash 50fc841) measures the three **together**
under one agentic workload — M parallel sessions sharing a system prompt, each
running multi-hop tool calls, a fraction resumed from persisted KV — asking
whether they ADD, OVERLAP, or FIGHT. Full report: `results/composite-1p5b.md`.

| finding | number | note |
|---|---|---|
| **Corruption gate** | **PASS** (L2 = 0.0, both session types; guard raises = 0) | cold (SP+TL) and resumed (KP+TL) sessions produce first-token logits bit-identical to a stateless reference; the enforced guard never fires under concurrency. Composition is *correct*, not just fast. |
| **Full-stack value** | **3.37–3.59×** (rung 1 → rung 4) vs the same workload with no mechanisms | the honest deployment number, dominated by the Tool Loop; reported as the full stack, never a cherry-picked isolated best |
| **Sub-additivity** | KP marginal delta ~0 (no resume) to ~10% (half resumed) | Shared Prefix and KV Persistence **partition by session type** (cold-prefix vs resumed-history) and add WITHOUT multiplying — a persisted blob is full-logical, so neither covers the other's subset. Confirms the Run 5 probe-Q2 prediction. |
| **Tool Loop dominates** | Δ 14–57 s (rung 3 → rung 4) | removing per-hop conversation re-prefill is the bulk of a multi-hop agent; most of the 3.5× is here |
| **Pool pressure** | did NOT materialize | M=12 / resume 0.5 uses 13,578 of 32,768 cells (41%), zero admission failures, zero slot exhaustion — the default budget is generous at this scale (honestly reported non-event, not manufactured) |

**Honesty guardrails (as §6):** the vs-tuned-server number (0.53–0.84×) is **not**
a headline — the native rungs run sessions sequentially for clean rung-delta
attribution while the server batches, so that gap mixes execution model with
mechanism; the clean per-mechanism competitive picture is the parity result in
the isolated runs (§1). The composite's job is delta attribution and the
full-stack value, both above. No disappointment clause fired; guard raises = 0 at
every point; ran under the chronometry budget (~2 h); no incidents, no re-runs.

**Net.** The level-3 mechanisms **compose** — correct (gate), sub-additive (they
cover different session subsets), Tool-Loop-dominated for multi-hop agents. The
honest deployment headline is **~3.5× over no mechanisms**; the per-mechanism
competitive numbers (§1: parity with a tuned server; §3: 8.2× density) remain the
external comparison. **This closes the 0.5 measurement campaign.** What remains is
not measurement but consolidation into POSITIONING (done) and the standing
release gate §7.2 (`state_set` MAC before a disk-backed KV store ships); a
discrete-GPU run (§6) is owed before any speed ratio is presented as
hardware-general.
