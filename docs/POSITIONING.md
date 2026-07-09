# Positioning

Where Palimpsests sits, who it is for, where the novelty actually is, and —
honestly — what performance we are *aiming* for versus what we have *measured*.
This document is deliberately blunt about the last distinction, because the whole
project is built on a measurement discipline (see [BENCHMARKING.md](BENCHMARKING.md)):
a number we have not produced on our own hardware is a **target**, not a result,
and is labeled as such here.

Today there is exactly **one benchmark** we have run ourselves — the tool-loop vs
re-prefill measurement below, now repeated across three environments. Everything
else in the performance section remains an external target. Keeping that line
sharp is the point.

---

## Who this is for

Palimpsests is a foundation library for running local LLM inference with
fine-grained control and an auditable trail. Two audiences overlap:

1. **Developers of agentic workloads** who want one abstraction from a thin
   Ollama wrapper up to a native serving loop, without rewriting the code above
   the engine as they move down the levels.
2. **Teams in regulated or sensitive sectors** — finance, defense, healthcare,
   public sector — for whom *where inference runs* and *whether the trail can be
   trusted* matter as much as raw speed.

The second audience is the sharper positioning, so it is worth being precise
about why.

## Why regulated / air-gapped deployments

A cloud inference API cannot simultaneously offer all three of the following.
Local-first execution with a hash-chained audit log can.

- **Data residency.** Request content never leaves infrastructure the operator
  controls. Air-gapped operation is a supported mode, not a workaround.
- **Traceability after the fact.** Every model and KV-state operation is recorded
  — the trail a regulator or internal auditor asks for.
- **Integrity of the trail.** The record is encrypted at rest *and* each row is
  SHA-256-chained to its predecessor, with the chain's head anchored outside the
  database. Editing, deleting, reordering, or replacing the log is therefore
  **detectable** (`AuditLog.verify()`), not merely discouraged — integrity can be
  demonstrated on demand rather than asserted. The limits of that guarantee — an
  attacker holding both the encryption key and keychain write access can forge
  chain and anchor together — are stated in the audit-log threat model in
  [SECURITY.md](../SECURITY.md), including a table of which attacker capabilities
  are and are not detected.

The regulatory anchor is the **EU AI Act** (Regulation (EU) 2024/1689). For
high-risk systems (Annex III — which an autonomous tool-calling agent is a strong
candidate for), **Article 12** makes automatic, lifetime event logging a legal
requirement, and **Article 26(6)** sets a minimum six-month retention. Article 12
does not say *tamper-proof*, but a log that can be silently altered has little
evidentiary value in an audit — which is exactly the gap an encrypted,
hash-chained trail addresses. Full references and caveats (including the moving
Digital Omnibus timeline and the not-yet-final technical standards) are in
[SECURITY.md](../SECURITY.md).

**We are not making a compliance claim.** Palimpsests is a library, not a
certified product; it provides *primitives designed to help address* these
obligations. Compliance is a determination for the deploying organization.

---

## What is novel here

Novelty has two forms, and conflating them is what makes strong systems work
sound trivial. There is **mechanism novelty** — a new inference primitive, a new
attention kernel — and there is **composition novelty** — a combination that does
not exist as a coherent system, closing a real gap. Palimpsests makes a
composition claim, and states the mechanism scope honestly so the claim stays
defensible.

**The mechanism scope (what we do not claim).** We do not invent a new inference
primitive or touch the attention kernel. Batched decode, per-sequence KV
save/restore, and shared-prefix copy are llama.cpp's. Saying so is not modesty;
it is what keeps every claim verifiable against a running system.

**The composition claim (where the novelty is).** No single system today combines
*continuous batching + shared-prefix KV + KV-persistence* under **one engine
abstraction**, **specialized for agentic edge workloads**, and **portable across
platforms**. Each component exists somewhere (see the Prior-art table in the
README), but the assembled system does not. The nearest by substance, **oMLX**,
covers only KV-persistence, only on Apple Silicon, without the three-level
abstraction or the context-memory layer.

**Why the composition is hard — the part "integration" hides.** The pieces resist
being combined unless the seams are designed:

- **One contract over three control models.** An external daemon (Ollama), a
  managed subprocess (llama.cpp), and an in-process serving loop (pal-native)
  have genuinely different control surfaces, yet must present a single
  `InferenceEngine` contract so callers query `capabilities` and never branch on
  engine identity.
- **One substrate under three features.** Continuous batching, shared-prefix
  copy, and KV persistence all depend on the *same* position tracking (`n_past` /
  `start_pos`). Get it wrong and a copied or restored KV resumes at the wrong
  position and silently corrupts output — so the substrate had to be built once,
  deliberately, beneath all three (this is why the position step shipped as its
  own invisible layer before the visible features).
- **One context-memory layer over opaque and transparent engines alike.** The
  sink/window/evict + block-retrieval layer must behave identically whether it
  sits above an opaque HTTP daemon or above KV state we own directly.
- **Commodity hardware, not a datacenter.** The serving techniques that exist
  (vLLM, SGLang) assume datacenter scale; the contribution is making the policy
  work as a local, cross-platform library.

That coordination — one contract over three control models, one substrate under
several features, one memory layer over both opaque and owned engines, on
commodity hardware — is the system-level engineering. It is architecture, not
glue.

---

## What we have measured ourselves

One benchmark, run three times. It is the one the level's strongest claim rests
on: **the server-side tool loop (N5) vs a re-prefill baseline.** In an agentic
`generate → tool → continue` cycle, the tool loop keeps the shared prefix and the
growing conversation live in KV and feeds only each tool result; a stateless
engine re-reads (re-prefills) the whole conversation every hop. Both arms decode
the same content through the same backend, model, and sampling — the only
variable is state control (see `benchmarks/bench_tool_loop.py`). Expectations
were pre-registered in writing before each run, per `BENCHMARKING.md` Rule 0.

### The three runs

| config (nominal) | prefix (measured) | CPU · 1.5B | iGPU · 1.5B | iGPU · 7B |
|---|---|---|---|---|
| prefix=50, hops=1 (control) | 27 | 1.08× | 1.00× | 0.99× |
| prefix=500, hops=4 | 363 | 2.14× | 1.22× | 1.34× |
| prefix=2000, hops=8 | 1491 | 4.67× | 2.13× | 2.46× |
| prefix=4000, hops=12 | 2979 | 7.23× | 3.41× | 4.10× |

Greedy sampling, `n_ctx=8192`, 5 repeats per arm (10 where a wide spread demanded
a re-run). Full JSON, environments, and pre-registered expectations:
`results/report.md` (CPU), `results/report-igpu-vulkan.md` (iGPU 1.5B),
`results/report-igpu-7b.md` (iGPU 7B). Reproduction: `results/REPRODUCE.md`.

**Only the two iGPU columns are a controlled comparison.** They share a machine,
a build, a pinned commit, and a virtualenv; the single changed variable is the
model. The CPU column is an **earlier run in a different environment** (Docker /
Debian / gcc, versus native Windows / MSVC / Vulkan), so its *within-run* speedups
are valid but its absolute times are not directly comparable to the others.

### What the numbers say

**The control behaves.** At a negligible prefix (27 tokens, one hop) the arms sit
at parity — 1.00× and 0.99× on the two iGPU runs. An un-rigged harness must show
this: with no prefix worth keeping, there is nothing for the tool loop to win.

**The win is exactly the re-prefill work avoided — and the arithmetic closes.**
If the mechanism is what we say it is, the treatment arm pays the prefill once
while the baseline pays it on every hop. Then the saved wall time should equal
*hops × TTFT*. On the 7B run:

| config | baseline − tool loop | TTFT | ratio | hops |
|---|---|---|---|---|
| prefix=500, hops=4 | 6.21 s | 1.59 s | 3.9 | 4 |
| prefix=2000, hops=8 | 56.86 s | 7.02 s | 8.1 | 8 |
| prefix=4000, hops=12 | 197.79 s | 16.26 s | 12.2 | 12 |

It lands within a few percent at every config, and the same check holds on the
1.5B runs. TTFT medians are near-identical between arms throughout (16.26 s vs
16.32 s at 4000/12), so the gain comes from the hop loop, not from any first-fill
asymmetry. This is a stronger statement than "we are faster": the saved time is
accounted for, not merely observed.

**The speedup scales with the prefill cost being avoided.** Two independent axes,
one cause:

- *Faster prefill hardware lowers the coefficient.* Moving from CPU to the iGPU,
  the baseline's per-hop penalty shrinks, and so does our advantage.
- *A larger model raises it.* Prefill cost grows faster than decode cost with
  model size, so at 7B the baseline pays more per hop — 1.34× / 2.46× / 4.10×
  against 1.22× / 2.13× / 3.41× at 1.5B, on the same machine.

Both were predicted in writing before the runs, and both held. Together they are
the mechanism, measured from two directions.

**In practical terms**, on the 7B agent loop (12 hops, ~3k-token prefix), the
integrated GPU takes **4 min 22 s** re-prefilling and **1 min 4 s** with the tool
loop.

### What this does not show — read before quoting it

- **This is an edge claim, not a server-class one.** The advantage is largest
  where prefill is expensive relative to decode: commodity and integrated
  hardware, larger models, longer prefixes. On datacenter accelerators with very
  fast prefill it will compress further. We measured that direction rather than
  guessing it, and we do not extend the claim past where we measured.
- **It is a mechanism check, not a representative performance figure.** Every run
  so far is on an **integrated** GPU or CPU, on Qwen2.5 Q4_K_M. A discrete-GPU
  (CUDA) run is a separate, pending exercise. We do not present "7×" or "4×" as a
  headline.
- **Cite the measured prefix, not the nominal label.** The filler heuristic
  produces fewer tokens than the config name suggests ("4000" is ~2979 measured).
- **One soft number.** At 500/4 on the 1.5B iGPU run the two arms' ranges overlap
  at 5 repeats, so its 1.22× is the least firm figure in the set. The same config
  at 7B shows no overlap (18.11–19.38 s vs 23.22–25.64 s), and every other config
  is tight.
- **One benchmark, not a suite.** The KV-persistence and shared-prefix speedups
  below remain **targets** until measured the same way.

---

## Performance: targets, not yet results

> **Read this first.** None of the numbers below were produced by Palimpsests on
> our hardware. They are published results from **other** systems and papers that
> exercise the *same mechanisms* we implement. We list them as **orientation
> targets** — the ballpark we aim to reproduce as each mechanism is measured on
> hardware, under the protocol in [BENCHMARKING.md](BENCHMARKING.md). Until then,
> treat every figure as "someone else achieved this on their setup; our goal is
> to get into this range on ours." A benchmark is only worth running if it can
> disappoint us — so these are hypotheses to test, not marketing. (The one
> exception, now measured by us, is the tool-loop result in the section above.)

### KV persistence — avoiding re-prefill (our N6 / N6b direction)

The mechanism: persist a session's KV state and reload it instead of
recomputing the prefill. This is the single largest lever in the papers below,
and it maps directly onto our `save_state` / `load_state` and content-addressed
store.

| Reported effect (their hardware) | Setting | Source |
|---|---|---|
| TTFT 172 s → 1.3 s (**≈136×**) at 32K context, hot cache | Gemma 3 12B, edge | *Agent Memory Below the Prompt* — Persistent Q4 KV Cache, arXiv 2603.04428 |
| Context restore 15.7 s → 577 ms at 4K, warm disk | Gemma 3 12B, edge | arXiv 2603.04428 |
| **1.9×** TTFT reduction in later phases; 23% wall-time saving | 5-phase multi-agent workflow | arXiv 2603.04428 |
| **24×** TTFT reduction when querying cached experts | 10-expert routing | arXiv 2603.04428 |
| Capacity: Q4 fits **12** agents vs FP16's **3** at 8K on 24 GB | edge, fixed memory | arXiv 2603.04428 |

This paper is the closest external twin to our direction — edge, persistent
quantized KV, multi-agent — which makes it our strongest reference *and* our
honesty check: the underlying persistence mechanism is not ours to claim. What is
ours is the surrounding system — the same persistence exposed under the
three-level abstraction, addressed by content (N6b), and sharing one position
substrate with batching and shared-prefix reuse — which no existing tool assembles
on cross-platform local hardware.

### Shared-prefix KV — computing a common prefix once (our N4 direction)

The mechanism: a system prompt shared across sessions is decoded once and copied,
not recomputed per session. Our prefix-holder policy implements exactly this.

| Reported effect (their hardware) | Setting | Source |
|---|---|---|
| Up to **15×** throughput on multi-round Q&A with a shared prefix | server-class | LMCache published benchmarks |
| TTFT reduced by ~two orders of magnitude under long inputs via prefix caching | agentic multi-turn | *Observation, Not Prediction* (ConServe), arXiv 2606.01839 |
| Cache hit rate 80.2% (CoQA) vs ~53% best baseline; TTFT 284 ms vs 372–2140 ms | affinity-scheduled multi-turn | IEMAS, arXiv 2603.17302 |

The principle underneath all of these: **any change to the start of the context
invalidates the entire prefix cache from that point** — a single changed token in
a 5,000-token system prompt forces recomputation of all 5,000. Shared-prefix
reuse is valuable precisely because it protects the expensive common prefix.

### Sleep-time compute — using idle cycles (roadmap)

The mechanism: precompute over the context while the device is idle, so
user-facing turns do less work. Verified against the source paper.

| Reported effect (their hardware) | Setting | Source |
|---|---|---|
| ~**2.5×** less test-time compute for similar accuracy (up to 5× fewer tokens) | stateful multi-query | Lin et al., *Sleep-time Compute*, arXiv 2504.13171 |
| ~**+15%** accuracy at matched compute when queries share context | stateful multi-query | arXiv 2504.13171 |

Edge fit: locally, idle GPU time is free — there is no cloud meter running — so
the trade this paper makes (spend idle compute to cut user-facing latency) is
even more favorable on-device than in the cloud. This is roadmap, not built.

---

## The honest summary

- **What is real today:** the three-level abstraction, the context-memory layer,
  the encrypted hash-chained audit log, and a fully test-covered level-3 skeleton
  (streaming, stateful sessions, continuous batching, server-side tool loop,
  shared-prefix KV, KV persistence) — backed by a **real `LlamaCppBackend`
  validated on hardware**. The composition — several serving features over one
  position substrate, under one contract, on cross-platform local hardware —
  exists and is tested; that is the novel part.
- **What we have measured ourselves:** one benchmark, three runs — the tool loop
  against a re-prefill baseline, on CPU (1.5B) and an integrated GPU (1.5B and
  7B). The advantage grows with the prefill cost avoided, the arithmetic accounts
  for the saved time (*hops × TTFT*), and the control sits at parity. It is a
  **mechanism check on edge-class hardware**, not a representative discrete-GPU
  figure, and we do not extend it to server-class deployments.
- **What is still a target:** the KV-persistence and shared-prefix numbers above.
  They come from external systems exercising the same mechanisms; reproducing them
  on our hardware, with a strong baseline (a tuned Ollama), is the continuing
  point of the benchmarking phase.
- **What we will not do:** claim a new inference primitive we did not build,
  publish a speedup we have not measured, quote a sanity-check number as a
  headline performance figure, extend a measured claim to hardware we have not
  measured, describe an integrity guarantee more strongly than the code provides,
  or call the project compliant with a regulation it has not been certified
  against. The scope honesty and the measurement discipline are what make the
  composition claim credible — they are part of the product, not a hedge against
  it.
