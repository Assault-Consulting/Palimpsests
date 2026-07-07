# Positioning

Where Palimpsests sits, who it is for, where the novelty actually is, and —
honestly — what performance we are *aiming* for versus what we have *measured*.
This document is deliberately blunt about the last distinction, because the whole
project is built on a measurement discipline (see [BENCHMARKING.md](BENCHMARKING.md)):
a number we have not produced on our own hardware is a **target**, not a result,
and is labeled as such here.

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
Local-first execution with a tamper-evident audit log can.

- **Data residency.** Request content never leaves infrastructure the operator
  controls. Air-gapped operation is a supported mode, not a workaround.
- **Traceability after the fact.** Every model and KV-state operation is recorded
  — the trail a regulator or internal auditor asks for.
- **Integrity of the trail.** The record is encrypted and tamper-evident, so its
  integrity can be demonstrated rather than merely asserted.

The regulatory anchor is the **EU AI Act** (Regulation (EU) 2024/1689). For
high-risk systems (Annex III — which an autonomous tool-calling agent is a strong
candidate for), **Article 12** makes automatic, lifetime event logging a legal
requirement, and **Article 26(6)** sets a minimum six-month retention. Article 12
does not say *tamper-proof*, but a log that can be silently altered has little
evidentiary value in an audit — which is exactly the gap an encrypted,
tamper-evident trail addresses. Full references and caveats (including the moving
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

## Performance: targets, not yet results

> **Read this first.** None of the numbers below were produced by Palimpsests on
> our hardware. They are published results from **other** systems and papers that
> exercise the *same mechanisms* we implement. We list them as **orientation
> targets** — the ballpark we aim to reproduce once the real `LlamaCppBackend`
> runs on hardware, under the protocol in [BENCHMARKING.md](BENCHMARKING.md).
> Until then, treat every figure as "someone else achieved this on their setup;
> our goal is to get into this range on ours." A benchmark is only worth running
> if it can disappoint us — so these are hypotheses to test, not marketing.

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
  the encrypted audit log, and a fully test-covered level-3 skeleton (streaming,
  stateful sessions, continuous batching, server-side tool loop, shared-prefix
  KV, KV persistence) on a fake backend behind the ADR-0002 seam. The composition
  — several serving features over one position substrate, under one contract, on
  cross-platform local hardware — exists and is tested; that is the novel part.
- **What is a target:** every performance number above. They come from external
  systems exercising the same mechanisms; reproducing them on our hardware, with
  a strong baseline (a tuned Ollama), is the point of the benchmarking phase.
- **What we will not do:** claim a new inference primitive we did not build,
  publish a speedup we have not measured, or call the project compliant with a
  regulation it has not been certified against. The scope honesty and the
  measurement discipline are what make the composition claim credible — they are
  part of the product, not a hedge against it.
