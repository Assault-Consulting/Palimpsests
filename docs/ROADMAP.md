# Palimpsests L3 roadmap

**Status:** working plan. Updated as steps land.

The value of Palimpsests is not any single mechanism — every individual
mechanism (parallel batching, prefix sharing, KV persistence) exists
somewhere already. The value is **orchestration**: composing llama.cpp's
primitives into disciplined policy for local agentic serving, plus the
**measurement stand** (L1/L2/L3 behind one abstraction) that lets us test
whether a research idea actually helps *on this hardware* vs a strong
baseline. Everything below is weighed by that lens.

A note on numbers: figures cited from external papers (e.g. sleep-time
compute's 2.5×, KV-reuse speedups) are **hypotheses until measured on our
own hardware** per `BENCHMARKING.md`. We adopt their *logic* now; their
*numbers* are flagged "to verify." A consolidated, sourced table of those
targets lives in `POSITIONING.md`. As of 0.4 one of those hypotheses — the
tool-loop advantage — has a first measured result (see below).

---

## Done

- **Spike S1** — three llama.cpp primitives confirmed (ADR-0001).
- **ADR-0002** — in-process, and the fake-backend test seam.
- **N1** — native scheduler + stateless streaming (`streaming`).
- **N3a** — stateful sessions, one at a time (`stateful_sessions`).
- **N3b** — concurrent session batching (`continuous_batching`).
- **N5** — server-side tool loop, no re-prefill (`server_side_tools`).
- **N-pos** — per-slot KV position (`n_past` / `start_pos`), the
  substrate N4 and N6 both need. No user-visible feature; no flag moved.
- **N4a** — scheduler primitives for a prefix holder (reserve / warm /
  copy-to-slot), the first case of slot-orchestration policy. No flag.
- **N4b** — engine-side prefix registry + refcounted holders + exact
  token-match identity; `shared_prefix` on. Variant B: engine owns the
  registry, scheduler stays thin.
- **N6** — KV persistence: `save_state` / `load_state` with the position
  packed into a self-contained blob; `kv_persistence` on.
- **N6b** — content-addressed KV store ("LMCache for edge") layered over
  N6: reuse a saved state by a hash of the tokens that produced it, not by
  an opaque path. No flag (a convenience layer over the N6 primitive).
- **BENCHMARKING.md** — the honest measurement protocol.
- **Real `LlamaCppBackend` — validated on hardware (0.4).** The ctypes
  backend mapping onto the same primitives the fake backend exposes,
  brought online on real hardware (llama-cpp-python 0.3.33, Qwen2.5-1.5B
  Q4_K_M). Construction, tokenize round-trip, and a scheduler/session
  smoke test passed; the vocab/memory/state_seq version shims resolved
  cleanly. One context-param fix was needed on first contact
  (`n_batch = n_ctx`, so a large single-call prefill does not trip
  `GGML_ASSERT` inside `llama_decode`). This closes the "real backend"
  gap — the skeleton now runs a real model.
- **First measurement — tool-loop (N5) vs re-prefill.** Our strongest
  claimed advantage, measured first per the working order below. Result:
  1.08× at the control (negligible prefix) growing to ~7× at
  prefix≈3000 / 12 hops — the speedup tracks the re-prefill work the tool
  loop avoids, with near-identical TTFT between arms. Measured **CPU-only
  on a 1.5B model** as a mechanism sanity check, **not** a representative
  performance figure; the numbers and full method are in `results/` and
  `POSITIONING.md`. A GPU / larger-model run is the pending next step.

**The level-3 skeleton is complete, and the real backend is now
validated.** All six capability flags — `streaming`, `stateful_sessions`,
`continuous_batching`, `server_side_tools`, `shared_prefix`,
`kv_persistence` — are true behind the ADR-0002 seam, with the
content-addressed store on top, and the `[native]` backend runs a real
model on hardware. What remains is not more skeleton: it is more
measurement (GPU, larger models, the persistence and shared-prefix cases)
and research layers on top.

---

## Reframing: two planned steps were stronger as policy, not mechanism

External review sharpened two steps we were about to build as raw
mechanism into their more valuable framing. Both are now landed in that
sharper form:

- **N4 was "shared-prefix KV"; it became prefix-aware slot
  orchestration.** The value is not `seq_cp` (llama.cpp's primitive) but
  the *policy* over it: agent→slot affinity, prefix-aware routing,
  cache-invalidation-aware placement. The shared-prefix holder (N4a/N4b)
  is the *first case* of this policy; broader prefix-aware routing grows
  out of it as scheduling matures.

- **N6 was "KV save/restore"; it became a content-addressed KV store.**
  Plain `save_state`/`load_state` (N6) is the primitive — `--slot-save-path`
  already exists in llama.cpp. The value is the content-addressed reuse
  layer (N6b): "LMCache for edge," addressing a warm KV by what it
  represents rather than where it happens to be stored.

---

## New direction: sleep-time compute (edge-native)

Verified against Lin et al., "Sleep-time Compute" (arXiv 2504.13171,
Letta + UC Berkeley). The model, while idle, pre-processes a static
context `c` into an enriched `c'` (`S(c) → c'`) that is reused across
future queries about the same context. Reported: ~2.5× less test-time
compute for equal accuracy (up to ~1/5 tokens), or ~15% more correct
answers at equal budget — *to verify on our hardware*. Effectiveness
correlates with how predictable the user's query is.

Why this fits Palimpsests specifically, more than it fits anyone else:

- **Edge idle compute is free.** On local hardware the GPU idles most of
  the time at no marginal cost — unlike cloud, where sleep-time compute
  spends billable cycles. The edge is the *natural* home for it.
- **It lands on what we already have.** `session.sleep()` → produce `c'`
  → store in the existing BlockMemory. No new substrate.
- **It is the project's own metaphor** — rewriting the palimpsest while
  no one is reading.

We are not first to the concept (Letta shipped it in MemGPT 2.0). Our
niche is the *edge-native* framing: free idle compute, local store, no
cloud. Its benefit is best *measured*, not asserted — which is why it now
sits **after** the real backend, alongside the first benchmarks, rather
than as one more fake-backend mechanism.

---

## Deferred, with conditions

- **Speculative tool execution + audit-log mining** (PASTE-style: tool
  sequences aren't random; mine execution traces into patterns; dispatch
  in parallel). Uniquely ours because the audit log is already an
  append-only trace store no wrapper project has. Deferred because: (1) it
  needs a *volume* of real traces we don't have yet; (2) its minimal form
  (async/parallel tool dispatch) conflicts with our deliberate synchronous
  tool-loop decision — we'd open async consciously, not by side effect.
  Numbers (e.g. 48.5%) to verify.
- **Structured-output safety interlock for speculative decoding**
  (auto-configure spec-decode per workload; e.g. raise `prompt_lookup_min`
  on tool-call turns to stop corrupting tool output). Small feature, real
  reliability, strong competence signal. Belongs with N7 (spec decoding).

---

## Working order (subject to revision)

The fake-backend skeleton (N1 → N3a → N3b → N5 → N-pos → N4a → N4b → N6 →
N6b) is **done**, and the real backend is now **validated on hardware with
the first tool-loop measurement landed** (0.4). What follows continues to
need hardware:

1. ~~**Real `LlamaCppBackend` + run the BENCHMARKING protocol.**~~
   **Done (0.4).** The ctypes backend runs a real model; the first
   measurement (tool-loop vs re-prefill, our strongest claimed advantage)
   is landed — a CPU-only 1.5B sanity check confirming the mechanism and
   its direction. **Next within this step:** a GPU / larger-model run for
   representative magnitudes, and the persistence (N6) and shared-prefix
   (N4) benchmarks against a tuned baseline.
2. **Sleep-time compute (edge)** — `session.sleep()` → `c'` → BlockMemory,
   built and measured together, since its value only shows on hardware.
3. **Disk-backed KV store** — persist the N6b store across process exit,
   behind the same `KVStore` interface (survive restarts / memory
   pressure).
4. **N7 + spec-decode safety interlock** — optional, later.

The priority remains measurement: now that a real backend exists, the
next numbers to produce are the GPU/larger-model tool-loop run and the
persistence and shared-prefix cases.

---

## Standing principles

- Scheduler stays thin (primitives); policy lives in the engine
  (Variant B). Research that is *state management* (eviction, retrieval,
  KV strategies, sleep-time rewriting) plugs in as policy over primitives;
  research that changes the *attention kernel* is L4 territory, out of
  scope.
- Extract the sampler behind a `Sampler` protocol when spec/contrastive
  decoding arrives, so sampling research plugs in without touching the
  loop. (Principle only; not yet built.)
- Every optimization's benefit is *measured*, not declared. A benchmark is
  only worth running if it can disappoint us.
