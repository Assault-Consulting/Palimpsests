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
*numbers* are flagged "to verify."

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
- **BENCHMARKING.md** — the honest measurement protocol.

The L3 skeleton is functionally complete for the four things a benchmark
needs: streaming, sessions, concurrent batching, tool loop.

---

## Reframing: two planned steps are stronger as policy, not mechanism

External review sharpened two steps we were about to build as raw
mechanism into their more valuable framing:

- **N4 was "shared-prefix KV". It becomes prefix-aware slot
  orchestration.** The value is not `seq_cp` (that is llama.cpp's
  primitive) but the *policy* over it: agent→slot affinity, prefix-aware
  routing, cache-invalidation-aware placement. The documented real pain
  is people manually pinning a main session to slot 0 and subagents to
  slot 1 so they don't evict each other's KV, and cache invalidation when
  a system prompt changes. Nobody has productized the policy layer. That
  is exactly our "integration, not mechanisms" mandate, and the scheduler
  is already half of it. The shared-prefix holder is the *first case* of
  this policy, not the whole of N4.

- **N6 was "KV save/restore". It becomes a content-addressed KV store.**
  Plain `save_state`/`load_state` is yesterday — `--slot-save-path`
  already exists in llama.cpp. The value shifts to a content-addressed,
  reusable KV store: "LMCache for edge" (LMCache is the datacenter/vLLM
  version; the edge niche is open). N6 should be built as that store, not
  as bare save/restore.

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

- **Edge idle compute is free.** On local hardware the GPU idles ~95% of
  the time at no marginal cost — unlike cloud, where sleep-time compute
  spends billable cycles. The edge is the *natural* home for it.
- **It lands on what we already have.** `session.sleep()` → produce `c'`
  → store in the existing BlockMemory. No new substrate.
- **It is the project's own metaphor** — rewriting the palimpsest while
  no one is reading.

We are not first to the concept (Letta shipped it in MemGPT 2.0). Our
niche is the *edge-native* framing: free idle compute, local store, no
cloud. This is a strong candidate to slot **before N6**, possibly before
finishing N4, because its benefit (idle compute) does not depend on
prompts coinciding the way prefix-sharing does.

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

1. **N4a** — scheduler primitives for a prefix holder (reserve / warm /
   copy-to-slot), on the fake backend, framed as the first case of slot
   orchestration policy. No flag change.
2. **N4b** — engine-side prefix registry + refcounted holders + exact
   token-match identity; flip `shared_prefix`. (Variant B: engine owns the
   registry; scheduler stays thin.)
3. **Sleep-time compute (edge)** — `session.sleep()` → `c'` → BlockMemory.
   Evaluate slotting this before N6.
4. **N6** — content-addressed KV store ("LMCache for edge"), built on
   N-pos + `state_get`/`state_set`; flip `kv_persistence`.
5. **N7 + spec-decode safety interlock** — optional, later.
6. **Real `LlamaCppBackend` + run the BENCHMARKING protocol** — the first
   real measurement, on the user's hardware (needs a GGUF and a build
   toolchain; validated off-CI).

Prefix-aware routing (the broader policy beyond a single shared holder)
grows out of N4b as scheduling matures.

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
