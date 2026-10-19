# Palimpsests roadmap

**Status:** working plan, revised with each release. Last revised for
**0.13** (October 2026). What shipped is in the
[CHANGELOG](../CHANGELOG.md); this page says where the project is going and
why, and what is deliberately not scheduled.

The direction has not changed since 0.6: the measurement campaign showed
that the level-3 speed mechanisms reach parity with a tuned
`llama-server`, not an edge over it, so the project's differentiation is
the **audit trail** — a format a regulator can check without trusting our
binary — and the deployment model, not raw speed. Everything below is
weighed by that.

---

## Where the project stands (0.13)

- **The format is frozen and independently reproduced.** PALA-1 v1.0
  (August 2026), five independent verifier implementations on record, a
  self-service verification kit, the vectors shipped inside the wheel.
  Post-freeze questions are answered in numbered
  [clarifications](specs/pala-1/CLARIFICATIONS.md); the core text has not
  changed.
- **The inference profile records the agent's tool loop** — calls,
  results, guard refusals, incidents and oversight — from the wire it
  mediates and from the surfaces that report to it: the ingestion route, agent
  hooks (Claude Code, Codex), the LiteLLM callback and the MCP proxy, and
  OpenTelemetry GenAI traces. Each record says how it was observed, and
  what its recorder could not see (profile r5 source marks, r6 outcome
  `unobserved`).
- **Retention is bounded and declared in the chain.** Rotation with a
  policy, segments that verify alone, and since r6 a continuation record at
  every cut carrying the derived root of everything before it — so the
  survivors of a deletion explain themselves.
- **The trail can leave the island.** SCITT signed statements (construction
  v3 carries the derived root), prefix-consistency proofs, evidence
  bundles, a published report schema.
- **The level-3 engine is complete and measured** (0.3–0.6): continuous
  batching, server-side tool loop, shared-prefix KV, KV persistence and a
  content-addressed KV store behind the ADR-0002 seam, measured on 1.5B and
  7B — see `results/CONSOLIDATION-0.5.md` and `POSITIONING.md`.

---

## Next: 0.14 — real traffic and testing

0.13 shipped the adapters; 0.14 is about evidence that they hold on real
traffic, outside our own test suite.

- **Run records on real traffic** for both adapter families (agent hooks,
  OpenTelemetry), on maintainers' hardware and accounts, filed under
  `docs/specs/pala-1/independent-runs/`.
- **OpenCode, revisited** (O1–O6): the plugin surface changed under us
  once; re-measured on a current release.
- **`COMPATIBILITY.md`** — which client and framework versions are known to
  work, from the surface checker's dated reports, not from memory.
- **Listings** in the ecosystems the adapters target, once the run records
  exist to point at.
- **The reading surface, towards its 1.0 contract** — the U track in
  [CONSUMER-SURFACE.md](CONSUMER-SURFACE.md): re-exports with a contract
  test (U19, U20), violation codes (U24), `empty_container` (U26),
  `container_check()` (U21), and `verify_segment_set()` (U18).
- **Independent verification of what is new** — a from-the-spec run of the
  inference profile r3–r6, and bridge run B3 reproducing SCITT statement
  construction v3. These depend on people outside the project and are
  planned, not promised for a date.

---

## Towards 1.0

PALA-1 is already at v1.0. **Palimpsests 1.0** is a different promise: that
a consumer written against it keeps working, and keeps meaning the same
thing, until 2.0 — and that defects reported against it will be fixed.
The criteria, agreed in October 2026:

- **A stable public API — the main criterion.** The reading surface is
  defined, test-pinned and phased in by [CONSUMER-SURFACE.md](CONSUMER-SURFACE.md):
  its rules on meaning (frozen `None` semantics, open vocabularies, machine
  fields versus sentences) already apply from 0.13; the structural rules
  (one import path, no removal within a major, deprecation over one minor)
  take effect at 1.0. The writer gets a contract of its own before then
  (U27), for runtime integrators.
- **Stable formats beside the frozen core.** The report
  (`pala-verification-report/1`), the bundle (`pala-bundle/1`), the
  consistency proof (`pala-consistency-proof/1`) and the segments manifest
  (`pala-segments/1`, which still needs a specification document of its
  own) change only by format-id bump. SCITT statement construction v3
  joins them after an independent reproduction.
- **Verification from our side, written down.** What is checked before
  every release — the suites on three platforms, the vectors, the surface
  checker, a reproducible build — as a checklist anyone can read, not a
  habit.
- **Readiness to fix, declared as a commitment.** Which versions receive
  fixes, how a vulnerability is handled and how fast, and that a critical
  problem reported by someone running Palimpsests is the first priority.
  The OpenSSF Gold badge and Scorecard are the practice this rests on;
  1.0 makes it a stated promise.

**Not a gate:** an independent security audit. It is welcome and it is a
question of funding; it does not block the work, and until it happens the
documentation says it has not happened.

**Not a criterion we control:** users. A stable API comes first; users
follow it.

---

## Later, unscheduled

- **Assurance tiers B and C** beyond today's PKCS#11 anchor — a hardware
  root of trust and an external witness — gated on the tier open questions
  (TPM clear semantics, witness longevity).
- **A storage-boundary `SHED` class and a predictive "boundary
  approaching" event** — the two `Planned` rows of the ISO/IEC 24970
  mapping.
- **Anchoring the segments manifest** (retention-continuation open issue 2).
- **A disk-backed KV store** — gated on a MAC over `state_set` input first:
  that is a real trust boundary.
- **A discrete-GPU run** — owed before any speed ratio is presented as
  hardware-general; the integrated GPU flatters every prefill-saving
  mechanism.
- **ISO/IEC 42001 and 23894 mappings**, condensed, in the form of the
  existing ones.
- **Speculative decoding** (N7) with its structured-output interlock, and
  the research items below.

---

## Deferred: sleep-time compute (edge-native) — not scheduled

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
cloud. **Deprioritized as of 0.6.** The 0.5 measurement campaign showed the
level-3 speed mechanisms reach parity with a tuned `llama-server`, not an
edge over it; the project's differentiation is the audit/compliance story
and the deployment model, not another edge perf feature. Sleep-time is a
genuine idea and stays recorded here, but it is **not scheduled** — effort
goes to the verifiable-audit direction (the sections above) instead. Its
benefit would still be *measured, not asserted*, if it is ever built.

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
