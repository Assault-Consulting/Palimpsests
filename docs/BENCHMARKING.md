# Measuring effectiveness — the benchmarking protocol

**Status:** methodology document
**Read before running any comparison.**

Palimpsests' central value is not a single fast feature — every individual
mechanism (parallel requests, prefix sharing, KV persistence) already
exists somewhere. The value is the **measurement stand**: L1, L2, and L3
behind one abstraction, on the same hardware and model, so a hypothesis —
"this research idea helps agentic local inference" — can be *measured*
against an honest baseline instead of believed.

That value exists only if the measurement is honest. A stand that always
flatters us is not an instrument; it is a mirror. This document fixes the
protocol **before** any run, so the baseline and metrics are chosen before
we see a result, not tuned after.

---

## 0. The one rule

**A benchmark is only worth running if it is allowed to disappoint us.**

If a comparison cannot produce "L3 gave no meaningful gain here" or "a
well-configured baseline matched us," it is broken. Every design choice
below serves this rule.

---

## 1. Strong baseline, never a straw man

The most common way to lie with a benchmark is to weaken the baseline.
Avoid it deliberately:

- **Ollama (L1) must be configured optimally**, not left at defaults.
  Ollama supports parallel requests since v0.2 via `OLLAMA_NUM_PARALLEL`
  (auto-selects 1 or 4 by memory). Comparing L3 batching against Ollama
  with `OLLAMA_NUM_PARALLEL=1` is dishonest — set it to a sensible value
  (e.g. 4) and set the context length to match the test.
- **llama.cpp (L2) must run the same launch flags** L3 uses internally —
  same quant, same flash-attention, same GPU offload. If L2 and L3 differ
  in anything except the level of state control, the number is worthless.
- Use the **same build** of the underlying engine for L2 and L3 (both are
  llama.cpp). A faster forward pass in one build would masquerade as an
  architectural win.

If in doubt, make the baseline *stronger* than feels fair. A win over a
strong baseline is real; a win over a weak one is noise.

---

## 2. One variable at a time

Everything identical except the single thing under test:

- same **hardware** (same machine, same GPU/CPU, nothing else running),
- same **model file** (same GGUF, same quantization),
- same **prompt**, same **input length**, same **max tokens**,
- same **sampling** (greedy / fixed seed — never compare greedy vs
  sampled),
- same **context size** budget.

The variable under test is exactly one of: the control level (L1 vs L2 vs
L3), or one research idea toggled on/off *within* L3. Never both at once.

---

## 3. What to measure

Report all of these; a single number hides the trade-offs:

- **TTFT** — time to first token (latency; dominated by prefill).
- **TPOT** — time per output token (steady-state generation speed).
- **End-to-end wall time** — for the *whole task*, not one call. This is
  where L3's agentic wins live (a 10-step tool loop, not one generation).
- **Throughput** — total tokens/sec across all active sequences (the
  batching metric; meaningful only for the multi-session test).
- **Peak memory** — RAM and VRAM. A speed win that OOMs is not a win.

Latency vs throughput trade off against each other. Batching can raise
throughput while raising per-request latency. Report both so the
trade-off is visible, not buried.

---

## 4. The workloads that actually separate the levels

L3 does **not** make a single, isolated generation faster — the forward
pass is the same llama.cpp underneath. So a single-prompt benchmark will
(correctly) show ~no L3 advantage. Test the profiles where L3's state
management is supposed to pay off, and say plainly when it doesn't:

1. **Single-shot generation.** One prompt, one response. Purpose: confirm
   L3 is *not slower* on the base case, and establish TPOT parity. Expect
   no L3 win here — that is the honest control.
2. **Agentic tool loop.** One conversation, N iterations of
   generate → tool call → continue, with a large shared system prompt.
   This is L3's strongest case (no re-prefill via the server-side tool
   loop). Measure end-to-end wall time vs L2 re-prefilling each step.
3. **Multiple concurrent sessions, shared system prompt.** K sessions
   (2–8), same large system prompt. Compare L3 (shared-prefix KV + one
   forward) against Ollama with `NUM_PARALLEL=K`. Expect the L3 win to
   come mostly from prefix sharing — so **also run a no-shared-prefix
   variant**, where L3 and a batched baseline may come out close. Record
   that honestly; it maps the boundary of our advantage.
4. **Cold-start with KV persistence** (once N6 exists). Long context,
   restart, first-token latency with vs without KV loaded from disk.

For each workload, decide **before the run** what result would mean "L3
helps here" and what would mean "it doesn't."

---

## 5. Procedure

1. Warm up: run each engine once and discard (exclude cold model-load from
   timings unless cold-start is the thing being measured).
2. Repeat each measurement **at least 5 times**; report median and spread
   (min/max or IQR), never a single run.
3. Fix the seed; use greedy where possible so token counts are identical
   across engines.
4. Record the full environment: machine, OS, GPU, driver, engine build/
   commit, model file + quant, all launch flags, and every env var
   (including `OLLAMA_NUM_PARALLEL`). A number without its environment is
   not reproducible and not evidence.
5. Keep the raw results. Report the protocol and the environment alongside
   the numbers so a reader can rerun and check.

---

## 6. Honest reporting

- If L3 shows no gain on a workload, **say so** and keep the result. The
  negative result is the stand doing its job — it tells us where to *not*
  spend effort, which is as valuable as a win.
- Report the trade-off, not just the favorable axis ("L3 raised throughput
  1.8x but per-request latency rose 20%"), so the reader sees the whole
  picture.
- Never present a win over a mis-configured baseline. If the baseline
  wasn't tuned, the comparison is void — rerun it.
- Distinguish *measured* from *expected*. Anything not actually run on this
  stand is a hypothesis, labelled as such.

---

## 7. Why this protocol is the moat

Features get copied. A disciplined, reproducible method for asking "does
this actually help *local agentic* inference on *this* hardware, versus a
strong baseline?" — and being willing to answer "no" — is much harder to
copy, because it requires the honesty to publish results that don't
flatter you. That honesty is the durable asset. Protect it by choosing the
baseline and metrics here, in writing, before each run.
