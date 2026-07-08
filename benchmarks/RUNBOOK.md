# v0.4 hardware runbook — bringing the real backend online

**Status:** instructions for the empirical phase. Nothing here has been
run yet; this is the checklist to follow the first time hardware (a
machine with a C toolchain and enough RAM/VRAM for a small GGUF) is
available. It exists so the gap between "code on the shelf" (v0.3) and
"numbers we can call our own" (v0.4) is a checklist, not a research
session from memory.

The two artifacts this runbook drives:

- `src/palimpsests/providers/native/llamacpp_backend.py` — the real
  `NativeBackend`, written blind against the ctypes API. **Expected to
  fail on first contact** at one or more of the marked risk points; the
  code is structured so each failure lands on one named line.
- `benchmarks/bench_tool_loop.py` — the first measurement (tool loop vs
  re-prefill), following `docs/BENCHMARKING.md`.

---

## Step 0 — decide the expected result BEFORE running anything

`docs/BENCHMARKING.md` Rule 0: a benchmark is only worth running if it can
disappoint us. So commit, in writing, before the first number:

- **Expected:** the tool-loop (treatment) beats re-prefill (baseline) on
  end-to-end wall time, and the margin **grows** with `--prefix-tokens`
  and `--hops`.
- **Control:** at `--prefix-tokens 50 --hops 1` the two arms should be
  **close** — little to no advantage. If the tiny-prefix case already
  shows a large win, the harness is rigged; stop and find the bug.
- **A flat or <1x result at large prefix/hops is a real negative.** Record
  it in the report; do not tune the baseline to make it disappear.

Write these expectations into the report file first, then run. This is the
whole discipline — the number is allowed to prove us wrong.

---

## Step 1 — install the native extra and get a model

```bash
# In a clean venv on the hardware:
pip install -e ".[native,embeddings]"     # pulls llama-cpp-python (native build)
```

If `llama-cpp-python` fails to build, that is a toolchain problem, not a
Palimpsests problem — install a prebuilt wheel for the platform/CUDA, or
provide a compiler. Record the EXACT installed version:

```bash
python -c "import llama_cpp; print(llama_cpp.__version__)"
```

Get a small GGUF (a 1–3B model is enough to validate correctness; size up
only once it runs). Note the file, the quant, and where it came from — all
three go in the report.

---

## Step 2 — pin the API surface (the version shims)

`llamacpp_backend.py` was written blind and guards three known
cross-version differences with runtime shims. Confirm which branch the
installed version actually uses and record it in the module's
"Validated against:" docstring line:

1. **Module path.** `from llama_cpp import llama_cpp as _lib`. If the
   symbols live elsewhere in this version, fix the one import.
2. **Vocab handle** (`_resolve_vocab`): does `llama_model_get_vocab`
   exist? If yes, tokenize/detokenize take the vocab; if not, the model.
3. **KV op names** (`_seq_op`, `_memory`): `llama_memory_seq_*` +
   `llama_get_memory`, or the older `llama_kv_cache_seq_*` on the context?
4. **state_seq signatures**: do `llama_state_seq_get_data` /
   `set_data` take the `size` argument in this version? (See the comments
   in `state_get` / `state_set`.)

A five-line script that just constructs `LlamaCppBackend(model_path)` and
prints success is the fastest way to shake out 1–3, because construction
touches model load, context creation, and vocab resolution.

---

## Step 3 — validate the backend in isolation, primitive by primitive

Do **not** start with the benchmark. Validate the backend against the
same expectations the FakeBackend encodes, one primitive at a time, so a
failure is unambiguous. Suggested order (cheapest/most-fundamental first):

1. **tokenize / detokenize round-trip.** `detokenize(tokenize(s))` should
   recover `s` (modulo whitespace/normalization). If the two-call buffer
   sizing is wrong, this is where it shows — cheaply.
2. **single-token decode.** One `BatchEntry`, one token, `start_pos=0`,
   `wants_logits=True`. Assert the returned dict has the seq_id and a
   logits vector of length `n_vocab`. This proves the batch builder, the
   logits-flag placement, and `llama_get_logits_ith` indexing on the
   simplest possible input — THE highest-risk code on its easiest case.
3. **multi-token prefill.** One entry with K tokens; only the last should
   carry logits. Confirms the `is_last` logic and pos assignment.
4. **two-sequence batch.** Two entries in one `decode`. Confirms
   `seq_id`/`n_seq_id` array shape and that logits demux by seq_id.
5. **seq_copy + seed position.** Warm a holder, copy to a slot, decode
   the slot at the seeded position; output should be coherent. A wrong
   `pos` here is the silent-corruption trap — the output will look like a
   broken model, so watch for garbage, not for an exception.
6. **state_get / state_set round-trip.** Save a slot, mutate/close, set it
   back, continue; the continuation should match an uninterrupted run.

Only when 1–6 pass does the scheduler's behavior (already CI-proven on the
fake backend) hold on the real one. If a step fails, the fix is local to
one method by construction.

---

## Step 4 — smoke the scheduler/session on the real backend

Run the existing session flow (a `NativeSession.send`, then an
`append_tool_result`) against the real backend with a tiny prompt. This is
the integration check: the pure-Python control logic that CI proved on the
fake backend now driving real KV. Expect nothing surprising if Step 3
passed — but run it before benchmarking so a benchmark anomaly can't be
confused with an integration bug.

---

## Step 5 — run the benchmark and sweep the variable

```bash
# control first — expect the arms to be close:
python benchmarks/bench_tool_loop.py --model MODEL.gguf --prefix-tokens 50 --hops 1 --repeats 5

# then the sweep the claim lives on — expect a growing margin:
python benchmarks/bench_tool_loop.py --model MODEL.gguf --prefix-tokens 500  --hops 4 --repeats 5
python benchmarks/bench_tool_loop.py --model MODEL.gguf --prefix-tokens 2000 --hops 8 --repeats 5
python benchmarks/bench_tool_loop.py --model MODEL.gguf --prefix-tokens 4000 --hops 12 --repeats 5
```

One variable at a time (`docs/BENCHMARKING.md` §2): change prefix size OR
hop count between runs, not both when isolating an effect. Keep every
JSON blob the script prints; paste it beside the environment in the
report.

A real EOS matters: the benchmark currently passes `stop_tokens=()` and
relies on the `max_tokens=32` cap, so both arms generate a fixed count —
fine for a wall-time comparison, but note it. Reading the model's true EOS
and passing it makes the loop end naturally; do that before quoting TPOT.

---

## Step 6 — record, and let it land in POSITIONING

For each configuration, record (per `docs/BENCHMARKING.md` §5): median +
spread over repeats, the full environment, the model + quant, and every
flag. Then:

- If the claim holds: replace the corresponding **target** row in
  `docs/POSITIONING.md` with a **measured** row — clearly relabeled
  "measured, our hardware," with the environment — and cut 0.4.
- If it does not: record the negative in POSITIONING just as plainly, and
  in `docs/ROADMAP.md` note where the advantage did and did not appear.
  A measured negative is a v0.4 deliverable too — it is the stand doing
  its job.

The point of v0.4 is not "show a win." It is "produce our first honest
number, whatever it says." That number — win or not — is what lifts the
level-3 features from an implemented mechanism (TRL ~3) to one
demonstrated in a relevant setting (TRL ~4–5), and it is worth far more to
a technical evaluator than another unmeasured target.

---

## Known first-run failure modes (quick index)

| Symptom | Most likely cause | Where |
|---|---|---|
| `AttributeError` on construct | vocab/memory/module name differs this version | Step 2, `_resolve_vocab` / `_memory` |
| `TypeError` on state calls | `size` arg present/absent this version | `state_get` / `state_set` |
| garbage output, no exception | wrong `pos` (start_pos) in the batch | `decode`, pos assignment |
| logits wrong length / KeyError | logits flag on wrong token, or index bug | `decode`, `is_last` + `get_logits_ith` |
| truncated / wrong tokens | two-call buffer sizing wrong | `tokenize` |
| OOM on context create | `n_ctx` × `n_seq_max` too large for VRAM | Step 1, shrink both |
