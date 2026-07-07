# Palimpsests

**A layered local-LLM inference engine: from thin wrapper to your own serving service, under one abstraction.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-pending-lightgrey.svg)](#)
[![PyPI](https://img.shields.io/badge/PyPI-unreleased-lightgrey.svg)](#)

> **Status: v0.2, with the level-3 skeleton complete.** Levels 1 (Ollama) and 2
> (llama.cpp) work behind one abstraction, with the context-memory layer (window
> manager + block-memory retrieval) and an encrypted audit log. Level 3
> (pal-native) now has its full serving skeleton — streaming, stateful sessions,
> continuous batching, server-side tool loop, shared-prefix KV, and KV
> persistence — implemented and test-covered against a fake backend behind the
> ADR-0002 seam. The real in-process `LlamaCppBackend` (and the first on-hardware
> benchmarks) are the next step. APIs may change before v1.0.

---

## What this is

Ollama and llama.cpp are optimized for one question: *how fast can I answer a
single request?* A growing class of workloads has a different shape — **agentic
workloads**: a process that makes hundreds of calls in a loop, shares one system
prompt across calls, retries, branches, and invokes tools. That is a different
profile than single-request throughput, and the tools tuned for single requests
leave the agentic-specific wins — reusing a shared prefix, not re-prefilling
across a tool loop, persisting KV between sessions — on the table.

Palimpsests gives you **three levels of control** over local inference behind a
**single `InferenceEngine` abstraction**, plus a **context-memory layer** that
works the same on all three levels.

```
Level 1  ·  ollama       →  thin HTTP client to an external daemon
                            (max compat, zero control)
Level 2  ·  llamacpp     →  embedded engine via subprocess
                            (control over quant, KV cache, offload)
Level 3  ·  pal-native   →  own serving service (continuous batching,
                            shared prefix KV, server-side tool loop,
                            KV persistence)
```

You move from level 1 to level 3 **without changing the code above the engine.**
Callers ask `engine.capabilities`, never `isinstance`.

The name is the mechanism: a *palimpsest* is a parchment scraped clean and
rewritten, where the old text still shows through. That is exactly what the
context-memory layer does — it evicts the middle of the context (scrapes),
writes new content into the window, but the evicted text bleeds back through
retrieval. At level 3 the same image applies to KV state.

---

## What it does

- **Long context on small models without OOM.** The context-memory layer keeps a
  stable *sink* (system prompt + first turns) and a recent *window*, evicts the
  middle to disk, and retrieves relevant blocks back on demand. A 7B model with
  an 8K real context serves a conversation far longer than 8K — the ceiling is
  disk, not RAM.
- **One API, three engines.** Prototype on Ollama, take fine-grained control with
  llama.cpp, run the native service — the calling code above the engine does not
  change. The same context-memory layer runs identically on all three.
- **Agentic-workload serving at level 3.** Continuous batching, a shared system
  prompt decoded once and copied rather than recomputed per session, a tool loop
  that continues in-place without re-prefilling the conversation, and KV state
  that persists and is reusable by content. These are the levers that matter when
  a process makes hundreds of calls in a loop, not one.
- **Local-first, air-gap capable, auditable.** Inference runs on-host; nothing
  leaves the machine to answer a request. Every model and KV operation is
  recorded to an encrypted, tamper-evident audit log. This is the sharp edge for
  **regulated and sensitive deployments** — see **[Regulated / air-gapped
  deployments](#regulated--air-gapped-deployments)** below.
- **Memory mechanisms, exposed not reinvented.** KV-cache quantization, flash
  attention, GPU offload, mmap trade-offs — surfaced as declared capabilities
  per engine, validated (e.g. KV-quant requires flash attention).

---

## Scope: what it deliberately does not touch

Palimpsests works **above the attention kernel**, not inside it. It composes
llama.cpp's existing primitives (batched decode, per-sequence KV save/restore,
shared-prefix copy) into serving policy; it orchestrates context above the
engine; it manages KV state at level 3. It does **not** modify the attention
math, write custom CUDA kernels, or change how a forward pass is computed — that
is a different project (and a different risk profile). Drawing this line
deliberately is what keeps the claims verifiable: everything the project asserts,
it can demonstrate.

It is also an **inference library, not a certified compliance product** — it
provides primitives designed to help address regulatory obligations, but using
it does not by itself make a deployment compliant. See
**[SECURITY.md](SECURITY.md)**.

---

## Install

```bash
pip install palimpsests                # base: level 1 (Ollama) + context-memory
pip install "palimpsests[embeddings]"  # + numpy, for block-memory retrieval
```

Level 2 (llama.cpp) needs the `llama-server` binary on your `PATH` — Palimpsests
spawns and manages it as a subprocess, so there is **no native pip build**.
Install it out-of-band (`brew install llama.cpp`, a release binary, or your own
GPU build) and point Palimpsests at a model:

```bash
export PALIMPSESTS_LLAMACPP_MODEL=/path/to/model.gguf   # enables level 2
```

The `[llamacpp]` extra is an empty, documented marker — the Python side needs
only `httpx`, which the base already pulls.

## Quick start

Requires a running [Ollama](https://ollama.com) daemon for level 1.

```bash
# talk to a model (prompt via -m, or piped over stdin)
palimpsests chat qwen2.5:7b -m "explain KV cache quantization in two sentences"
echo "same, but piped" | palimpsests chat qwen2.5:7b

# give a long conversation a smaller context budget (sink/window/evict kicks in)
palimpsests chat qwen2.5:7b -m "..." --context-size 4096

# list models the active engine can see
palimpsests models

# inspect engines (control level, installed, * = active) and switch
palimpsests engine list
palimpsests engine use llamacpp
```

Or drive the same orchestration from Python, without the terminal:

```python
from palimpsests.core import init_app, chat

ctx = init_app()
messages = [{"role": "user", "content": "hello"}]
for chunk in chat(ctx, model="qwen2.5:7b", messages=messages):
    print(chunk.delta, end="", flush=True)
```

The `chat` function fits the conversation to the context budget (sink + window +
evict) before it reaches the engine, and records the call to the audit log —
you get context management and auditability without wiring them yourself.

**Full run + settings guide:** **[docs/USAGE.md](docs/USAGE.md)** — every
command, every working setting (`--context-size`, environment variables, adapter
timeouts, `EngineMemoryConfig`), the Python API, and troubleshooting.

---

## Architecture in one screen

- **`engine/`** — the `InferenceEngine` Protocol, `InferenceSession` (level-3
  stateful sessions), `ChatChunk` / `ChatResponse`, `EngineCapabilities`,
  `EngineMemoryConfig`. `chat()` is derived from `chat_stream()` — adapters
  implement streaming only.
- **`providers/`** — engine adapters: `ollama` (L1), `llamacpp` (L2),
  `native` (L3: scheduler + session + prefix holders + KV store).
- **`context/`** — context-memory: `window_manager` (sink + window + evict) and
  `block_memory` (evicted text → embeddings → retrieval), sharing one backing
  store with KV persistence.
- **`registry.py`** — one active engine globally (radio, not checkbox).
- **`audit/`** — every model / KV operation is auditable.

Full design: **[ARCHITECTURE.md](ARCHITECTURE.md)**. Positioning, audiences, and
performance targets: **[docs/POSITIONING.md](docs/POSITIONING.md)**.

---

## Regulated / air-gapped deployments

Palimpsests is aimed, in part, at teams for whom *where inference runs* and
*whether the audit trail can be trusted* matter as much as raw speed — finance,
defense, healthcare, public sector.

- **Local-first / air-gap capable** — no request content leaves the host; no
  third-party call is needed to answer a request. Data residency on hardware you
  control.
- **Encrypted, tamper-evident audit log** — every model and KV operation is
  recorded to an encrypted store (SQLCipher, key in the OS keychain), so the
  trail's integrity can be demonstrated, not merely asserted.

These map onto real obligations. The **EU AI Act** (Regulation (EU) 2024/1689)
makes automatic, lifetime event logging a legal requirement for high-risk systems
(**Article 12**) with a **six-month minimum retention** (Article 26(6)) — and an
autonomous tool-calling agent is a strong candidate for the high-risk (Annex III)
classification. Article 12 does not say *tamper-proof*, but a silently-alterable
log has little evidentiary value in an audit; a tamper-evident trail targets that
gap.

**This is not a compliance claim.** The project is not certified, the audit log
has not been independently pen-tested, and the AI Act's own technical standards
are not yet final. Full references, caveats, and the moving timeline are in
**[SECURITY.md](SECURITY.md)**; the honest target-vs-measured performance picture
is in **[docs/POSITIONING.md](docs/POSITIONING.md)**.

---

## Prior art & the gap we close

We mapped the landscape before building, and hold it in view so the project rests
on a real, defensible gap rather than a false sense of novelty. Every *component*
below exists somewhere. What does **not** exist is any single system that
composes all of them under one abstraction, specialized for agentic edge
workloads, cross-platform.

| Stack component | Where it exists today | The limit |
|---|---|---|
| Provider abstraction (L1–2) | LM Studio, Jan, ServiceStack AI Server | wrappers only — no native serving level below them |
| Sink/window context | StreamingLLM; practical guides | a technique, not a product that also does the rest |
| Block retrieval of evicted context | many memory / RAG projects | not integrated with a KV-managing serving loop |
| Continuous batching on edge | Clairvoyant (sidecar); vLLM/SGLang (datacenter) | datacenter-scale or a bolt-on, not a local library |
| Shared-prefix KV | vLLM, SGLang | server-class, not exposed as a local, cross-platform policy |
| KV persistence as memory | oMLX (macOS); *Persistent Q4 KV Cache*, arXiv 2603.04428 | Apple/MLX-only, or a research artifact — persistence alone |

**The gap, stated positively:** no tool combines continuous batching +
shared-prefix KV + KV-persistence under a single engine abstraction, specialized
for agentic edge workloads, and portable across platforms. The nearest single
system by substance is **oMLX** — and it covers only the KV-persistence facet,
only on Apple Silicon, without the three-level abstraction or the context-memory
layer.

**Why this composition is hard, not just assembled.** The difficulty is not
finding the pieces; it is that they fight each other unless the seams are
designed. Three levels with genuinely different control surfaces (an external
daemon, a managed subprocess, an in-process serving loop) have to present *one*
`InferenceEngine` contract, so callers query `capabilities` and never branch on
engine identity. The context-memory layer has to behave identically whether it
sits above an opaque HTTP daemon or above KV state we own directly. Shared-prefix
reuse and KV persistence have to share the *same* position-tracking substrate
(`n_past` / `start_pos`) as continuous batching, or a restored or copied KV lands
at the wrong position and silently corrupts output. And it has to hold on
commodity local hardware, not a datacenter. That coordination — the seams, the
one substrate under several features, the single contract over three control
models — is the system-level work. "Integration" undersells it; it is
architecture.

The honest scope line still holds (see [Scope](#scope-what-it-deliberately-does-not-touch)):
the novelty is in this composition and its seams, not in a new inference kernel.

---

## Roadmap

- [x] **v0.1** — Level 1 (Ollama) + context-memory window manager + CLI +
      audit/registry foundation
- [x] **v0.1.x** — block-memory retrieval of evicted context, wired into the
      chat flow
- [x] **v0.2** — Level 2 (llama.cpp) with the full `EngineMemoryConfig` applied
      as launch flags to a managed `llama-server`; level-3 slot registered
- [x] **Level-3 skeleton (fake backend)** — the pal-native serving loop, complete
      behind the ADR-0002 seam: streaming → stateful sessions → continuous
      batching → server-side tool loop → shared-prefix KV → KV persistence →
      content-addressed KV store. All six capability flags true.
- [ ] **Real `LlamaCppBackend` + first benchmarks** — the ctypes backend on
      hardware, measured against a tuned baseline under
      [docs/BENCHMARKING.md](docs/BENCHMARKING.md).
- [ ] **Beyond the skeleton** — sleep-time compute (edge), disk-backed KV store,
      speculative decoding. See [docs/ROADMAP.md](docs/ROADMAP.md).

Each level graduates by flipping the corresponding `capabilities` flag from
`False` to `True`. A flipped flag means the *mechanism* is implemented and
tested — **not** that a speedup has been measured; that is the benchmarking phase.

---

## Contributing

Early, but PRs and issues welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md).
Python code lands via PR (never direct to `main`); ruff `["E","F","I","B","UP"]`,
line length 100, Python 3.11+, pytest.

Security issues: please report privately — see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
