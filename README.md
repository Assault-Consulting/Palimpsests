# Palimpsests

**A layered local-LLM inference engine: from thin wrapper to your own serving service, under one abstraction.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-pending-lightgrey.svg)](#)
[![PyPI](https://img.shields.io/badge/PyPI-unreleased-lightgrey.svg)](#)

> **Status: v0.1.** Level 1 (Ollama) works end to end from the CLI, with the
> context-memory window manager and an encrypted audit log. Levels 2–3 are on
> the roadmap (see below). APIs may change before v1.0.

---

## What this is

Ollama and llama.cpp are optimized for one question: *how fast can I answer a
single request?* A growing class of workloads has a different shape — **agentic
workloads**: a process that makes hundreds of calls in a loop, shares one system
prompt across calls, retries, branches, and invokes tools. That is a different
profile than single-request throughput.

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

## Why it might be useful

- **Long context on small models without OOM.** The context-memory layer keeps a
  stable *sink* (system prompt + first turns) and a recent *window*, evicts the
  middle to disk, and retrieves relevant blocks back on demand. A 7B model with
  an 8K real context behaves as if it had a far longer one — bounded by disk,
  not RAM.
- **One API, three engines.** Prototype on Ollama, get fine-grained control with
  llama.cpp, and (eventually) run the native service — same calling code.
- **Memory mechanisms, exposed not reinvented.** KV-cache quantization, flash
  attention, GPU offload, mmap trade-offs — surfaced as declared capabilities
  per engine, validated (e.g. KV-quant requires flash attention).

---

## What this is *not*

This project **does not invent new inference mechanisms.** Everything it does
lives either as engine launch parameters (levels 1–2), orchestration above the
engine (context-memory), or a serving service with KV-state management (level
3). It never modifies the attention kernel. See **Prior art** below for an
honest accounting of what already exists.

---

## Install

```bash
pip install palimpsests               # base (level 1, context-memory)
pip install "palimpsests[llamacpp]"   # + level 2 (native wheel build)
```

> `[llamacpp]` pulls a native dependency. GPU builds (Metal / CUDA / Vulkan) are
> a runtime opt-in, not tested in CI — CPU baseline only.

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
  `native` (L3 slot).
- **`context/`** — context-memory: `window_manager` (sink + window + evict) and
  `block_memory` (evicted text → embeddings → retrieval), sharing one backing
  store with future KV persistence.
- **`registry.py`** — one active engine globally (radio, not checkbox).
- **`audit/`** — every model / KV operation is auditable.

Full design: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Prior art & positioning

We researched the landscape before writing this. The honest finding: **no single
project assembles this whole stack, but every individual piece already exists
somewhere.** We hold this in view so the project is built on integration, not a
false sense of novelty.

| Stack component | State of the world | Examples |
|---|---|---|
| Provider abstraction (L1–2) | commodity | LM Studio, Jan, ServiceStack AI Server |
| Sink/window context | known technique | StreamingLLM; practical guides |
| Block retrieval of evicted context | RAG pattern | many memory projects |
| Continuous batching on edge | actively worked on | Clairvoyant (SJF sidecar); vLLM/SGLang (datacenter) |
| Shared prefix KV | serving standard | vLLM, SGLang |
| KV persistence as memory | **already shipped** | **oMLX** (macOS, paged SSD KV); *Persistent Q4 KV Cache*, arXiv 2603.04428 |

**Where the value actually is:** integration and positioning, not a new
mechanism. The closest single tool by substance is **oMLX** — but it is Apple/MLX
only and does KV persistence alone, without the three-level abstraction or the
context-memory layer. Palimpsests' bets are (1) the **full stack as one
product**, (2) **cross-platform** (not tied to Apple Silicon), (3) **one
abstraction from wrapper to native service.**

---

## Roadmap

- [x] **v0.1** — Level 1 (Ollama) + context-memory window manager + CLI +
      audit/registry foundation *(block memory lands in a v0.1.x point release)*
- [ ] **v0.2** — Level 2 (llama.cpp) with full `EngineMemoryConfig`
- [ ] **v0.3+** — Level 3 native service, incrementally: continuous batching +
      shared prefix KV → server-side tool loop → speculative decoding →
      KV-as-memory

Each level graduates by flipping the corresponding `capabilities` flag from
`False` to `True`.

---

## Contributing

Early, but PRs and issues welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
Python code lands via PR (never direct to `main`); ruff `["E","F","I","B","UP"]`,
line length 100, Python 3.11+, pytest.

## License

[Apache-2.0](LICENSE).
