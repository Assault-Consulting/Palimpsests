# Palimpsests — Architecture

**Status:** design document
**Scope:** the inference engine and the layers built above it

---

## 0. Thesis

Ollama and llama.cpp are optimized for one question: *how fast can I answer a
single request?* But a growing class of workloads has a different shape —
**agentic workloads**: a process that makes hundreds of calls in a loop, shares
one system prompt across calls, retries, branches, and invokes tools. That is a
different profile than single-request throughput.

Palimpsests builds **three levels of control** over local inference behind a
single abstraction, plus a **context-memory layer** that works the same on all
three levels. Levels 1–2 are "how do I cheaply run someone else's model." Level 3
is an own inference service designed for agentic, multi-session workloads on
local/edge hardware, where datacenter solutions (vLLM/SGLang) do not fit because
of their VRAM requirements.

The name reflects the central mechanism: a *palimpsest* is a parchment scraped
clean and rewritten, where the old text still shows through. That is exactly what
the context-memory layer does — it evicts the middle of the context (scrapes),
writes new content into the window, but the evicted text bleeds back through
retrieval; at level 3 the same image applies to KV state.

The governing principle of this whole document: **we do not modify the attention
kernel.** Everything we do lives either as engine launch parameters (levels 1–2),
orchestration above the engine (context-memory), or an own service with KV-state
management (level 3). Research gives us *principles*; we implement them where we
have control.

---

## 1. Three levels of control

```
Level 1: Ollama / LM Studio (external daemon)
   -> we don't control inference, only an HTTP client to someone else's server
   -> maximum compatibility, zero control over loading/quant/batching

Level 2: Embedded engine (llama.cpp via subprocess)
   -> we control loading, quant, sampling, KV cache, offload
   -> self-contained, no external daemon
   -> we depend on the upstream API

Level 3: Own wire protocol (own inference service)
   -> full control: continuous batching, shared prefix KV,
      server-side tool loop, KV persistence
   -> the most work, but this is a platform, not a wrapper
```

All three hide behind a single `InferenceEngine` abstraction. Callers never know
which level is active — they ask `engine.capabilities`, never `isinstance`.

| Level | engine_id | What it adds over the previous |
|---|---|---|
| 1 | `ollama` | Basic local inference, zero configuration |
| 2 | `llamacpp` | Fine-grained control of memory mechanisms (§3) |
| 3 | `pal-native` | Agentic-first: batching, shared prefix, tool-loop, KV-memory |

---

## 2. The abstraction and the stateless / stateful split

Two worlds, deliberately separated so the abstraction does not break when we
reach level 3:

- **stateless** (`chat()` / `chat_stream()`) — "fire and forget." Levels 1–2 live
  here entirely.
- **stateful** (`InferenceSession`) — a live session with persistent KV state.
  Exists only at level 3.

### 2.1 Data shared across all levels

- `ChatChunk` — a stream increment (`delta`, `done`, metadata in the final chunk).
  Has a `tool_call` slot for the server-side tool loop (level 3; always `None` on
  1–2).
- `ChatResponse` — the accumulated stream (non-streaming is derived for free).
- `ModelInfo` — `name`, `size_bytes`, `engine_id`, `quant`, `loaded`.
- `EngineMemoryConfig` — see §3.
- `EngineCapabilities` — the adapter's capability declaration (drives orchestration).

### 2.2 `EngineCapabilities` — behavior via data, not types

The orchestrator asks `engine.capabilities.server_side_tools`, **not**
`if isinstance(engine, ...)`. Adding level 3 means raising flags in one place;
call sites do not change.

```
control_level: int            # 1 | 2 | 3
streaming: bool
stateful_sessions: bool       # holds KV between calls          (level 3)
shared_prefix: bool           # shared prefix KV across sessions (level 3)
server_side_tools: bool       # tool-loop without re-prefill     (level 3)
continuous_batching: bool     # N sessions in one forward        (level 3)
kv_persistence: bool          # KV to/from disk                  (level 3)
```

### 2.3 The contract

- `InferenceEngine.chat_stream(...)` — levels 1–2 implement only this.
- `InferenceEngine.open_session(...)` — level 3; on 1–2 the base class raises
  `CapabilityUnsupported` (**loud refusal, not a silent fallback**).
- `InferenceSession` — a live session: `send()`, `append_tool_result()`,
  `save_state() -> bytes`, `load_state(bytes)`, `close()`.
- `BaseInferenceEngine` — shared logic: `chat()` = accumulation of `chat_stream()`;
  the default `open_session()` raises `CapabilityUnsupported`.

**Consequence:** level 3 does not rewrite the architecture — it **fills already
existing slots**. `NativeEngine` will be the first to return a real
`InferenceSession` instead of an error; no call site above it changes.

---

## 3. `EngineMemoryConfig` — memory-reduction mechanisms (levels 1–2)

Every real memory mechanism is an **engine launch parameter**, not our logic. We
do not implement them — we **expose** them. Each adapter declares what it can do;
the UI shows only what is supported.

```
kv_cache_quant: str | None    # None | "q8_0" | "q4_0" | "turbo3"
flash_attention: bool         # PREREQUISITE for kv_cache_quant
gpu_layers: int | None        # -ngl; None = CPU-only
use_mmap: bool                # a trade-off, not a clear win
context_size: int | None      # -c; the main driver of KV size
draft_model: str | None       # speculative decoding
```

### 3.1 Production-ready in engines (we expose, not implement)

- **KV cache quantization** (`--cache-type-k q8_0/q4_0`) — the biggest practical
  win. F16 KV at 128K can OOM; q8/q4 KV lets it fit. **Requires Flash Attention**,
  otherwise KV is dequantized every step and becomes slower than no quantization
  at all.
- **Flash Attention** (`--flash-attn`) — constant attention memory regardless of
  length (tiled). Prerequisite for KV-quant.
- **Partial GPU offload** (`-ngl N`) — N layers on GPU, the rest on CPU. Runs
  models larger than VRAM. RAM does not drop automatically (mmap).
- **mmap** (default on) — weights are mapped from disk on demand; `--no-mmap`
  reduces RAM when the model is smaller than RAM but blocks loading a model larger
  than RAM.
- **Speculative decoding** — a draft model proposes, the large one verifies in
  batches. Speed, not memory.

### 3.2 Fresh, working, edge (know it, don't base on it)

- **TurboQuant for GGML** (`--cache-type-k turbo3`) — ~4.57x KV compression at
  3.5 bpw. For 13B+ on very long context, near-lossless; degrades on very small
  models. An option, not a default.

### 3.3 Research — do NOT base on this (papers, not engines)

KIVI, KVQuant, PyramidKV, XQuant rematerialization, low-rank KV,
retrieval-augmented attention (InfLLM, RetrievalAttention) at the kernel level —
mostly not in stable engine releases. A source of ideas, not a base.

### 3.4 Validation in code

`kv_cache_quant != None` requires `flash_attention == True`. This is an adapter
check with a **clear error**, not a silent performance regression.

### 3.5 Sensible defaults (consumer hardware: 16–32GB RAM, maybe a consumer GPU)

- **KV quant `q8_0` + Flash Attention** — near-lossless, meaningful savings on
  context.
- **`turbo3` KV** — for 13B+ at 128K+, with a small-model warning.
- **`context_size`** — the main lever (a direct multiplier of KV size).
- **mmap on** by default; `--no-mmap` when the model fits in RAM.
- **GPU offload** — auto-detect how many layers fit, with a manual override.

---

## 4. Context-memory — an orchestration layer above all levels

The most important layer. It works **the same** on levels 1/2/3 because it lives
at the text/message level entering the model, not in the attention kernel. This
is what makes local inference with long memory practical on consumer hardware.

```
context/
  window_manager.py    # Ideas 1+3: sink + window + evict-middle, prefix stability
  block_memory.py      # Idea 2: evicted -> embed -> retrieval (on the fs layer)
```

### 4.1 Idea 1 — the StreamingLLM principle for long context

**Research:** the first ~4 tokens ("attention sinks") absorb 45–55% of attention
mass; evicting them under a sliding window blows up perplexity ~100x. Fix: always
keep the first K tokens + a sliding window of the last W. This is already a
standard eviction technique, not our invention — we apply it at the
message-history level.

**Our implementation** (not KV, but the message-history level):

```
[SINK: system prompt + first N messages]   <- NEVER cut
[EVICTED MIDDLE: old messages]              <- eviction candidates
[WINDOW: last W messages]                   <- always kept
```

The difference from naive truncation: we keep the "sink" — the system prompt and
first exchanges that set the task structure. Implementation is a
`ContextWindowManager` above the `InferenceEngine`: a tokenizer counts fit
(`context_size`); on overflow it keeps sink+window and evicts the middle (not
lost — see §4.2).

### 4.2 Idea 2 — the InfLLM principle as block retrieval over files

**Research:** InfLLM splits context into blocks, keeps most in CPU memory, pulls
the top-k relevant ones for the current query.

**Our implementation:** retrieval not of KV blocks (kernel level) but of **text
blocks of evicted context** — the same principle one level up:

- The evicted "middle" is chunked into blocks.
- Each block is embedded by a local embedder (`nomic-embed-text` via the active
  engine).
- Blocks live in `workspace/.context-memory/` (on the fs layer); the vector index
  is a SQLite database alongside.
- Before a call: embed the query, retrieve the top-k relevant blocks, insert them
  back between sink and window.

This is effectively a RAG pattern over evicted context — a known approach applied
to our backing store. The result: memory bounded by disk, not RAM.

### 4.3 Idea 3 — prefix-cache-aware structuring (a free win)

**Research:** the prompt/prefix caching win only materializes if the prefix is
byte-stable.

**Our approach:** the sink part (system + first messages) is stable by definition
-> the prefix is always identical -> the engine reuses the prefix KV
**automatically**. So Idea 1 turns this win on for free, as long as we
deliberately keep the sink stable (no timestamps/dynamics at the start of the
prompt).

### 4.4 Layer summary

A 7B model with a real 8K context + block-memory retrieval behaves as if it had a
much longer context, without OOM, because the evicted content is on disk. The
backing store (`workspace/.context-memory/`) is deliberately shared with the
future level-3 KV persistence (§5.5) — it just stores something different
(text vs KV).

---

## 5. Level 3 — own inference service (agentic-first)

Not "run someone else's model faster" (that is 1–2), but an inference service for
agentic, multi-session workloads. All ideas below share one architectural base: a
**persistent model server with KV-state management that understands requests are
related** (a shared system prompt, related sessions). Implemented sequentially.

> **Important (see §6 Prior art):** none of the level-3 ideas are our invention.
> Continuous batching and shared prefix are standard in datacenter serving engines
> (vLLM, SGLang). SSD KV persistence already ships in a product (oMLX) and appears
> in research (Persistent Q4 KV Cache, arXiv 2603.04428). Our bet is not the
> novelty of a mechanism, but bringing these mechanisms to the local desktop under
> a single abstraction together with levels 1–2 and context-memory.

### 5.1 Continuous batching for multi-session

**Problem:** several parallel agentic sessions. On 1/2 each is a separate request
(queue, or a separate copy of the model = multiplied RAM). Ollama/LM Studio have
no continuous batching (serial dispatch, FCFS).

**Level 3:** one loaded model; the decode step processes tokens from N sessions in
one forward pass. Not full vLLM — the right scheduler for **2–8 local sessions**,
not 1000 users. Follows directly from the multi-session profile.

**Slot:** the scheduler multiplexes several `InferenceSession`s onto one model.

### 5.2 Shared prefix KV across sessions

**Problem:** sessions share a large system prompt (rules, tool definitions). On
1/2 each call recomputes the prefix KV from scratch.

**Level 3:** compute the system prefix KV **once**, keep it in memory; each session
starts from the ready prefix KV (radix-tree prefix sharing like SGLang, but at the
scale of "a few sessions share one system prompt").

**Slot:** `open_session(system_prompt=X)` — sessions with the same X share the
prefix KV.

### 5.3 Server-side tool-calling loop

**Problem:** the agentic loop is host -> engine (up to tool_call) -> parse ->
execute tool -> **new call** with the result -> engine **re-reads the whole
context**. Each tool-use iteration is a full re-prefill.

**Level 3:** the loop lives **inside** the service. The model generates a tool_call
-> decode pauses with **KV preserved** -> tool_call goes out -> the result comes
back -> decode **resumes from the same KV**, appending only the result. The context
is not re-read. For a local model where prefill is slow, this is the difference
between "usable" and "painful" on a 10-step tool loop.

**Slot:** `send()` yields a chunk with `tool_call`; `append_tool_result()`
continues from the same KV.

### 5.4 Speculative decoding with a role-specific draft model

**Research:** a draft model proposes in batches, the large one verifies; ~90 ->
180+ tokens/sec on high-context long-output.

**Level 3:** we integrate draft+target into our loop. The draft model can be chosen
per session type — a fast classifier gets an aggressive draft, long reasoning gets
a more accurate one.

**Slot:** `config.draft_model` at the `open_session` level.

### 5.5 KV states as persistent memory (catches up with oMLX, cross-platform)

At level 3 we have KV access -> instead of retrieving text and **recomputing** its
KV (as block-memory §4.2 does), we store the **KV itself** for evicted blocks to
disk and load it back ready.

**State of the world (see §6):** this already exists — oMLX does paged SSD KV
caching (safetensors, two-tier RAM/SSD), cutting TTFT from 30–90s to <5s; arXiv
2603.04428 does the same with Q4 KV on disk. **Our difference** is not discovery
but: (a) cross-platform (oMLX is Apple/MLX only), (b) integration into a single
abstraction together with levels 1–2 and context-memory, (c) a backing store
shared with the text memory of §4.2.

**Slot:** `save_state() -> bytes` / `load_state(bytes)`. The bytes go into the same
`workspace/.context-memory/` as the text blocks of §4.2 — text-memory ->
KV-memory becomes a natural transition, not a separate project.

An honest complexity assessment: this is a late-horizon feature, not a "next PR."

### 5.6 Level-3 implementation ranking

| Idea | Value | Complexity | Order |
|---|---|---|---|
| Continuous batching | Very high | Medium | 1 |
| Shared prefix KV | Very high | Medium | 1 (one architecture with batching) |
| Server-side tool loop | High | Medium-high | 2 |
| Speculative per-role | Medium | Medium | 3 (optional) |
| KV-as-memory | High | Very high | Horizon |

Ideas 1–3 share one base (persistent server + KV-state management), so once it
exists, tool-loop and KV-memory are additions on top of the same base, not
separate projects.

---

## 6. Prior art & positioning (honest analysis of analogs)

A landscape survey (as of mid-2026) showed: **no project assembles this whole
stack, but every individual piece already exists somewhere.** We invent no new
mechanism. This must stay in view so strategy is not built on a false sense of
novelty.

### 6.1 What already exists

| Stack component | State of the world | Examples |
|---|---|---|
| Provider abstraction (L1–2) | commodity | LM Studio, Jan, ServiceStack AI Server (OSS gateway) |
| Sink/window context (§4.1) | known technique | StreamingLLM; practical guides |
| Block retrieval of evicted context (§4.2) | RAG pattern | numerous memory projects |
| Continuous batching on edge (§5.1) | actively worked on | Clairvoyant (SJF sidecar-proxy for Ollama/llama.cpp); vLLM/SGLang for datacenter |
| Shared prefix KV (§5.2) | serving standard | vLLM, SGLang |
| KV persistence as memory (§5.5) | **already shipped** | **oMLX** (macOS, paged SSD KV, safetensors); arXiv 2603.04428 (Q4 KV on disk) |

### 6.2 Key findings

- **oMLX** — a macOS-native inference server on mlx-lm with paged SSD KV caching:
  cache blocks persist to disk (safetensors, two-tier RAM/SSD), survive context
  shifts and restarts without recomputation; TTFT on long context drops from
  30–90s to <5s. This is our §5.5, already in production — but Apple/MLX only, KV
  persistence alone, without the three-level abstraction or context-memory.
- **Clairvoyant** — a drop-in sidecar proxy for serial OpenAI-compatible backends,
  solving head-of-line blocking via SJF scheduling; directly attacks our §5.1
  problem (batching/queueing on consumer hardware without datacenter VRAM).
- **ServiceStack AI Server** — an OSS self-hosted gateway with multi-provider
  orchestration; our provider-abstraction level, but server-side, without
  context-memory and without levels 2–3.

### 6.3 Where the value actually is

Not technology, but **integration + positioning**:

1. **The full stack as one product.** No one has assembled "three levels of
   control under one abstraction + context-memory on all three + local-first."
   oMLX is Apple + KV-persistence only. Clairvoyant is a batching proxy only. AI
   Server is a gateway only. Palimpsests is the only one offering the full stack.
2. **Cross-platform.** The main concrete advantage over oMLX (closest by
   substance): not tied to Apple Silicon.
3. **One abstraction from wrapper to native service.** The user moves through
   levels 1->2->3 without changing code above the engine.

### 6.4 Strategic conclusion

The problem is **maturing and consolidating now**: continuous batching on edge is
being attacked, KV persistence already ships in a product, provider abstraction is
a commodity. The biggest risk is not "someone did the same thing" but "someone
assembles the integration faster." So the priority is to **assemble a working full
stack end-to-end faster than the market consolidates**, rather than perfecting each
level in isolation.

---

## 7. PR sequence

The order is deliberate: **context-memory (I3, I5) before llama.cpp (I6)** — pure
Python delivers value even at level 1, without the native-wheel CI pain, and
differentiates faster.

| PR | Name | Substance | Depends on |
|---|---|---|---|
| I1 | Inference Protocol + contracts | `InferenceEngine`, `InferenceSession`, `ChatChunk/Response`, `ModelInfo`, `EngineMemoryConfig`, `EngineCapabilities`, `BaseInferenceEngine`; registry `local_inference` + `active_inference_engine`; audit `engine_id` (nullable). Inert. | — |
| I2 | Ollama -> level-1 adapter | Port the HTTP client -> `OllamaEngine`; `chat_stream` via Ollama `stream:true`; thin re-export for compatibility. Zero behavioral diff. | I1 |
| I3 | `ContextWindowManager` | Ideas 1+3: sink/window/evict + prefix stability. Pure Python. | I1 |
| I4 | `local_chat` API / CLI | `chat`/`models`/`engine` commands; routes through `ContextWindowManager`. | I2, I3 |
| I5 | `BlockMemory` | Idea 2: evicted -> embed -> retrieval; backing `workspace/.context-memory/` + SQLite index. | I3, fs layer |
| I6 | llama.cpp level-2 adapter | `LlamaCppEngine` spawns and owns a `llama-server` subprocess (OpenAI-compatible HTTP, not the `llama-cpp-python` binding); full `EngineMemoryConfig` applied as launch flags; FA<->KV-quant validation inherited; spawn + attach modes; opt-in via `PALIMPSESTS_LLAMACPP_MODEL`; `[llamacpp]` extra is an empty marker (binary out-of-band); wire-level CI (no real llama.cpp). | I1 |
| I7 | Native wire slot | `NativeEngine` subclasses `BaseInferenceEngine`; `control_level=3` with every feature flag `False`; every operation raises `CapabilityUnsupported`; `is_available()` `False`. Honest placeholder — `ProcessManager` extracted later, on the first real native lifecycle. | I1 |

After that: sequential implementation of the level-3 features (§5) on top of the
I7 slot, in the order of §5.6.

---

## 8. Invariant principles (guardrails)

- **We do not touch the attention kernel.** Everything is engine parameters,
  orchestration, or an own service with KV management.
- **Behavior via `capabilities`, not `isinstance`.** Adding a level = flags in one
  place.
- **Loud refusal, not a silent fallback** (`CapabilityUnsupported`).
- **One active engine globally** (radio). Per-call routing comes later.
- **Subprocess-ready from day one.** Even in-process llama.cpp does not assume
  in-process in the contract.
- **A shared backing store** for text-memory (§4.2) and KV-memory (§5.5) —
  `workspace/.context-memory/`.
- **We do not claim mechanism novelty** (§6). Our bet is integration,
  cross-platform reach, and the speed of assembling the full stack.
- **Research gives principles; we implement them where we have control.**
  Kernel-level papers are a source of ideas for the application/service level, not
  a base.
