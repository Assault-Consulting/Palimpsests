# Changelog

All notable changes to Palimpsests are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0. Before v1.0, minor versions may include breaking
API changes.

## [0.2.0] — 2026-07-06

The three-level architecture is now structurally complete: all three
control levels exist behind one `InferenceEngine` contract.

### Added

- **Level 2 — llama.cpp adapter (`LlamaCppEngine`).** The first *control*
  level: Palimpsests spawns and owns a `llama-server` subprocess, so the
  full `EngineMemoryConfig` (context size, GPU offload, flash attention,
  KV-cache quantization, mmap, draft model) is applied as real launch
  flags rather than ignored. Two modes: spawn (own the server from a
  model path) and attach (talk to a user-run server by URL). Opt-in via
  `PALIMPSESTS_LLAMACPP_MODEL`.
- **Managed subprocess lifecycle (`LlamaServerProcess`).** Free-port
  allocation, spawn, readiness by health poll, early-death detection, and
  idempotent shutdown — scoped to `llama-server` for now.
- **Level 3 slot — `NativeEngine`.** A registered, honest placeholder:
  `control_level=3` with every feature flag `False`, every operation
  refusing with `CapabilityUnsupported`, and `is_available()` `False`.
  The serving service (continuous batching, shared-prefix KV, server-side
  tool loop, KV persistence) is not implemented yet.
- **Block-memory retrieval (`BlockMemory`).** Evicted context is embedded
  and stored in SQLite; the most relevant blocks are retrieved back on
  demand (numpy cosine, no vector DB). Injectable embedder, defaulting
  through the active engine's `/api/embeddings`. Backing store shared with
  future KV persistence under `<workspace>/.context-memory/`.
- **Block memory wired into the chat flow.** `chat` now stores evicted
  messages and, lazily (only when eviction happened), retrieves relevant
  blocks back as a single prepended system message. Graceful: without an
  embed-capable engine or numpy, chat behaves exactly as before.
- **Ollama embeddings.** `OllamaEngine.embed()` exposes `/api/embeddings`,
  the default source for block-memory vectors.
- **`docs/USAGE.md`** — a run + settings guide for the current state.

### Changed

- `AppContext.engines` widened from `OllamaEngine` to the `InferenceEngine`
  protocol now that multiple adapters coexist. Callers read capabilities,
  never the concrete type, so nothing downstream changed.
- The `[llamacpp]` extra is now empty and documented: the server-subprocess
  approach needs the `llama-server` binary out-of-band, not a Python
  package. `numpy` moved to its own `[embeddings]` extra (and `[dev]`).
- Development status classifier is Beta; README, roadmap, and install
  instructions updated to reflect levels 1–2 shipped and the level-3 slot.

## [0.1.0] — 2026-07-06

Initial release.

### Added

- **Level 1 — Ollama adapter (`OllamaEngine`).** Thin HTTP client to an
  external Ollama daemon: streaming chat, model listing, availability
  probe, and the subset of `EngineMemoryConfig` Ollama honors.
- **The engine contract.** `InferenceEngine` protocol, `BaseInferenceEngine`
  (derives `chat` from `chat_stream`, refuses sessions by default),
  `EngineCapabilities`, `EngineMemoryConfig` (with the flash-attention
  prerequisite for KV-quant enforced), and the level-3 `InferenceSession`
  protocol.
- **Context-window manager.** Sink/window/evict fitting to a token budget,
  reporting what it evicted.
- **Registry** — one active engine globally (radio, not checkbox).
- **Audit log** — append-only, encrypted at rest (SQLCipher) with a key
  from the OS keychain, falling back to an ephemeral key headless.
- **CLI** — `chat`, `models`, `engine list` / `engine use`.

[0.2.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.2.0
[0.1.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.1.0
