# Changelog

All notable changes to Palimpsests are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0. Before v1.0, minor versions may include breaking
API changes.

## [0.3.0] — 2026-07-07

The **level-3 serving skeleton is structurally complete**: all six of the
`pal-native` capability flags — `streaming`, `stateful_sessions`,
`continuous_batching`, `server_side_tools`, `shared_prefix`,
`kv_persistence` — are now `True`, implemented and test-covered against a
fake backend behind the ADR-0002 seam. This closes the *architectural*
half of level 3; the *empirical* half (a real backend and measured
performance) is deliberately deferred to 0.4 — see **Notes** below.

### Added

- **Native scheduler (`Scheduler`).** A batch-ready decode loop written
  entirely against the `NativeBackend` protocol (ADR-0002), so it is pure
  Python and fully CI-tested with a fake backend. Structure is
  `queue → batched decode-step → demux`; one `step` builds one batch from
  all active slots and calls `decode` once.
- **Stateless streaming (N1).** `chat_stream` drives a single-slot
  scheduler to completion — the level-3 `streaming` flag.
- **Stateful sessions (N3a).** `NativeSession` holds a scheduler slot
  across turns (`open_slot` / `feed` / `run_turn` / `close_slot`), so
  later turns append to live KV instead of re-prefilling — the
  `stateful_sessions` flag.
- **Concurrent session batching (N3b).** `run_sessions` /
  `Scheduler.run_batch` advance several sessions' turns in one shared
  decode loop — true continuous batching, synchronous, no async imposed
  on callers — the `continuous_batching` flag.
- **Server-side tool loop (N5).** `NativeSession.append_tool_result`
  continues the same turn after an external tool by feeding only the
  result into live KV, with no re-prefill — the `server_side_tools` flag.
- **Per-slot KV position substrate (N-pos).** Each slot tracks `n_past`;
  every decode carries `start_pos`. The invisible substrate shared-prefix
  and persistence both build on — a copied or restored KV simply starts
  at a nonzero position.
- **Shared-prefix KV (N4).** A prefix holder decodes a system prompt once
  and copies it into each session's slot instead of recomputing it
  (scheduler primitives `reserve_prefix_holder` / `warm_prefix` /
  `copy_prefix_to_slot`; engine-side registry keyed by exact prefix
  tokens, opt-in via `share_prefixes`) — the `shared_prefix` flag.
- **KV persistence (N6).** `NativeSession.save_state` / `load_state`
  serialize a session's KV to a self-contained blob (the position packed
  into a header) and restore it without re-prefilling — the
  `kv_persistence` flag.
- **Content-addressed KV store (N6b).** `KVStore` / `InMemoryKVStore`
  address a saved state by a hash of the tokens that produced it, not by
  an opaque path — "LMCache for edge," layered over N6.
- **ADR-0001 / ADR-0002.** The two decisions the level rests on: the
  backend is llama.cpp's low-level C API, and it runs in-process with the
  scheduler/session tested via a fake backend, the real one validated on
  hardware.
- **`docs/BENCHMARKING.md`, `docs/ROADMAP.md`, `docs/POSITIONING.md`.**
  The measurement protocol, the working plan, and the honest positioning
  (audiences, the regulated-sector angle, and a target-vs-measured
  performance table).
- **`SECURITY.md`, `CODE_OF_CONDUCT.md`.** A private-disclosure policy
  with a regulated-sector security posture (EU AI Act Art. 12 / 26(6)
  mapping), and the Contributor Covenant 2.1.

### Changed

- **`NativeEngine` is no longer a placeholder.** In 0.2.0 it was a
  registered stub: `control_level=3` with every flag `False` and every
  operation refusing. It now implements the full serving skeleton behind
  the fake-backend seam, with all six capability flags `True`,
  `open_session` returning a live `NativeSession`, and the prefix registry
  wired in. (This corrects the 0.2.0 note that described level 3 as "not
  implemented yet.")
- **README, roadmap, and positioning** updated to reflect the completed
  skeleton and the gap-forward positioning (a composition claim — no
  single system combines continuous batching + shared-prefix KV +
  KV-persistence under one abstraction for agentic edge workloads,
  cross-platform — with the mechanism scope stated honestly).

### Notes

- **This release is the skeleton, not a running level-3 engine on
  hardware.** Every capability flag being `True` means the *mechanism* is
  implemented and tested against a fake backend — it does **not** mean a
  real model runs through level 3, nor that any speedup has been measured.
  The real in-process `LlamaCppBackend` (behind the `[native]` extra) is
  not shipped here and is validated only on hardware with a GGUF model.
- **No performance numbers are claimed.** The figures in
  `docs/POSITIONING.md` are external published results used as orientation
  targets, explicitly labeled as such. Producing our own numbers, against
  a tuned baseline under `docs/BENCHMARKING.md`, is the point of **0.4**.
- **0.4 will be the empirical release:** the real backend, the first
  on-hardware benchmarks (starting with the tool-loop-vs-re-prefill case,
  our strongest claimed advantage), and any capability the measurements
  justify keeping or cutting.

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

[0.3.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.3.0
[0.2.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.2.0
[0.1.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.1.0
