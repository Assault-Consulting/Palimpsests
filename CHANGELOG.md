# Changelog

All notable changes to Palimpsests are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0. Before v1.0, minor versions may include breaking
API changes.

## [Unreleased] — 0.5.0

The audit log becomes **genuinely** tamper-evident. Prior versions
described it that way, but provided only encryption at rest and an
append-only API surface: anyone holding the key could open the database
and rewrite or delete rows leaving no trace. Encryption is
confidentiality, not integrity. This release closes the gap between the
claim and the code.

### Security (0.4.1 hardening, from the 2026-07 internal audit)

- **Per-database head anchors.** The keychain anchor entry is now scoped
  to the log's resolved path (`anchor_scope`). Previously the anchor was
  machine-global: two audit logs on one host overwrote each other's
  anchor, making an honest log verify as "replaced" — and burying a real
  alarm in false ones. Existing logs re-anchor under the scoped name on
  their first post-upgrade write; until then `verify()` reports
  `head_anchored=False` for them.
- **Anchor write failures are counted, not swallowed.** `record()` now
  tracks failed keychain writes (`AuditLog.anchor_failures`) and logs a
  one-time warning, instead of silently dropping the wholesale-replacement
  guarantee mid-run.
- **`verify()` distinguishes an unanchored tail from a replacement.** A
  stale anchor that names a row *inside* the chain is now reported as
  `anchor_lag=N` ("chain extends N rows beyond the anchor" — a crash
  between commit and anchoring, or appends without keychain access),
  while an anchor naming no row in the chain is reported as a
  replacement/rollback. Both remain `ok=False`; the diagnosis differs.
- **Error messages in audit rows are clipped** (200 chars). Exception
  text from other libraries can embed URLs with tokens or payload
  fragments, which does not belong in a metadata-only log.
- **Audit DB file permissions** tightened to owner-only (best-effort
  `0600`), which matters most for the explicitly-permitted plaintext path.
- **First-run key race closed.** `load_or_create_key` reads back the
  stored key after writing, so two processes racing through first run
  converge on one key instead of encrypting with a loser's key.
- **`set_audit_log` now takes the singleton lock** (it was declared and
  unused).
- **llama-server stderr no longer uses an unread `PIPE`** (a child that
  logs > 64 KiB would block on write and hang); stderr goes to a temp
  file whose tail is included in startup-failure errors.
- **All GitHub Actions pinned to commit SHAs** (tags are mutable refs;
  `pypa/gh-action-pypi-publish@release/v1` was a moving branch).
- **Version metadata synced**: `__version__` said 0.2.0 while
  `pyproject.toml` said 0.4.0; both now 0.4.1.

Deferred by decision: local llama-server child runs without `--api-key`
(any same-host process can reach it). Accepted for the current testing
phase; the planned split of Level 3 into a separate distribution changes
the HTTP exposure model and will revisit this.

### Added

- **Hash-chained audit records.** Every row now carries `prev_hash` and
  `row_hash = SHA-256(prev_hash || canonical(fields))`. Altering,
  deleting, or reordering any row breaks the chain. The canonical
  encoding is length-prefixed, so no field value can forge a record
  boundary, and `NULL` encodes distinctly from the empty string.
- **`AuditLog.verify()`** — walks the chain oldest-first and returns a
  `VerifyResult` naming the first row whose recorded hash or predecessor
  link fails.
- **Out-of-band head anchor.** A chain alone cannot detect *wholesale
  replacement* — an attacker with the key can rebuild a consistent chain
  from scratch. The chain head is therefore also stored in the OS
  keychain, refreshed every `anchor_every` rows (default: every write)
  and flushed on `close()`. `verify()` compares chain head to anchor.
- **`VerifyResult.head_anchored`** — states whether the replacement check
  actually ran. A passing verification with `head_anchored=False` means
  the chain is internally consistent but replacement would not have been
  caught (for example, on a host with no keychain). The flag exists so a
  passing result is never read as stronger than it is.
- **`AuditIntegrityError`** — raised when the store cannot be opened in a
  trustworthy state, distinct from a verification *result*.

### Breaking

- **A missing SQLCipher build no longer degrades silently to plaintext.**
  Previously, if `sqlcipher3` (the optional `[encryption]` extra) was not
  installed, the audit log accepted the encryption key, ignored it, and
  wrote an unencrypted database. It now raises `AuditIntegrityError`.

  To keep the previous behavior, choose it explicitly:

  ```bash
  pip install 'palimpsests[encryption]'      # preferred: actually encrypt
  # or, accepting a plaintext audit log:
  export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
  ```

  In the API, pass `AuditLog(..., allow_unencrypted=True)`. A plaintext
  log is still hash-chained: tampering remains evident, only
  confidentiality is given up.

### Fixed

- **A wrong encryption key now fails at open.** SQLCipher does not
  validate `PRAGMA key` when it is set, so a wrong key previously sailed
  past the constructor — and could initialize a *new* encrypted database
  over what looked like an unreadable one. A sanity read now forces the
  failure immediately.

### Notes

- **The honest boundary is documented, not implied.** An attacker holding
  the encryption key *and* write access to the keychain can forge the
  chain and its anchor together. Detecting that requires committing the
  chain head outside the host's trust boundary — a remote append-only
  log, a notary, a transparency log. Palimpsests does not do this and
  does not claim it. See the audit-log threat model in `SECURITY.md`,
  which also names the residual weaknesses (process-supplied timestamps,
  the `anchor_every` window, no independent audit).
- Tests for this work attack the database file directly with `sqlite3`,
  bypassing `AuditLog` entirely — an attacker does not politely go
  through a class whose API offers no mutation.

## [0.4.0] — 2026-07-08

The **empirical half of level 3**: the real in-process backend now runs a
real model on hardware, and the first benchmark our strongest claim rests
on — the server-side tool loop vs a re-prefill baseline — has been measured.
0.3.0 shipped the level-3 skeleton on a fake backend and claimed no
performance; 0.4.0 brings up the real backend and produces the first number
we can call our own. That number is a **CPU-only 1.5B mechanism sanity
check, not a representative performance figure** — see **Notes**.

### Added

- **Real `LlamaCppBackend` (the `[native]` extra).** The ctypes backend
  that maps `NativeBackend` (the ADR-0002 seam) onto llama.cpp's low-level
  C API — batched `decode`, per-sequence `seq_copy` / `seq_remove`,
  `state_get` / `state_set`, tokenize/detokenize — is now brought online
  and validated on hardware (llama-cpp-python 0.3.33, Qwen2.5-1.5B Q4_K_M,
  CPU). Construction, a tokenize round-trip, and a scheduler/session smoke
  test passed; the vocab / memory / state_seq cross-version shims resolved
  cleanly against the pinned build. The same scheduler, session, and engine
  that 0.3 tested against a fake backend now drive a real model unchanged —
  the point of the ADR-0002 seam.
- **First on-hardware measurement — tool loop (N5) vs re-prefill**
  (`benchmarks/bench_tool_loop.py`, `results/report.md`,
  `results/REPRODUCE.md`). Both arms decode the same content through the
  same backend/model/sampling; the only variable is state control (live KV
  vs re-prefilling the conversation each hop). Result: near-parity at the
  control (1.08× at ~27 prefix tokens, 1 hop) growing to ~7× at ~2979
  prefix tokens / 12 hops, with TTFT near-identical between arms — the win
  comes from avoided re-prefill, and it scales with the re-prefill work
  removed. Expectations were pre-registered before the first number, per
  `BENCHMARKING.md` Rule 0.
- **`benchmarks/RUNBOOK.md` and `benchmarks/config.html`.** The
  hardware-bring-up checklist (primitive-by-primitive backend validation,
  then the benchmark sweep, control first) and a dependency-free static
  command builder for the benchmark.

### Fixed

- **`n_batch` on context creation (`LlamaCppBackend`).** On the first
  hardware run, a large single-call prefill (~3000 tokens) aborted the
  process with `GGML_ASSERT(n_tokens_all <= cparams.n_batch)` inside
  `llama_decode`, because the logical batch size was left at llama.cpp's
  default (2048). The context is now created with `n_batch = n_ctx` so the
  logical batch admits the largest prefill the context can hold. The
  measured decode logic is untouched; smaller configs were unaffected.
- **`_seq_op` version shim (`LlamaCppBackend`).** The newer/older KV
  symbol fallback (`llama_memory_seq_*` vs `llama_kv_cache_seq_*`) is now
  resolved through a small `_first_attr(lib, *names)` helper that looks up
  a runtime-chosen name, replacing a constant-attribute `getattr` chain
  (ruff B009) while preserving the cross-version dispatch intent.

### Notes

- **The measured numbers are a mechanism sanity check, not representative
  performance.** The first run was **CPU-only** (Docker, no GPU) on a
  **1.5B** model with greedy sampling. The *direction and shape* of the
  result — near-parity when there is no prefix to reuse, a growing win as
  the avoided re-prefill work grows — are the finding. Absolute magnitudes
  will differ on GPU and larger models. We do **not** present "7×" as a
  headline; a GPU / larger-model run is the pending next step, and the
  KV-persistence and shared-prefix numbers in `POSITIONING.md` remain
  external **targets** until measured the same way.
- **Cite the measured prefix, not the nominal label.** The benchmark's
  filler heuristic produces fewer tokens than the nominal config name
  (e.g. "4000" is ~2979 measured); the measured column is the honest one.
- **Positioning and roadmap** updated: `POSITIONING.md` gains a "What we
  have measured ourselves" section (clearly separated from the external
  targets), and `ROADMAP.md` moves the real-backend/first-measurement step
  into Done with a GPU/larger-model run as the next measurement priority.

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

[0.4.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.4.0
[0.3.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.3.0
[0.2.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.2.0
[0.1.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.1.0
