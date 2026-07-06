# ADR-0002: Level-3 server runs in-process; the N1 test boundary

- **Status:** Accepted
- **Date:** 2026-07-06
- **Context level:** Level 3 (`pal-native`)
- **Depends on:** ADR-0001 (backend is llama.cpp via its low-level C API)

## Context

ADR-0001 settled *what* performs the forward pass (llama.cpp via its
low-level C API). This ADR settles *where* it runs and *how* the first
implementation (N1) is tested, because both shape the N1 skeleton and are
expensive to get wrong.

### Decision 1 — in-process, not a subprocess

Levels 1 and 2 wrap someone else's ready server (Ollama, `llama-server`)
and talk to it over HTTP, so a subprocess is the natural form there.
Level 3 is different: its entire value is direct control over KV state —
`llama_memory_seq_cp`, `llama_state_seq_get_data/set_data`,
`llama_decode` over a multi-sequence `llama_batch`. Those are C-API calls
against an in-memory context object.

A subprocess would not remove those calls — we still make them via the
bindings — it would only insert a wire protocol *between us and the calls
we already have to make*. No off-the-shelf HTTP server (not even
`llama-server`) exposes `seq_cp` / `state_seq` over HTTP, so a subprocess
means **inventing our own KV wire protocol on top of the C API**, rather
than avoiding one. That is more work for less control, and control is the
whole point of level 3.

**Decision:** the level-3 server runs **in-process** — the model is
loaded in the same Python process via the ctypes bindings, and the
scheduler calls the KV primitives directly, with no serialization and no
wire protocol.

The known downsides are managed rather than avoided:

- **A native crash (segfault) takes the whole process down.** Accepted
  for now. Isolation, if it is ever needed, is added later as a
  subprocess *wrapper around* the finished in-process engine
  (extract-on-need), without sacrificing control today.
- **The GIL.** `llama_decode` in native code releases the GIL during
  compute (standard for ctypes calls), so the main thread is not held.
  To be verified during N1, but not a blocker.

### Decision 2 — the N1 test boundary

The project's discipline has been: verify every change on a fresh clone
with the exact CI step (clone → install → ruff → pytest) and commit
exactly what passed. N1 loads llama.cpp through ctypes and performs a
forward pass, which needs a C toolchain and a GGUF model — neither is
available in the authoring sandbox. Writing blind is not the answer;
**layering N1 so the committed code stays fully verifiable** is.

N1 is split into two layers with different verification modes:

1. **Scheduler / loop / lifecycle — pure Python, deterministic, fully
   tested in CI.** The `queue → scheduler → batched decode-step → demux`
   structure (at N=1), the session state machine, and the
   `ProcessManager` extraction. The backend sits behind an interface
   (`decode(batch) -> logits`, `seq_cp`, `state_seq_get/set`), tested
   with a **fake backend**, exactly as the fake embedder and the mocked
   `Popen` were used before.
2. **The llama.cpp ctypes backend — the real implementation of that
   interface.** A thin layer mapping the interface onto
   `llama_cpp.llama_cpp` calls. It **cannot run in CI** (no model, no
   build), so it lives behind a `[native]` extra with a lazy import, and
   CI covers only argument construction and ctypes-level mocking — the
   same posture used for the level-2 `memory_to_args` without a real
   `llama-server`.

The boundary between the two is sharp. The committed N1 PR is a
**fully-verified scheduler skeleton** plus a **thin native layer behind
mocks**. Real end-to-end decode is validated on real hardware with a
model — the same "wire-level CI + optional real-hardware smoke" pattern
established for level 2.

## Consequences

- N1 delivers a batch-ready loop at N=1 whose enabling of N>1 (N3) is an
  unlock, not a rewrite.
- `ProcessManager` is extracted from `providers/process.py` during N1 —
  the second concrete lifecycle, per the rule-of-three we committed to.
- The native backend's real behavior (throughput, correctness, GIL
  release) is confirmed outside CI, on hardware with a GGUF model.
- If in-process isolation ever becomes necessary, it is added as a
  subprocess wrapper around the finished engine, and only then does a KV
  wire protocol get designed — not before.
