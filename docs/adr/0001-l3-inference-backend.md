# ADR-0001: Level-3 inference backend

- **Status:** Accepted
- **Date:** 2026-07-06
- **Context level:** Level 3 (`pal-native`) — the own inference service
- **Supersedes / superseded by:** —

## Context

Levels 1 (Ollama) and 2 (llama.cpp via a managed `llama-server`
subprocess) are shipped. Level 3 is the own inference service: continuous
batching, shared-prefix KV, a server-side tool loop, and KV-as-memory
persistence (see `ARCHITECTURE.md` §5).

The governing invariant (`ARCHITECTURE.md` §8) is that **we do not modify
the attention kernel**. Level 3 is therefore *state management around a
forward pass*, not an own forward pass. That leaves one decision that
shapes the entire level: **what performs the forward pass, and does its
API give us enough control to build the level-3 features on top of it?**

Three candidate backends were on the table:

1. **llama.cpp as a library** (direct bindings to its C API), reusing the
   same GGUF models level 2 already runs.
2. **A Rust stack** (candle / mistral.rs) — cleaner for an "own server",
   but a second language in the project and a slower forward pass than
   an optimized llama.cpp.
3. **An own decode kernel** — maximum control, but it violates the
   no-attention-kernel invariant and is the least differentiated,
   hardest part of the stack.

Getting this wrong is cheap now and very expensive later, so it was
de-risked with a spike (**S1**) before committing to any server code.

## The spike (S1)

S1 did **not** build a server or run a model. It answered three control
questions from the ground truth — the public `llama.h` C API — and
confirmed the same primitives are exposed by the Python low-level
bindings (`llama_cpp.llama_cpp` in `llama-cpp-python`). Each question maps
directly to a level-3 feature slot.

### S1.1 — Multi-sequence batching (continuous batching, §5.1)

**Answer: yes, first-class.** `llama_batch` carries per-token sequence
IDs:

```c
typedef struct llama_batch {
    int32_t        n_tokens;
    llama_token *  token;
    llama_pos   *  pos;
    int32_t     *  n_seq_id;
    llama_seq_id ** seq_id;   // <- per-token sequence id
    int8_t      *  logits;
} llama_batch;
```

A single `llama_decode` processes tokens from several sequences in one
forward pass; `llama_batch_init(..., n_seq_max)` and the context's
`n_seq_max` size the batch. This is exactly what the scheduler needs.

### S1.2 — Per-sequence KV save/restore (tool loop §5.3, KV-memory §5.5)

**Answer: yes, direct.**

- `llama_state_seq_get_data(ctx, dst, size, seq_id)` — serialize one
  sequence's KV to a buffer → the `save_state() -> bytes` primitive.
- `llama_state_seq_set_data(ctx, src, size, dest_seq_id)` — deserialize
  into a sequence → `load_state(bytes)`.
- `llama_state_seq_save_file` / `llama_state_seq_load_file` — direct file
  I/O, mapping straight onto the shared `.context-memory/` store.

The tool loop (pause decode with KV preserved, resume without re-prefill)
and KV persistence both fall out of these.

### S1.3 — Cross-sequence prefix sharing (shared-prefix KV, §5.2)

This was the *historically weak spot* and the reason a spike was needed.
**Answer: yes — the limitation is gone.**

```c
LLAMA_API void llama_memory_seq_cp(
    llama_memory_t mem,
    llama_seq_id   seq_id_src,
    llama_seq_id   seq_id_dst,
    llama_pos      p0,
    llama_pos      p1);
```

`llama_memory_seq_cp` copies KV cells from one sequence to another over a
position range. Compute the system-prompt KV once in sequence 0, then
broadcast it into each session's sequence — no recompute. The context
even exposes a `kv_unified` flag whose documentation is framed around
whether "sequences share a large prefix", i.e. the library is designed
with cross-sequence prefix sharing in mind.

### Reference implementation

`llama.cpp`'s own `examples/parallel/parallel.cpp` already combines
continuous batching with shared-prefix KV — precisely the N3+N4 shape of
our plan:

```c
llama_memory_t mem = llama_get_memory(ctx);
// system prompt decoded into sequence 0, then broadcast to each client:
llama_memory_seq_cp(mem, 0, i, -1, -1);   // (-1,-1) copies the whole prefix
// when a client finishes and a new one starts:
llama_memory_seq_rm(mem, i, -1, -1);      // clear that client's KV
llama_memory_seq_cp(mem, 0, i, -1, -1);   // re-seed from the shared prefix
client.n_past = n_tokens_system;          // decode resumes after the prefix
```

We are not first-movers on this path; there is a canonical reference to
port from.

## Slot → primitive mapping

| Level-3 slot (§5)            | llama.cpp primitive                                   | Status          |
| ---------------------------- | ----------------------------------------------------- | --------------- |
| §5.1 continuous batching     | `llama_batch` per-token `seq_id` + `llama_decode`     | direct          |
| §5.2 shared prefix KV        | `llama_memory_seq_cp(mem, src, dst, p0, p1)`          | direct + ref    |
| §5.3 server-side tool loop   | `llama_state_seq_get_data` / `llama_state_seq_set_data` | direct        |
| §5.5 KV-as-memory            | `llama_state_seq_save_file` / `llama_state_seq_load_file` → `.context-memory/` | direct |

## Decision

**Level 3 builds on llama.cpp via its low-level C API** (the
`llama_cpp.llama_cpp` ctypes bindings), reusing the same GGUF models as
level 2.

- The **Rust fallback (candle / mistral.rs) is not needed** — S1 did not
  hit a wall; the one historically weak area (prefix sharing) is solved
  by `llama_memory_seq_cp`.
- An **own decode kernel is explicitly rejected** — it would break the
  no-attention-kernel invariant and is the least differentiated work in
  the stack. Our differentiation is the *state management* around the
  forward pass (scheduler, prefix tree, KV persistence, tool loop), not
  the forward pass itself.

## Consequences

- We use the **low-level ctypes module** (`llama_cpp.llama_cpp`), not the
  high-level `Llama` convenience class, which does not expose
  sequence-level KV control ergonomically. This is expected for an own
  server loop.
- Building `llama-cpp-python` from source needs a C toolchain / CMake;
  level 3 relies on prebuilt wheels or a user-provided toolchain — the
  same "native dependency out-of-band" posture as level 2, kept
  consistent.
- The plan's contested checkpoint (shared-prefix KV, step N4) is
  **de-risked ahead of implementation**: the primitive exists and a
  reference implementation is available.
- The first implementation step (N1) is a `NativeServer` skeleton with a
  **batch-ready loop at N=1**, structured as `queue → scheduler →
  batched decode-step → demux`, so that enabling N>1 later is an unlock,
  not a rewrite. The reusable `ProcessManager` is extracted from
  `providers/process.py` at that point (the second concrete process
  lifecycle).

## Notes

- S1 was an API-surface spike: it inspected `llama.h` and the Python
  binding definitions; it did not build the library or run a model. The
  capability questions it answered are about API control, which is what
  determines architectural feasibility. Throughput and correctness under
  real load are for the N1+ implementation, on real hardware.
- One open decision remains for N1 and is **not** settled by this ADR:
  whether `NativeServer` runs in-process (direct access to `mem` /
  `seq_cp` / `state_seq` with no serialization) or as a subprocess (as
  level 2 does). The low-level API argues for in-process to keep the KV
  control that is the whole point of level 3; to be decided when N1
  starts.
