# <img src="assets/icon-dark.svg" alt="" height="30" align="center"> Palimpsests

**Local-first LLM inference with a tamper-evident, independently-verifiable audit trail — built for regulated and air-gapped deployments under the EU AI Act. The audit format is frozen; the inference is measured.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Assault-Consulting/Palimpsests/actions/workflows/ci.yml/badge.svg)](https://github.com/Assault-Consulting/Palimpsests/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/palimpsests.svg)](https://pypi.org/project/palimpsests/)
[![Python](https://img.shields.io/pypi/pyversions/palimpsests.svg)](https://pypi.org/project/palimpsests/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13534/badge)](https://www.bestpractices.dev/projects/13534)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Assault-Consulting/Palimpsests/badge)](https://scorecard.dev/viewer/?uri=github.com/Assault-Consulting/Palimpsests)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21978107.svg)](https://doi.org/10.5281/zenodo.21978107)

> **Status: v0.10 — the audit format is the deliverable, and its consumer
> surface is public.** The **[PALA-1
> format](docs/specs/pala-1/PALA-1.md)** is **frozen at v1.0**: a
> self-describing, byte-level audit format with byte-exact test vectors, a CC0
> reference implementation, a stdlib-only production codec, and the
> three-question `palimpsests pala verify` CLI — with **five independent
> verifier implementations (three external) on record** and a self-service
> [verification kit](docs/specs/pala-1/verification-kit/README.md). The writer
> emits it end-to-end with cross-boot resume; the writer APIs remain
> experimental and may change before v1.0. Verify it yourself; do not take our
> word for it — the published vectors now ship **inside the wheel**, and
> `palimpsests pala selftest` checks this build against them.
>
> Underneath sits a real local inference engine: Levels 1 (Ollama) and 2
> (llama.cpp) behind one abstraction, a context-memory layer, and a level-3
> native serving loop. That engine is **measured, not asserted** — on a
> multi-hop agentic workload the full stack runs **~3.5× over no mechanisms on
> 1.5B, rising to ~4× on 7B**, with an **8.2× session-density** crossing under a
> shared prefix, matching a tuned `llama-server` in-process without running a
> server. Method, numbers, and limits: **[Agentic serving](#agentic-serving-level-3)**
> below and **[results/](results/)**.
>
> The integrity story is in **[SECURITY.md](SECURITY.md)** and
> **[docs/ASSURANCE-CASE.md](docs/ASSURANCE-CASE.md)**; the honest
> target-vs-measured performance picture is in
> **[docs/POSITIONING.md](docs/POSITIONING.md)**.

---

## Try it in 60 seconds

No model download, no configuration — the demo runs a tiny audited agent
turn through the real level-3 stack and verifies its trail before your
eyes:

```bash
pip install palimpsests
palimpsests demo          # agent turn → PALA-1 chain → verified, narrated
palimpsests pala verify palimpsests-demo.pala   # run the auditor's check yourself
```

Then point any OpenAI-compatible client (chat shells, editor plugins,
agent frameworks) at your local engine — same interface, with an
evidence trail:

```bash
pip install 'palimpsests[serve]'
palimpsests serve         # OpenAI-compatible endpoint on http://127.0.0.1:11435/v1
```

Compliance mappings, architecture, and the assurance case are one link
deep: **[AUDIT-ARCHITECTURE](docs/AUDIT-ARCHITECTURE.md)** ·
**[EU-AI-ACT-MAPPING](docs/compliance/EU-AI-ACT-MAPPING.md)** ·
**[ASSURANCE-CASE](docs/ASSURANCE-CASE.md)** ·
**[the frozen PALA-1 spec](docs/specs/pala-1/PALA-1.md)**.

---

## What this is

Palimpsests is a **local-first inference engine whose distinguishing property is
its audit trail** — a tamper-evident, independently-verifiable log of what the
system did, in a format (**PALA-1**) that is **frozen at v1.0** and specified
byte-for-byte, so anyone can re-verify a log without trusting this software. That
is the sharp edge for **regulated and air-gapped deployments** — finance,
defense, healthcare, public sector — where *whether the audit trail can be
trusted* matters as much as raw speed.

The inference engine under that audit trail is a real one. Palimpsests gives you
**three levels of control** over local inference behind a **single
`InferenceEngine` abstraction**, plus a **context-memory layer** that works the
same on all three:

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

## Regulated & air-gapped deployments

The audit trail is not a feature bolted onto an inference library; it is the
reason the project leads with it. Palimpsests is aimed at teams for whom *where
inference runs* and *whether the log can be trusted* are first-order concerns.

- **Local-first / air-gap capable** — no request content leaves the host; no
  third-party call is needed to answer a request. Data residency on hardware you
  control.
- **Frozen, independently-verifiable format** — PALA-1 is **frozen at v1.0**,
  specified byte-for-byte with test vectors, a CC0 reference implementation, and
  five independent verifiers (three external). A log is evidence anyone can check
  from the spec alone; it does not depend on trusting this codebase.
- **Encrypted, tamper-evident audit log** — every model and KV operation is
  recorded to an encrypted store (SQLCipher, key in the OS keychain). Each row is
  chained to its predecessor by SHA-256, and the chain's head is anchored outside
  the database, so **editing, deleting, reordering, or wholesale-replacing the
  log is detectable** — `palimpsests pala verify` reports the first row that
  fails. Encryption gives confidentiality; the chain gives integrity; the anchor
  gives completeness.

  The boundary is stated plainly rather than implied: an attacker holding *both*
  the encryption key and write access to the keychain can forge the chain and its
  anchor together. Catching that would need a commitment outside the host's trust
  boundary (a remote append-only log, a notary, a transparency log), which
  Palimpsests does not provide. The full threat model, including which attacker
  capabilities are and are not detected, is in **[SECURITY.md](SECURITY.md)**.

These map onto real obligations. The **EU AI Act** (Regulation (EU) 2024/1689)
makes automatic, lifetime event logging a legal requirement for high-risk systems
(**Article 12**) with a **six-month minimum retention** (Article 26(6)) — and an
autonomous tool-calling agent is a strong candidate for the high-risk (Annex III)
classification. Article 12 does not say *tamper-proof*, but a silently-alterable
log has little evidentiary value in an audit; a tamper-evident trail targets that
gap. The **[Article 12 mapping](docs/compliance/EU-AI-ACT-MAPPING.md)** sets out,
requirement by requirement, which properties ship and which are planned — in the
claim form *"enables a provider/deployer to meet,"* not *"is compliant."* A
companion **[ISO/IEC 24970 mapping](docs/compliance/24970-MAPPING.md)** covers the
AI-logging standard (and its Annex Z presumption of conformity), and
**[docs/RETENTION.md](docs/RETENTION.md)** gives the measured storage math for the
six-month duty.

**This is not a compliance claim.** The project is not certified, the audit log's
implementation has not been independently pen-tested, and the AI Act's own
technical standards are not yet final. Full references, caveats, and the moving
timeline are in **[SECURITY.md](SECURITY.md)**; the honest target-vs-measured
performance picture is in **[docs/POSITIONING.md](docs/POSITIONING.md)**. The
structured argument that the project delivers these properties — claims, evidence,
and the explicit residuals and defeaters — is the
**[assurance case](docs/ASSURANCE-CASE.md)**.

For where the project stands against external frameworks — a self-attested
**OSPS Baseline Level 2** and **SLSA Build Level 2** release provenance, each
with its limits — see **[Standards posture](SECURITY.md#standards-posture)**.

---

## What it does

- **Local-first, air-gap capable, auditable.** Inference runs on-host; nothing
  leaves the machine to answer a request. Every model and KV operation is
  recorded to an encrypted, **hash-chained** audit log, so alteration or deletion
  is detectable rather than silent — see **[Regulated & air-gapped
  deployments](#regulated--air-gapped-deployments)** above.
- **Long context on small models without OOM.** The context-memory layer keeps a
  stable *sink* (system prompt + first turns) and a recent *window*, evicts the
  middle to disk, and retrieves relevant blocks back on demand. A 7B model with
  an 8K real context serves a conversation far longer than 8K — the ceiling is
  disk, not RAM.
- **One API, three engines.** Prototype on Ollama, take fine-grained control with
  llama.cpp, run the native service — the calling code above the engine does not
  change. The same context-memory layer runs identically on all three.
- **Agentic-workload serving at level 3.** Continuous batching plus the three
  levers a tuned server also uses, behind one API: **Shared Prefix**, **Tool
  Loop**, and **KV Persistence** — measured, not asserted (see [Agentic
  serving](#agentic-serving-level-3)).
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
pip install "palimpsests[encryption]"  # + SQLCipher, to encrypt the audit log
pip install "palimpsests[embeddings]"  # + numpy, for block-memory retrieval
```

**On the audit log.** It is always hash-chained; encryption at rest needs the
`[encryption]` extra. Without a native SQLCipher build the log **refuses to
open** rather than silently writing plaintext. If you accept a plaintext (still
chained) log, say so explicitly:

```bash
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
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

```bash
# the whole point in one command — no model, no daemon, no config:
palimpsests demo

# the OpenAI-compatible endpoint (needs the serve extra):
palimpsests serve
```

Everything below requires a running [Ollama](https://ollama.com) daemon
for level 1.

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

# verify a PALA-1 audit stream (three questions, header-only, no key needed)
palimpsests pala verify serving.pala --anchor <64-hex-head>

# export it as JSONL for inspection — the pala2json converter (spec §1.1)
palimpsests pala export serving.pala -o serving.jsonl
```

The export is **derived, never authoritative**: it carries no signature and
enters no hash — the binary PALA-1 log is the evidence, and every exported
line names its record by `seq` and `record_hash` so any claim can be taken
back to the record and re-verified there. Deterministic by design: same
container bytes, same export bytes.

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

## Agentic serving (level 3)

Ollama and llama.cpp are optimized for one question: *how fast can I answer a
single request?* Agentic workloads have a different shape — a process that makes
hundreds of calls in a loop, shares one system prompt across calls, retries,
branches, and invokes tools — and the agentic-specific wins (reusing a shared
prefix, not re-prefilling across a tool loop, persisting KV between sessions) are
left on the table by single-request tools.

Level 3 (`pal-native`) is Palimpsests' own serving loop: continuous batching plus
the three levers a tuned server also uses, behind one API —

- **Shared Prefix** — decode a shared system prompt once, copy it across sessions
  instead of recomputing it.
- **Tool Loop** — continue in place without re-prefilling the conversation
  between tool calls.
- **KV Persistence** — freeze and restore a session's KV state.

These are **measured, not asserted**, on 1.5B and 7B (iGPU/Vulkan):

- In-process, the **Tool Loop** and **KV Persistence** *match a tuned
  `llama-server`* on speed — without running a server.
- **Shared Prefix** gives an **8.2× session-density** crossing on a fixed KV
  budget; the unified KV pool behind it (`kv_unified`) ships as a first-class,
  tested backend parameter (v0.6), guarded by `PrefixHolderInUseError` against a
  release-ordering corruption a greedy chain would have hidden.
- With all three enabled the full stack runs **~3.5× over no mechanisms on 1.5B,
  rising to ~4× on 7B**, on a multi-hop agentic workload — sub-additive and
  composing without corruption.

The honest bar: on *speed* Palimpsests matches a tuned `llama-server` rather than
beating it; its edges are **session density** under a shared prefix, the
**~3.5–~4× full-stack** value of the three mechanisms together, and the
in-process, no-server, auditable deployment model. Method, numbers, and limits:
**[results/](results/)** and **[docs/POSITIONING.md](docs/POSITIONING.md)**.

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
- [x] **v0.3 — level-3 serving skeleton (fake backend)** — the pal-native
      serving loop, complete behind the ADR-0002 seam: streaming → stateful
      sessions → continuous batching → server-side tool loop → shared-prefix KV →
      KV persistence → content-addressed KV store. All six capability flags true.
      The *architectural* half of level 3.
- [x] **v0.4 — real `LlamaCppBackend` + first benchmark** — the in-process
      ctypes backend runs a real model on hardware; the first tool-loop-vs-
      re-prefill measurement lands (a CPU-only 1.5B sanity check) per
      [docs/BENCHMARKING.md](docs/BENCHMARKING.md). The *empirical* half begins.
- [x] **0.5.1 (dev) — Tool Loop benchmark campaign** — full three-arm sweeps
      (ours / naive re-prefill / tuned `llama-server`) on 1.5B and 7B
      (iGPU/Vulkan), under a transport-fair headline convention. Result: the
      Tool Loop **matches a tuned llama-server** in-process (adjusted parity on
      both models), and runs up to ~3.9× over re-prefilling with no tool loop at
      all — the value of the loop itself, *not* an edge over the server. A
      per-sequence context-budget trade-off surfaced at deep histories. Reports:
      [results/](results/).
- [x] **v0.5 — integrity & supply chain** — the audit log becomes genuinely
      tamper-evident (hash chain + out-of-band head anchor + `audit verify`),
      the KV-state deserialization path is validated and fuzzed, releases ship a
      reproducible CycloneDX SBOM and a signed GitHub Release, and the project's
      governance and a [security assurance case](docs/ASSURANCE-CASE.md) are
      documented.
- [x] **0.5 measurement campaign complete** — Shared Prefix and KV Persistence
      measured in isolation (1.5B and 7B), then a composite run (also 1.5B and 7B)
      with all three mechanisms enabled: they **compose without corruption**, are
      **sub-additive** (Shared Prefix and KV Persistence save prefill for
      *different* session subsets — cold vs resumed — so they add without
      multiplying), and the full stack runs **~3.5× over no mechanisms** (rising to ~4× on 7B),
      dominated by the Tool Loop. Shared Prefix also gives an **8.2×
      session-density** crossing on a fixed KV budget. Reports:
      [results/](results/).
- [x] **v0.6 — campaign consolidated + `kv_unified` first-class** — the
      unified KV pool ships as a supported, tested backend parameter, turning
      the 8.2× session-density crossing from a benchmark demonstration into a
      product property, guarded by `PrefixHolderInUseError` against a
      release-ordering corruption the greedy chain would have hidden.
      Positioning and the roadmap now carry the measured campaign; sleep-time
      compute is deprioritized — the differentiation is audit/compliance and
      the deployment model, not raw speed.
- [x] **v0.7 — verifiable audit: the format is the deliverable** —
      [PALA-1](docs/specs/pala-1/PALA-1.md) is **frozen at v1.0**: a
      self-describing, byte-level audit format with byte-exact test vectors,
      a CC0 reference implementation, a stdlib-only production codec, the
      three-question `palimpsests pala verify` CLI, and four independent
      verifier implementations (two external) on record; the writer emits it
      end-to-end with cross-boot resume, plus a self-service
      [verification kit](docs/specs/pala-1/verification-kit/README.md). The
      lean tag is deliberate: the format needed no more code to be finished.
- [x] **v0.8 — audit semantics + public API** — incident/oversight record
      kinds (`INCIDENT_CANDIDATE`, `OVERSIGHT_ACK` with a pseudonymous operator id,
      documented erasure), additive in the frozen profile; verifier
      advisories (referential integrity, boot-scoped monotonic drift);
      JSONL export; the `AuditReader` public API; retention guidance. See
      [docs/ROADMAP.md](docs/ROADMAP.md).
- [x] **v0.9 — the tool loop on the record + the standards groundwork** —
      profile r3 (`TOOL_CALL`/`TOOL_RESULT`, the loop-limit guard) end to end:
      spec, byte-exact companion vectors, writer, session wiring, reader
      recognition and advisories (including span pairing — the resolution of
      the fifth independent run's finding); post-freeze
      [CLARIFICATIONS](docs/specs/pala-1/CLARIFICATIONS.md); a fifth
      independent verification (Perl 5, hand-rolled NIST-validated AES-GCM).
- [x] **v0.10 — value in one command, and a public consumer surface** —
      `palimpsests demo` (an audited agent turn, verified, with no model or
      network) and the OpenAI-compatible endpoint `palimpsests serve`,
      including function calling whose every tool hop is recorded as r3 on
      every engine level; engine auto-selection. On the audit side the trail
      becomes something others can consume: the published vectors ship in the
      wheel with `pala selftest`, Merkle inclusion proofs and
      `merkle_checkpoint`, the `pala bundle` evidence bundle, time-health and
      per-boot analytics, the `pala-verification-report/1` model with a JSON
      Schema shipped beside the vectors, `pala segment` for retention, and
      [INTEGRATION-SURFACE](docs/INTEGRATION-SURFACE.md) declaring the
      stability class of every channel.
- [ ] **Later** — assurance tiers B/C (hardware root of trust, external
      witness); a discrete-GPU run (the integrated GPU flatters every
      prefill-saving mechanism, so these ratios compress on fast prefill); a
      disk-backed KV store (gated on a `state_set` MAC); speculative decoding.
      Sleep-time compute is not scheduled. See
      [docs/ROADMAP.md](docs/ROADMAP.md).

Each level graduates by flipping the corresponding `capabilities` flag from
`False` to `True`. A flipped flag means the *mechanism* is implemented and
tested; a *measured* result is a separate step. Those measurements are now in —
all three level-3 mechanisms on 1.5B and 7B, plus a composite — and they set the
honest bar: on *speed* Palimpsests matches a tuned `llama-server` rather than
beating it; its edges are **session density** under a shared prefix (8.2× on a
fixed budget), the **~3.5–~4× full-stack** value of the three mechanisms together on
a multi-hop agent, and the in-process, no-server, auditable deployment model.

---

## Contributing

Early, but PRs and issues welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), our
[Code of Conduct](CODE_OF_CONDUCT.md), and [GOVERNANCE.md](GOVERNANCE.md) (how the
project is run and where decisions are made).
Python code lands via PR (never direct to `main`); ruff `["E","F","I","B","UP"]`,
line length 100, Python 3.11+, pytest.

Security issues: please report privately — see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
