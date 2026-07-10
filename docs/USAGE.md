# Usage — running Palimpsests and which settings work

A practical guide to the current state of the project (v0.3). Level 1
(Ollama) is the fully documented, end-to-end path below. Levels 2
(llama.cpp) and 3 (pal-native) exist behind one abstraction — level 3's
serving skeleton is complete and test-covered against a fake backend, and
its real in-process backend plus benchmarks are the v0.4 target. Where a
level-2/3 setting is not yet a stable, user-facing knob, this guide says so
rather than documenting something that may change.

---

## 1. Prerequisites

- **Python 3.11+** (the package requires `>=3.11`; tested on 3.11 and 3.12).
- **A running Ollama daemon** — this is the level-1 backend. Palimpsests
  does not load models itself; it talks to Ollama over HTTP.
  - Install Ollama: https://ollama.com
  - Start the daemon (it listens on `http://localhost:11434` by default).
  - Pull at least one model, e.g.: `ollama pull qwen2.5:7b`

Without a running Ollama daemon, `models` and `chat` return a clean
error (`engine unavailable`) rather than a traceback — that is the
expected behavior.

For **level 2**, you additionally need the `llama-server` binary from
llama.cpp on your `PATH` (installed out-of-band — `brew install llama.cpp`,
a release binary, or your own GPU build) and a GGUF model; point Palimpsests
at it with `PALIMPSESTS_LLAMACPP_MODEL`. For **level 3** (the native serving
loop), the real backend ships behind the `[native]` extra and is validated
on hardware — see the roadmap and `docs/BENCHMARKING.md`.

> **⚠ Level 2 is single-user-host only.**
> The managed `llama-server` child listens on a **local HTTP port with no
> authentication** (`--api-key` is not set). Any other process on the same
> machine can send prompts into your slots, read output, or exhaust the
> server; port selection also has a check-then-bind race. **Do not enable
> level 2 on a host you share with untrusted users or processes.** Levels 1
> and 3 are unaffected. This is a deliberate, documented deferral — see
> [Accepted risks](../SECURITY.md#accepted-risks).

---

## 2. Installation

```bash
# base package: level 1 (Ollama) + context-memory + CLI + audit/registry
pip install palimpsests
```

The base package pulls **no native dependency** — only `httpx`,
`pydantic`, and `typer`. All native complexity (llama.cpp) lives behind
extras.

### Optional extras

| Extra | What it provides | State |
|---|---|---|
| `[keyring]` | audit-log encryption key from the OS keychain | works |
| `[encryption]` | at-rest audit-log encryption (SQLCipher) | works |
| `[embeddings]` | local embeddings (numpy) for block memory | works |
| `[llamacpp]` | level 2 marker (needs the `llama-server` binary on PATH) | works; empty marker; **single-user host only** — see §1 |
| `[native]` | level 3 real backend (llama-cpp-python) | ships; validated on hardware |

Example, with audit-log encryption:
```bash
pip install "palimpsests[keyring,encryption]"
```

---

## 3. Basic usage (CLI)

After installation the `palimpsests` command is available.

### Chat with a model

```bash
# prompt via -m
palimpsests chat qwen2.5:7b -m "explain KV cache quantization in two sentences"

# prompt via stdin (pipe)
echo "same, but piped" | palimpsests chat qwen2.5:7b
```

The reply streams token by token to stdout.

### List models

```bash
palimpsests models
```
Shows the models the active engine can see (reads Ollama's `/api/tags`).
Row format: `<name>  <size GB>  <quant>`.

### Engines

```bash
# show known engines: control level, installed state, * = active
palimpsests engine list

# switch the active engine
palimpsests engine use llamacpp
```

`engine list` shows all three levels (`ollama`, `llamacpp`, `pal-native`)
with their control level and installed state. `engine use` on an engine
that isn't available in your environment returns a clean error rather than
a traceback.

### Everything `--help` shows

```bash
palimpsests --help              # list of commands
palimpsests chat --help         # chat options
palimpsests engine --help       # engine subcommands
```

---

## 4. Which settings work

### 4.1. `chat` command settings

| Option | Default | What it does |
|---|---|---|
| `-m`, `--message` | — | prompt text; if omitted, read from stdin |
| `-c`, `--context-size` | `8192` | token budget for context fitting |

**`--context-size` is the main setting worth understanding.** It is not
the model's context length but a **budget** that Palimpsests fits the
conversation to before sending (sink/window/evict). If the conversation
exceeds the budget, the middle is evicted, keeping the system prompt +
first messages (sink) and the most recent ones (window).

```bash
# give a long conversation a smaller budget — eviction starts to apply
palimpsests chat qwen2.5:7b -m "..." --context-size 4096
```

Because tokens are counted with a heuristic (~3.5 chars/token, biased
toward **over**-counting), the budget is held at 80% of the stated size
(`safety_margin=0.8`) — so an estimation error costs a few wasted
tokens rather than an OOM.

### 4.2. Environment variables

| Variable | Default | What it does |
|---|---|---|
| `PALIMPSESTS_CONFIG_DIR` | `~/.config/palimpsests` | where `audit.db` and `registry.json` live |
| `XDG_CONFIG_HOME` | — | if set, config → `$XDG_CONFIG_HOME/palimpsests` |
| `PALIMPSESTS_LLAMACPP_MODEL` | — | path to a GGUF model; enables level 2 (see the level-2 warning in §1) |
| `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT` | — | set to `1` to accept a plaintext (still hash-chained) audit log when SQLCipher is unavailable |

```bash
# isolated config (handy for tests / multiple profiles)
PALIMPSESTS_CONFIG_DIR=/tmp/pcfg palimpsests engine list
```

### 4.3. Ollama adapter settings (via the Python API)

Via the CLI the base URL is currently fixed (`localhost:11434`). Via
Python you can override it:

| `OllamaEngine(...)` parameter | Default | What it does |
|---|---|---|
| `base_url` | `http://localhost:11434` | address of the Ollama daemon |
| `connect_timeout` | `5.0` s | connect timeout (a dead daemon fails fast) |
| `read_timeout` | `300.0` s | read timeout (a stream can run long) |

### 4.4. Memory settings (`EngineMemoryConfig`)

These are the knobs **declared** in the contract. Each level accepts the
subset it can honor; the rest are deliberately ignored (a level never
silently pretends to apply a knob it does not support — query
`engine.capabilities`).

| Field | Default | Ollama L1 | llama.cpp L2 |
|---|---|---|---|
| `context_size` | `None` | → `num_ctx` | → `--ctx-size` |
| `gpu_layers` | `None` | → `num_gpu` | → `--n-gpu-layers` |
| `kv_cache_quant` | `None` | ignored at L1 | → cache-type flags |
| `flash_attention` | `False` | ignored at L1 | → `--flash-attn` |
| `use_mmap` | `True` | ignored at L1 | → mmap flags |
| `draft_model` | `None` | ignored at L1 | → draft-model flags |

**One hard validation rule** (applies at every level): `kv_cache_quant`
requires `flash_attention=True`. Otherwise a `ValueError` is raised
immediately at config construction, because a quantized KV cache
without flash attention is dequantized every step and runs slower than
an unquantized one.

---

## 5. Usage from Python (no terminal)

The same orchestration the CLI uses:

```python
from palimpsests.core import init_app, chat

ctx = init_app()                       # config dir + audit + registry + engines
messages = [{"role": "user", "content": "hello"}]

for chunk in chat(ctx, model="qwen2.5:7b", messages=messages):
    print(chunk.delta, end="", flush=True)
```

`chat(...)` automatically: (1) fits the conversation to `context_size`
(default 8192) via the ContextWindowManager, (2) records the call to
the audit log, and (3) streams through the active engine. You get
context management and auditability for free, without wiring them
yourself.

Other orchestrated functions:
```python
from palimpsests.core import list_models, list_engines, select_engine

list_models(ctx)          # models on the active engine (audited)
list_engines(ctx)         # [(engine_id, level, installed, active), ...]
select_engine(ctx, "ollama")   # switch the active engine (audited)
```

If you want the bare adapter without registry/audit (e.g. for
embedding it in another product):
```python
from palimpsests.providers import OllamaEngine

engine = OllamaEngine(base_url="http://localhost:11434")
for chunk in engine.chat_stream(model="qwen2.5:7b", messages=messages):
    print(chunk.delta, end="", flush=True)
engine.close()
```

### Level-3 stateful sessions (Python)

Level 3 adds stateful sessions with a server-side tool loop and KV
persistence, behind the same `InferenceEngine` abstraction. The serving
skeleton is complete and test-covered against a fake backend; the real
in-process backend is validated on hardware (the `[native]` extra). The
session API surface — `open_session`, `send`, `append_tool_result`,
`save_state` / `load_state` — is documented in `ARCHITECTURE.md` and
exercised in the `tests/test_native_*` suite. Because the on-hardware
backend and its performance are the v0.4 target, this guide does not yet
quote level-3 runtime settings as stable user-facing knobs.

> **⚠ `load_state` is not yet a validated trust boundary.**
> The blob it takes is parsed in C by llama.cpp. Today those blobs are
> produced in-process by `save_state`, so nothing untrusted reaches that
> parser — but **do not pass `load_state` a blob you did not produce
> yourself**. Header validation and a MAC over persisted blobs land before
> the disk-backed KV store does; see
> [Accepted risks](../SECURITY.md#accepted-risks).

---

## 6. What happens under the hood on `chat`

```
palimpsests chat qwen2.5:7b -m "..."
  │
  ├─ init_app()         → config dir, audit log (encrypted), registry,
  │                        register ollama with a live availability probe
  ├─ ContextWindowManager.fit(messages, context_size)
  │                      → sink + window kept, middle evicted
  ├─ @audited("model.call")
  │                      → write to audit.db (success/error/denied)
  └─ OllamaEngine.chat_stream()
                         → POST /api/chat, NDJSON stream back
```

Every operation (`model.call`, `engine.list_models`, `engine.select`)
is written to an append-only audit log. For now the log can be read
only via Python (`get_audit_log().recent()`); there is no dedicated CLI
command to view it yet.

---

## 7. Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `engine unavailable` | Ollama daemon not running | run `ollama serve` |
| `model not found` | model isn't in Ollama | `ollama pull <model>` |
| `engine list` shows `not installed` | daemon didn't answer at `init_app` | check that Ollama listens on :11434 |
| empty reply from `chat` without `-m` in a terminal | neither `-m` nor a pipe provided | add `-m "..."` or pipe text in |
| level 2 not available | `llama-server` not on PATH or `PALIMPSESTS_LLAMACPP_MODEL` unset | install llama.cpp, set the model env var |
| `AuditIntegrityError` on startup | SQLCipher not installed, so the audit log refuses to open unencrypted | `pip install "palimpsests[encryption]"`, or accept plaintext with `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` |

---

*This document describes the v0.3 state: level 1 fully documented, level 2
available, level 3's serving skeleton complete with its real backend and
benchmarks as the v0.4 target. It is updated as the level-2/3 surfaces
stabilize into user-facing settings.*
