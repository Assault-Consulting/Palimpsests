# Usage — running Palimpsests and which settings work

A practical guide to the current state of the project (v0.1). It
describes **only what is actually implemented and working** — level 1
(Ollama). Levels 2 and 3 are not wired up yet, so their settings are
not listed here.

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

---

## 2. Installation

```bash
# base package: level 1 (Ollama) + context-memory + CLI + audit/registry
pip install palimpsests
```

> As of v0.1 the package is not yet on PyPI. Until it is published,
> install from a clone of the repository:
> ```bash
> git clone https://github.com/Assault-Consulting/Palimpsests.git
> cd Palimpsests
> pip install -e .
> ```

The base package pulls **no native dependency** — only `httpx`,
`pydantic`, and `typer`. All native complexity (llama.cpp) lives behind
the `[llamacpp]` extra, which is not yet active in v0.1.

### Optional extras (present, but not all active in v0.1)

| Extra | What it provides | State in v0.1 |
|---|---|---|
| `[keyring]` | audit-log encryption key from the OS keychain | works |
| `[encryption]` | at-rest audit-log encryption (SQLCipher) | works |
| `[llamacpp]` | level 2 (llama.cpp) | **level code not wired yet** |
| `[embeddings]` | local embeddings for block memory | for the upcoming block-memory work |

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

> In v0.1 only `ollama` can actually be active. `engine use` on an
> engine that isn't in the factory returns an error. `llamacpp` and
> `pal-native` arrive in later versions.

### Everything `--help` shows

```bash
palimpsests --help              # list of commands
palimpsests chat --help         # chat options
palimpsests engine --help       # engine subcommands
```

---

## 4. Which settings work

This is the exhaustive list of **actually working** settings in v0.1.

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

These are the knobs **declared** in the contract. Level 1 (Ollama)
accepts only a subset; the rest are deliberately ignored (level 1 never
claimed them — see the table below).

| Field | Default | Ollama L1 |
|---|---|---|
| `context_size` | `None` | → `num_ctx` (applied) |
| `gpu_layers` | `None` | → `num_gpu` (applied) |
| `kv_cache_quant` | `None` | ignored at L1 |
| `flash_attention` | `False` | ignored at L1 |
| `use_mmap` | `True` | ignored at L1 |
| `draft_model` | `None` | ignored at L1 |

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
command to view it in v0.1.

---

## 7. Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `engine unavailable` | Ollama daemon not running | run `ollama serve` |
| `model not found` | model isn't in Ollama | `ollama pull <model>` |
| `engine list` shows `not installed` | daemon didn't answer at `init_app` | check that Ollama listens on :11434 |
| empty reply from `chat` without `-m` in a terminal | neither `-m` nor a pipe provided | add `-m "..."` or pipe text in |

---

*This document describes the v0.1 state. Later versions (level 2
llama.cpp, block-memory retrieval, level 3) will add new settings; this
file will be updated accordingly.*
