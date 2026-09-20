# Usage — running Palimpsests and which settings work

A practical guide to what is in the released package and how to drive
it. All three levels ship: level 1 (Ollama), level 2 (llama.cpp) and
level 3 (pal-native, the in-process serving loop) sit behind one
abstraction, and level 3's mechanisms are measured rather than asserted
— see [results/](../results/) and [POSITIONING.md](POSITIONING.md).
Where a setting is not yet a stable, user-facing knob, this guide says
so rather than documenting something that may change.

New to the project? [Start here](START-HERE.md) explains what the audit
chain is in plain words and walks a five-minute demo. This page is the
reference underneath it.

Two commands are worth knowing before anything else:

```bash
palimpsests --version   # package, frozen core spec, profile revision
palimpsests demo        # an audited agent turn, verified, no model needed
```

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
expected behavior. Over HTTP the same condition is a **503** with
`code: engine_unavailable` in the OpenAI error shape, not a 500: the
status says which side is down.

`palimpsests demo` needs none of this — it runs a deterministic stub
backend, writes a real PALA-1 chain, and verifies it. Use it to check
an install before touching a model.

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
| `[serve]` | the OpenAI-compatible endpoint (`palimpsests serve`) | works |

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

### Serve an OpenAI-compatible endpoint

```bash
pip install 'palimpsests[serve]'
palimpsests serve                      # http://127.0.0.1:11435/v1
palimpsests-serve --api-key sk-…       # same server, bearer-guarded
palimpsests-serve --print-opencode-config
```

Point any OpenAI-compatible client at that base URL. Structured tool
loops that cross the endpoint are recorded to `<config>/serve.pala` as
`TOOL_CALL` / `TOOL_RESULT` pairs; a turn where tools were offered and
no structured call came back is recorded as `TOOLS_OFFERED_NO_CALL`, so
the boundary is visible rather than silent.

Bind to localhost and pass `--api-key` the moment anything beyond your
own shell can reach the port. A serve that cannot open its audit log
prints the reason and exits `1` before binding — it will not start an
endpoint it cannot answer from.

Clients that run their tool loop in text can report it onto the same
chain; see [`integrations/`](../integrations/) for the LiteLLM callback,
the MCP stdio proxy and the OpenCode plugin, each with its own README
stating what a reported record does and does not prove.

### Everything `--help` shows

```bash
palimpsests --help              # list of commands
palimpsests --version           # package · core spec · profile revision
palimpsests chat --help         # chat options
palimpsests engine --help       # engine subcommands
palimpsests pala --help         # the audit-chain tools
```

---

### Verify a PALA-1 stream without decryption keys

`pala verify` is read-only and needs no decryption key: record headers are
checked, and each body is checked against the digest bound into its header —
encrypted bodies are never opened. An auditor can therefore validate a
copied stream without receiving any key that created it.

The following script writes the smallest stream whose head can be verified
end to end. Save it as `make_demo.py`:

```python
from palimpsests.audit.pala_writer import PalaWriter

path = "demo.pala"
with PalaWriter(path) as writer:
    writer.genesis()
    writer.boot()
    head = writer.anchor()

print(head.hex())
```

Run it once and keep the printed value. `anchor()` appends an `ANCHOR`
record and returns the new chain head *including that record* — exactly the
value an out-of-band anchor store should hold:

```bash
HEAD=$(python make_demo.py)
echo "$HEAD"    # 64 hexadecimal characters (differs per run)
```

The binary `.pala` file stays authoritative; for human review, export a
JSONL view of the headers:

```bash
palimpsests pala export demo.pala --out demo.jsonl
# exported 3 record(s) to demo.jsonl
```

Give the saved head to the verifier:

```bash
palimpsests pala verify demo.pala --anchor "$HEAD"
# consistency: 3 records, chain intact
# anchor: c3cfe3c1… from manual
# completeness: chain head matches the supplied anchor
# witness: no WITNESS records — existence at a point in time is not attested
```

Exit `0` means the chain is intact **and** its head matches the anchor.
Without `--anchor` the command still checks internal consistency but exits
`2` (`PARTIAL`) on purpose: tail truncation, or wholesale replacement by
another internally consistent file, cannot be detected from the inside, and
the tool reports that limit instead of passing over it. A break, a gap, a
violated MUST or a body-digest mismatch exits `1` (`TAMPERED`) — flip a
single bit to see it:

```bash
python -c "b = bytearray(open('demo.pala','rb').read()); b[200] ^= 1; open('demo.pala','wb').write(bytes(b))"
palimpsests pala verify demo.pala --anchor "$HEAD"
# consistency: BROKEN — chain breaks at seq [1, 2]
```

The full exit-code contract (`0/1/2/3`) and machine-readable `--json`
output are described by `palimpsests pala verify --help`.

### The rest of the `pala` family

| Command | What it does |
|---|---|
| `pala verify` | the three questions — consistency, completeness, witness |
| `pala export` | JSONL view of the headers; derived, never authoritative |
| `pala report [--html]` | an attestation document; the verdict lives inside it |
| `pala bundle` | records + inclusion proofs + verdict in one tar |
| `pala segment` | cut a chain into retention-ready segments that verify alone |
| `pala consistency` / `consistency-verify` | prove an archived prefix is still a prefix |
| `pala selftest` | check this build against the vectors packaged in the wheel |

`pala selftest` also prints a characteristic line — records/s and the
reader's Python-heap cost per record, with a tripwire — so a
performance regression in the reader fails the selftest instead of
going unnoticed. Details for each command: `docs/audit/cli.md`.

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
| `PALIMPSESTS_SERVE_API_KEY` | — | bearer key for `palimpsests serve`; the integrations read the same variable |
| `PALIMPSESTS_SERVE_URL` | `http://127.0.0.1:11435` | where the integrations look for the serve |
| `PALIMPSESTS_AUDIT_REPORT` | — | set to `0` to disable client-side reporting in the integrations |

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

### Reading a chain from Python

```python
from palimpsests.audit.reader import AuditReader

with AuditReader.open("serve.pala") as reader:
    verdict = reader.verify()
    print(verdict.chain.count, verdict.chain.chain_ok)
```

`AuditReader` is the supported consumer surface — header-only, no key
needed, bounded in memory on large chains. Its stability class and the
rest of the integration surface are declared in
[INTEGRATION-SURFACE.md](INTEGRATION-SURFACE.md); the API itself is in
[docs/audit/reader.md](audit/reader.md).

### Level-3 stateful sessions (Python)

Level 3 adds stateful sessions with a server-side tool loop, shared
prefix KV and KV persistence, behind the same `InferenceEngine`
abstraction. The real in-process backend ships behind the `[native]`
extra and the three mechanisms are measured on 1.5B and 7B — method,
numbers and limits in [results/](../results/). The session API surface —
`open_session`, `send`, `append_tool_result`, `save_state` /
`load_state` — is documented in `ARCHITECTURE.md` and exercised in the
`tests/test_native_*` suite. Level-3 runtime settings are still not
quoted here as stable user-facing knobs: what is measured is the
mechanisms' effect, not a frozen configuration surface.

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
is written to an append-only audit log — the SQLite one, checked with
`palimpsests audit verify`. That is a different artifact from a PALA-1
`.pala` chain: the first is this application's own operational log, the
second is the portable, independently verifiable format an auditor
receives. `palimpsests serve` and level 3 write the latter.

The SQLite log can be read from Python (`get_audit_log().recent()`);
there is no dedicated CLI command to list its rows.

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
| `palimpsests-serve` prints an error and exits `1` | same cause, caught before the port is bound | the message names both remedies |
| HTTP `503 engine_unavailable` from the serve | the engine behind it is not running | start Ollama, or point at an engine that is up |
| `pala verify` exits `2` on a chain you believe is whole | no anchor was supplied, so completeness was not checked | pass `--anchor` / `--anchor-file`; see [anchors.md](audit/anchors.md) |

---

*This document tracks the released package. Claims here are limited to
what ships and what has been measured; where a surface is not yet
stable it is named as such rather than documented as if it were. The
project's own statements about what it does and does not prove are in
[SECURITY.md](../SECURITY.md), [ASSURANCE-CASE.md](ASSURANCE-CASE.md)
and [POSITIONING.md](POSITIONING.md).*
