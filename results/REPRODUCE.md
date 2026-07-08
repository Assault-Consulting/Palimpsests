# Reproducing the v0.4 first-run measurement from scratch

This is the exact procedure used for the first run of the real llama.cpp
backend and the tool-loop vs re-prefill benchmark, written from the
commands that were actually executed. Anyone with Docker should be able
to reproduce the numbers' *shape* (the growth of the speedup with prefix
and hops); absolute times will differ with hardware.

## Requirements

- Docker (any recent version; this run used Docker Desktop on Windows 11,
  Linux containers).
- ~8 GB free RAM for the container (the run peaked around 2.1 GiB used,
  but the baseline arm at prefix=4000 needs headroom).
- ~5 GB free disk in the Docker VM (image + toolchain + 1.1 GB model).
- No GPU required — this procedure is CPU-only by construction.

## 1. Isolated container

Work exclusively inside a container; nothing is installed on the host.

```bash
docker run -d --name pal-v04 -v palimpsests-work:/work -w /work \
  python:3.12-bookworm sleep infinity
docker exec pal-v04 bash -c "apt-get update && apt-get install -y build-essential wget git"
```

Run every subsequent command via `docker exec pal-v04 bash -c "..."`.

## 2. Clone and pin the exact commit

```bash
cd /work
git clone https://github.com/Assault-Consulting/Palimpsests.git
cd Palimpsests
git checkout 55742b34ec20ca45a689e05bd1fbf6143c56a37f
git rev-parse HEAD   # must print exactly 55742b34ec20ca45a689e05bd1fbf6143c56a37f
```

Do not use a moving branch head — the measurement is tied to this commit.

## 3. Install (compiles llama-cpp-python from source)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[native,embeddings]"
```

The llama-cpp-python wheel is built from C sources; expect several
minutes. This run produced llama-cpp-python 0.3.33 (CPU wheel). Record
the exact version:

```bash
python -c "import llama_cpp; print(llama_cpp.__version__)"
```

## 4. Model

```bash
mkdir -p models && cd models
wget https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf
ls -lh   # expect ~1.1 GB
cd ..
```

Model: Qwen2.5-1.5B-Instruct, quant Q4_K_M, from the official
`Qwen/Qwen2.5-1.5B-Instruct-GGUF` repository on Hugging Face. Record
file, quant, and source in your report.

## 5. Write "Expected" BEFORE running anything

Per `docs/BENCHMARKING.md` Rule 0 and `benchmarks/RUNBOOK.md` Step 0:
create `results/report.md` and commit to expectations before the first
number exists. Template used by this run:

```markdown
# v0.4 tool-loop measurement report

## Expected (written BEFORE running)
- Treatment (tool-loop) beats baseline (re-prefill) on wall time.
- The margin GROWS with --prefix-tokens and --hops.
- Control case (--prefix-tokens 50 --hops 1): arms should be CLOSE.
- A flat or <1x result at large prefix/hops = a REAL negative. Keep it.

## Environment
- commit: ...
- llama-cpp-python version: ...
- model file / quant / source: ...
- GPU: ...
- OS / CPU / RAM: ...

## Local patches
(none yet)

## Results
```

A flat or <1x result at large prefix/hops is a valid negative result —
record it, do not tune it away.

## 6. Validate the backend primitive-by-primitive (before benchmarking)

6.1 Construction (shakes out module-path / vocab / context-params shims):

```bash
python -c "
from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend
b = LlamaCppBackend('models/qwen2.5-1.5b-instruct-q4_k_m.gguf', n_ctx=2048, n_seq_max=2, n_gpu_layers=0)
print('OK: backend constructed'); b.close()"
```

6.2 Tokenize round-trip (shakes out the two-call buffer sizing):

```bash
python -c "
from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend
b = LlamaCppBackend('models/qwen2.5-1.5b-instruct-q4_k_m.gguf', n_ctx=2048, n_seq_max=2, n_gpu_layers=0)
toks = b.tokenize('Hello, world!', add_special=True)
print('tokens:', toks); print('roundtrip:', repr(b.detokenize(toks))); b.close()"
```

The roundtrip must contain `Hello, world!` (minor whitespace differences
are acceptable). On this run it was recovered exactly.

6.3 Scheduler/session smoke test:

```bash
python -c "
from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend
from palimpsests.providers.native.scheduler import Scheduler
from palimpsests.providers.native.session import NativeSession
b = LlamaCppBackend('models/qwen2.5-1.5b-instruct-q4_k_m.gguf', n_ctx=2048, n_seq_max=2, n_gpu_layers=0)
sch = Scheduler(b, max_active=1)
s = NativeSession(b, sch, system_prompt='You are a helpful assistant.', max_tokens=32, stop_tokens=())
print('--- send ---')
for c in s.send('Say hello in one word.'): print(c.delta, end='', flush=True)
print(); print('--- tool result ---')
for c in s.append_tool_result(tool_call_id='call_1', result='weather is sunny'): print(c.delta, end='', flush=True)
print(); s.close(); b.close(); print('SMOKE OK')"
```

Judge the output for coherence. Because `stop_tokens=()` and
`max_tokens=32`, generation runs past the model's EOS token — trailing
off-topic but *coherent* text after the answer is expected. Incoherent
byte salad with no exception means a wrong `pos` in `decode` (the
silent-corruption trap in RUNBOOK Step 3.5) — stop and fix before
benchmarking.

## 7. Benchmark — control first, then the sweep

Control (arms must be CLOSE; a big win here means the harness is rigged):

```bash
python benchmarks/bench_tool_loop.py --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf \
  --prefix-tokens 50 --hops 1 --repeats 5
```

This run measured 1.08x — inside the expected near-parity window.

Sweep, one configuration at a time, in this order:

```bash
python benchmarks/bench_tool_loop.py --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf --prefix-tokens 500  --hops 4  --repeats 5
python benchmarks/bench_tool_loop.py --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf --prefix-tokens 2000 --hops 8  --repeats 5
python benchmarks/bench_tool_loop.py --model models/qwen2.5-1.5b-instruct-q4_k_m.gguf --prefix-tokens 4000 --hops 12 --repeats 5
```

On CPU the last configuration takes ~45 minutes (the baseline arm
re-prefills a ~3000-token prefix 12 times per repeat). Do not reduce
`--repeats`. If min/max spread within an arm is large, re-run that
configuration with `--repeats 10`.

Note: `prefix_tokens_measured` in the output JSON is smaller than the
requested `--prefix-tokens` (e.g. 2979 measured for 4000 requested); the
requested value is an upper bound, the measured one is what to reason
from.

## 8. Known first-contact failure: GGML_ASSERT on large prefill (Patch 1)

At `--prefix-tokens 4000`, the unpatched backend aborts the whole process
(no Python traceback) with:

```
GGML_ASSERT(n_tokens_all <= cparams.n_batch) failed  (llama-context.cpp)
```

Cause: `LlamaCppBackend.__init__` did not set the logical batch size on
context creation, so it stayed at the llama.cpp default (2048), smaller
than a ~3000-token single-call prefix prefill passed to `llama_decode`.
Fix (included on this branch) — one line in
`src/palimpsests/providers/native/llamacpp_backend.py`:

```python
ctx_params.n_batch = n_ctx
```

The three smaller configurations never exceed 2048 tokens per decode call
and are unaffected. After applying the fix, re-run the control
configuration as a consistency check — this run got 1.05x post-patch vs
1.08x pre-patch, i.e. the fix did not perturb the measurement.

## 9. Recording results

For every configuration, paste the FULL JSON block printed by the script
into `results/report.md` under `## Results`:

```markdown
### config: prefix=<X> hops=<Y>
<full JSON>
speedup: <X.XX>x
```

Every local code change goes into `## Local patches` as a git diff with
the failure it addresses. Finish with an `## Interpretation (vs Expected)`
section stating plainly whether the pre-registered expectations held.
