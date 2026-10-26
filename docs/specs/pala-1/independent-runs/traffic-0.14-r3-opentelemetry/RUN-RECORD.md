# OpenTelemetry on real traffic — run 3, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Two runs of the same pydantic-ai agent against a local model, one with
content capture on and one with it off. Each produced three calls and
three results, none without a result, every one `reported-by-client`,
every call detailed `otel execute_tool; semconv unstated`. Outcomes were
`ok` × 1 and `error` × 2 in both — one more `error` than planned,
because the model made a failing `read_file` call of its own beyond the
deliberate one. The two chains differ by 144 bytes: the
digests that content capture provides and `--no-content` does not.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `C:\runs\venv`) |
| Palimpsests | `palimpsests 0.13.0 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | pydantic-ai-slim 2.61.0; opentelemetry-sdk 1.45.1; opentelemetry-exporter-otlp-proto-http 1.45.1 |
| Model | Ollama `llama3.1:8b`, Q4_K_M, digest `46e0c10c039e019119339687c3c1757c`, via `OLLAMA_BASE_URL=http://127.0.0.1:11434/v1` |
| Adapter file SHA-256 | none — the agent exports OTLP directly to the serve |
| Serve | `palimpsests-serve --api-key ***REDACTED***`, config dirs `C:\runs\r3a` and `C:\runs\r3b`, fresh for each variant |

### Model choice, stated

The run was planned with `qwen2.5:7b`. That model was not on the machine and
`llama3.1:8b` was, so `llama3.1:8b` was used and is recorded here rather
than silently substituted. The choice was not neutral: in this project's
earlier OpenCode traffic runs, `llama3.1:8b` was the one local model
observed to emit structured tool calls, while `qwen3:8b` refused to call
tools under a heavy system prompt. A model that declines to call tools
produces an empty chain and proves nothing about the adapter, so the
model most likely to exercise the path was chosen deliberately.

## What was done

1. `pydantic-ai-slim`, `opentelemetry-sdk` and
   `opentelemetry-exporter-otlp-proto-http` were installed into the run
   venv.
2. **Variant A, content capture on.** The serve was started on a fresh
   `C:\runs\r3a` (200 with the bearer, 401 without). With
   `PALIMPSESTS_SERVE_API_KEY` exported and
   `MODEL=ollama:llama3.1:8b`:

       python C:\runs\r3_otel_run.py C:\runs\scratch

   The agent's single prompt is fixed in the script: *List the files, then
   read notes.txt and missing.txt, and tell me what each one says.* The
   run ended with
   `run ended with: FileNotFoundError [Errno 2] No such file or directory: 'C:\runs\scratch\missing.txt'`
   and `spans exported: 5, failed to export: 0`. That ending is expected:
   pydantic-ai stops the agent when a tool raises, and the failing span is
   exported before it does.
3. The serve was stopped and `C:\runs\r3a\serve.pala` read.
4. **Variant B, content capture off.** The serve was started on a fresh
   `C:\runs\r3b` and the same command run with `--no-content`. It ended
   the same way, also with `spans exported: 5, failed to export: 0`.
5. The serve was stopped and `C:\runs\r3b\serve.pala` read.

Neither variant was retried.

## Result

### Variant A — content capture on

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 1883 bytes, SHA-256 `c824ee26b1b9d45e3e0ad109c214ec6271ad7e8441c39f55f237306833f384bd`
- verify: chain_ok **True**, 8 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `read_file` | `error` | `reported-by-client` | otel execute_tool; semconv unstated |
| 4 | `list_dir` | `ok` | `reported-by-client` | otel execute_tool; semconv unstated |
| 6 | `read_file` | `error` | `reported-by-client` | otel execute_tool; semconv unstated |

- calls: **3**, results: **3**, calls without a result: **0**
- outcomes: `error` × 2, `ok` × 1

`palimpsests pala verify C:\runs\r3a\serve.pala` exit code: **2**

### Variant B — `--no-content`

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 1739 bytes, SHA-256 `0474cb2baace5d832703daae907e567c0f5147bb74e36a8a262e3c289939a9b8`
- verify: chain_ok **True**, 8 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `list_dir` | `ok` | `reported-by-client` | otel execute_tool; semconv unstated |
| 4 | `read_file` | `error` | `reported-by-client` | otel execute_tool; semconv unstated |
| 6 | `read_file` | `error` | `reported-by-client` | otel execute_tool; semconv unstated |

- calls: **3**, results: **3**, calls without a result: **0**
- outcomes: `error` × 2, `ok` × 1

`palimpsests pala verify C:\runs\r3b\serve.pala` exit code: **2**

### A against B

| | A (content on) | B (`--no-content`) |
|---|---|---|
| chain bytes | **1883** | **1739** |
| records | 8 | 8 |
| calls / results | 3 / 3 | 3 / 3 |
| outcomes | `ok` × 1, `error` × 2 | `ok` × 1, `error` × 2 |

The 144-byte difference is what content capture buys: the digests. The
structure — record count, pairing, outcomes, marks — is identical without
it. `run_check.py` does not print digests, so the size comparison is how
the difference shows.

## What did not land, and why

- **Nothing was lost.** Five spans were exported in each variant and none
  failed to export; three of the five are the `execute_tool` spans that
  become pairs, and the rest of the trace is deliberately not kept.
- **The outcome split is not the planned one.** The plan
  expected `list_dir` and `read_file` on `notes.txt` to be `ok` and only
  `missing.txt` to be `error` — two `ok`, one `error`. Both variants
  produced one `ok` and two `error`: the model issued a `read_file` that
  failed in addition to the deliberate one. This is model behaviour, not
  a recording defect; the chain reports what the spans carried.
- **The order of calls differs between A and B.** A began with a failing
  `read_file`, B with `list_dir`. Nothing about `--no-content` causes
  that; the model is simply not deterministic across runs. A reader
  comparing the two tables side by side should not read the reordering as
  an effect of the flag.

## Limits of this run

One machine, one model, one prompt per variant, three tool calls each.
The agent stops at the first tool exception by design, so the run cannot
show a longer loop or a recovery after failure. No abandonment was
provoked, so no `cancelled` outcome appears. `semconv unstated` in every
detail means the exporter declared no GenAI conventions version; what a
stated version would change is untested here. Nothing shows behaviour
with a remote model, under concurrency, or on another OS.

### The serve start line does not work

As recorded in run 1: `palimpsests serve --api-key …` exits with
`No such option: --api-key`, and moving the key into
`PALIMPSESTS_SERVE_API_KEY` starts an endpoint that does not require it.
Both variants here used `palimpsests-serve --api-key ***REDACTED***`,
measured to answer 401 without the bearer.

---

This run was carried out with AI assistance.
