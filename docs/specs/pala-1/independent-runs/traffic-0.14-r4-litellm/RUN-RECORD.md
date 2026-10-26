# LiteLLM on real traffic — run 4, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Ten turns through LiteLLM against a local model produced ten calls and
ten results, none without a result, every one `reported-by-client`, and
**every result `unobserved`** — including the three turns that read a
file which does not exist. That is correct for this vantage: the callback
sees only the string the application fed back to the model, never the
tool, so it cannot say whether the tool failed. The model called the tool
on all ten turns; none answered without it.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `C:\runs\venv`) |
| Palimpsests | `palimpsests 0.13.0 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | litellm 1.106.4 (with `mcp` 2.3.0, which LiteLLM imports when a request carries `tools`) |
| Model | Ollama `llama3.1:8b`, Q4_K_M, digest `46e0c10c039e019119339687c3c1757c`, as `ollama_chat/llama3.1:8b` |
| Adapter file SHA-256 | `palimpsests_audit.py` — `7c8a81b3d8a55e3ae97e0591601af3fe0c445fa39b70a0be59f2c3f927339e29` |
| Serve | `palimpsests-serve --api-key ***REDACTED***`, config dir `C:\runs\r4`, fresh for the recorded run |

### Model choice, stated

The run was planned with `qwen2.5:7b`; it was not on the machine, and
`llama3.1:8b` was. The substitution is recorded rather than hidden, for
the reason given in run 3: a model that declines to call tools yields an
empty chain and tests nothing, and `llama3.1:8b` is the local model this
project has already observed emitting structured tool calls.

## What was done

1. `litellm` and `mcp` were installed into the run venv. `mcp` is not
   this project's dependency — LiteLLM 1.106 imports it as soon as a
   request carries `tools`, and does not install it itself.
2. **Setup check with the mock.** The serve was started on `C:\runs\r4`
   and, with `LITELLM_LOCAL_MODEL_COST_MAP=True` so no price map is
   fetched:

       python C:\runs\r4_litellm_run.py C:\runs\scratch --mock --turns 1

   It printed `turn 1: 1 tool call(s); answer: done`, confirming the
   wiring without a provider.
3. **The mock chain was discarded**: the
   serve was stopped, `C:\runs\r4` deleted and recreated empty, and the
   serve restarted on it. The mock turn appears nowhere in the result
   below.
4. **The recorded run.** With `MODEL=ollama_chat/llama3.1:8b` and
   `PALIMPSESTS_SERVE_API_KEY` exported:

       python C:\runs\r4_litellm_run.py C:\runs\scratch --turns 10

   The script cycles three fixed questions — *What does notes.txt say?*,
   *What does missing.txt say?*, *What does notes.txt say, in one word?*
   — executing `read_file` itself and feeding the result back, as an
   application would. All ten turns reported `1 tool call(s)`; none
   printed `no tool call`.
5. The serve was stopped and the chain read.

No step was retried.

## Result

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 5402 bytes, SHA-256 `1ec1d6a61f3a2980f7b7556d3a62ff945ebb2c7c01d31887f0f570cb6d8f5cf0`
- verify: chain_ok **True**, 22 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `read_file` | `unobserved` | `reported-by-client` |  |
| 4 | `read_file` | `unobserved` | `reported-by-client` |  |
| 6 | `read_file` | `unobserved` | `reported-by-client` |  |
| 8 | `read_file` | `unobserved` | `reported-by-client` |  |
| 10 | `read_file` | `unobserved` | `reported-by-client` |  |
| 12 | `read_file` | `unobserved` | `reported-by-client` |  |
| 14 | `read_file` | `unobserved` | `reported-by-client` |  |
| 16 | `read_file` | `unobserved` | `reported-by-client` |  |
| 18 | `read_file` | `unobserved` | `reported-by-client` |  |
| 20 | `read_file` | `unobserved` | `reported-by-client` |  |

- calls: **10**, results: **10**, calls without a result: **0**
- outcomes: `unobserved` × 10

`palimpsests pala verify C:\runs\r4\serve.pala` exit code: **2**

Serve access log: 20 posts to `/v1/pala/events` — ten calls and ten
results — **all accepted**, no refusals.

## What did not land, and why

- **Nothing was lost.** Ten turns, ten calls, ten results, ten pairs.
- **No turn answered without a tool.** The count of `no tool call` turns
  is **zero**. The model used `read_file` on
  every turn, including the three asking about a file that does not
  exist.
- **Three results were failures in the world and are recorded
  `unobserved`.** Turns 2, 5 and 8 asked about `missing.txt`; the script
  fed back the string `error: [Errno 2] No such file or directory…`. To
  the callback that is a string that re-entered generation, nothing more,
  so it reports `unobserved` rather than inferring `error` from the text.
  This is the behaviour outcome 4 exists for, observed on real traffic.

## Limits of this run

One machine, one model, ten turns, one tool. Every call used the same
tool name, so nothing here shows how the callback handles a varied
toolset. The loop was driven by a script that always returns a result, so
no call was abandoned and no `cancelled` outcome appears. Streaming was
not exercised. Nothing shows behaviour through the LiteLLM proxy rather
than the library, under concurrency, or with a remote provider.

### The serve start line does not work

As recorded in run 1: `palimpsests serve --api-key …` exits with
`No such option: --api-key`, and moving the key into
`PALIMPSESTS_SERVE_API_KEY` starts an endpoint that does not require it.
This run used `palimpsests-serve --api-key ***REDACTED***`, measured to
answer 401 without the bearer.

---

This run was carried out with AI assistance.
