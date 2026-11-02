# OpenCode on real traffic — run 3, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Seven runs on seven fresh config dirs, nine OpenCode sessions in all, and
the zero from run 1 now has a measured cause: with `PALIMPSESTS_SERVE_API_KEY` unset in
the window OpenCode is launched from, the plugin's two posts are refused
`401` and nothing reaches the chain; with the key set, the same single
turn puts a call and its result on the chain. Beyond that, a ten-prompt
session produced **6 calls and 6 results, none left without a result**,
and a repeat of the same ten prompts with the `~/.claude/skills`
catalogue moved aside produced **6 pairs of which 3 resolved `ok`**,
carrying the real tool names `read`, `task`, `write` and `webfetch`.
Every chain read here verifies intact.

What this run does **not** show is a clean ten-for-ten: these local 8B
models answer most prompts with tool-call JSON as plain text, so most
prompts executed no tool at all. That is a model-quality floor, not a
recording loss — in both ten-prompt sessions the chain carried **one
more** tool than the client's own transcript displayed.

## Environment

| | |
|---|---|
| Date | 2026-11-02 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `<repo>\.venv-p06`) |
| Palimpsests | `palimpsests 0.13.1 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | OpenCode 1.18.31 |
| Engine | Ollama 0.33.2, CPU inference (`dropping integrated GPU` at start-up) |
| Model | `llama3.1:8b`, Q4_K_M, 8.0B, digest `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`; one attempt on `qwen2.5-coder:7b`, Q4_K_M, 7.6B, digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |
| Provider | Ollama direct (`http://127.0.0.1:11434/v1`, `@ai-sdk/openai-compatible`); the serve is **not** the model provider in this run |
| Adapter file SHA-256 | `b33f7888dc2ee6f3aca0250fb7ad15ea10414496f6d84373f21fee9bc7b4909e` (the OpenCode plugin, installed to `~/.config/opencode/plugins/`) |
| Serve | `palimpsests serve --api-key ***REDACTED***`, config dir fresh for every run, `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` |

All sessions were driven headlessly — `opencode run "<prompt>"` for the
first turn of a session and `opencode run -c "<prompt>"` for each
following turn. The TUI was not used. `--auto` was not used, so a
permission request in `run` mode auto-rejects; that happened twice and is
recorded below.

`PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` was set for the serve because
SQLCipher is not available on this machine; it affects the serve's own
operations log, not the chain.

## O2 — why run 1 recorded nothing

### What was done

1. Serve started on a fresh `C:\runs\o2`.
2. In the window OpenCode was launched from, `PALIMPSESTS_SERVE_URL` was
   set to `http://127.0.0.1:11435` and `PALIMPSESTS_SERVE_API_KEY` was
   **left unset** (confirmed before the turn: `KEY_SET=False`).
3. One turn, in `C:\runs\scratch`:
   `opencode run "Read notes.txt and tell me what it says."`
   The client displayed one executed tool, `read`, and answered from the
   file's real contents. Elapsed 151 s.
4. Serve stopped, chain read.
5. Repeated on a fresh `C:\runs\o2b` with `PALIMPSESTS_SERVE_API_KEY`
   set (`KEY_SET=True`), same prompt, same working directory.
   Elapsed 121 s.

### Result — without the key (`C:\runs\o2`)

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 312 bytes, SHA-256 `1069a8fb5c516549f0bc90f6e0acfe0c9435de668cc5f48b54be92d76328f674`
- verify: chain_ok **True**, 2 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|

- calls: **0**, results: **0**, calls without a result: **0**
- outcomes: none

`palimpsests pala verify C:\runs\o2\serve.pala` exit code: **2**

Serve access log for the session: **2 posts to `/v1/pala/events`, both
answered 401**.

### Result — with the key (`C:\runs\o2b`)

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 820 bytes, SHA-256 `f616ba00568dc4370529c376fed4c2a87b7aab94b561d378623f3c1c38d5bece`
- verify: chain_ok **True**, 4 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `webfetch` | `error` | `reported-by-client` |  |

- calls: **1**, results: **1**, calls without a result: **0**
- outcomes: `error` × 1

`palimpsests pala verify C:\runs\o2b\serve.pala` exit code: **2**

Serve access log for the session: **2 posts to `/v1/pala/events`, both
answered 200**.

### What this establishes, and what it does not

The missing key is **sufficient** to produce a zero: 312 bytes, header
only, while the client visibly executed a tool. The plugin does not fail
loudly — by its own contract a report failure is logged and the tool
proceeds — so from the client's side the turn looks entirely normal.

With the key, the same prompt put a pair on the chain, so the ingestion
path works end to end on this machine. The pair is not the same tool: the
model chose `webfetch` with invalid arguments instead of `read`, and the
pair is therefore `error`. That is the model, not the surface.

Whether `PALIMPSESTS_SERVE_API_KEY` was exported in the window OpenCode
was launched from **during run 1 cannot be established**. The run 1
record does not state it — it names neither the variable nor a `401` —
and nothing on that run's chain or in this one can settle it after the
fact. Run 1's own stated finding was that the plugin announced itself and
never emitted an event; a `401` on every emission is consistent with that
observation but is not proof of what happened then.

## O1 — does an `ok` pair appear

Three attempts, each on its own fresh config dir. None of the three
produced an `ok` pair; the `ok` pairs in this record come from O3.

### Attempt 1 — `llama3.1:8b`, three turns (`C:\runs\o1`)

1. Serve on a fresh `C:\runs\o1`; URL and key both set.
2. `opencode run "Read notes.txt and tell me what it says."`
   → no tool executed. The model answered with the literal text
   `{"type": "tool", "name": "read", "parameters": {"fp": "notes.txt"}}`.
3. `opencode run -c "Read missing.txt and tell me what it says."`
   → `read` executed and failed: `The read tool was called with invalid
   arguments: SchemaError(Missing key at ["filePath"])`.
4. `opencode run -c "List the files in this directory."`
   → no tool executed; malformed JSON in the answer text.

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 816 bytes, SHA-256 `b1e7eba48d86d3285e12301b929b780cb45bf4b3d5fc6f14779358f7f130c293`
- verify: chain_ok **True**, 4 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `read` | `error` | `reported-by-client` |  |

- calls: **1**, results: **1**, calls without a result: **0**
- outcomes: `error` × 1

`palimpsests pala verify C:\runs\o1\serve.pala` exit code: **2**
Serve access log: 2 posts to `/v1/pala/events`, both **200**.

### Attempt 2 — `qwen2.5-coder:7b`, same three turns (`C:\runs\o1b`)

The model was switched in `~/.config/opencode/opencode.json` to
`ollama/qwen2.5-coder:7b` — tool-capable according to the engine's own
capability list — and the three turns were repeated on a fresh
`C:\runs\o1b`. All three answered with tool-call JSON as plain text:
`{"name": "read", "arguments": {"file_path": "notes.txt"}}`, the same for
`missing.txt`, and `{"name": "glob", "arguments": {"pattern": "*"}}`.
**No tool was executed at any turn.**

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 312 bytes, SHA-256 `224acb1873dde9b55bda7cde6e93fb3a73a710dfca9f7974eaf6c3e9ab4da55a`
- verify: chain_ok **True**, 2 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|

- calls: **0**, results: **0**, calls without a result: **0**
- outcomes: none

`palimpsests pala verify C:\runs\o1b\serve.pala` exit code: **2**
Serve access log: **0 posts** to `/v1/pala/events` — the plugin had
nothing to report. The model was switched back to `llama3.1:8b`
afterwards.

### Attempt 3 — `llama3.1:8b`, argument names spelled out (`C:\runs\o1c`)

Six turns on a fresh `C:\runs\o1c`, with the tool and its argument named
in the prompt:

1. `Use the read tool with filePath "notes.txt". Then tell me what the file says.`
   → no tool executed; malformed JSON in the answer.
2. `Use the read tool with filePath "missing.txt". Then tell me what happened.`
   → `read` executed and failed for the real reason:
   `File not found: C:\runs\scratch\missing.txt`.
3. `Use the list tool with path "." to list the files in this directory.`
   → no tool executed.
4. `Use the read tool with filePath "dates.txt". Then tell me the date it contains.`
   → no tool executed.
5. and 6. The prompt from O2, verbatim, twice, each in a **fresh**
   session (no `-c`) to rule out the polluted context of turns 1–4: once
   answered with a Python snippet, once with `task`-shaped JSON as text.
   No tool executed either time.

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 816 bytes, SHA-256 `0fae1015d68d31ded93b95f77d3303a119993f3e138031451db1148525d830b1`
- verify: chain_ok **True**, 4 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `read` | `error` | `reported-by-client` |  |

- calls: **1**, results: **1**, calls without a result: **0**
- outcomes: `error` × 1

`palimpsests pala verify C:\runs\o1c\serve.pala` exit code: **2**
Serve access log: 2 posts to `/v1/pala/events`, both **200**.

### What O1 establishes

Across twelve turns in three attempts, exactly two tools executed, both
`read`, both failing — once on a schema error, once on a genuine missing
file — and both landed as a correctly paired `error`. The `error` path of
the reported-by-client surface is therefore exercised with the real tool
name and a real failure. **The `ok` path is not demonstrated by O1**, and
the reason sits upstream of the surface: on this engine and these models,
the client usually never calls a tool.

## O3 — a ten-prompt session, counted three ways

The ten prompts are the ten from run 1 of the Claude Code series, in the
same order, so the two sessions can be compared.

### Pass 1 (`C:\runs\o3`)

Serve on a fresh `C:\runs\o3`; URL and key set; one session, ten turns,
working directory `C:\runs\scratch`.

| # | Prompt | What the client displayed |
|---|---|---|
| 1 | `Read notes.txt and tell me what it says.` | no tool executed (tool-call JSON as text) |
| 2 | `List the files in this directory.` | no tool executed |
| 3 | `Read missing.txt.` | no tool executed |
| 4 | `Run a command that prints the current date.` | `task` (General Agent) executed, **failed**: `Expected a string starting with "ses", got "None"` |
| 5 | `Create a file hello.txt containing the word hello, then read it back.` | `write` executed, **failed**: `permission requested: external_directory (C:\home\user\*); auto-rejecting` → `The user rejected permission to use this specific tool call.` |
| 6 | `Append the line "second line" to notes.txt, then show me the whole file.` | no tool executed |
| 7 | `How many lines and how many words does notes.txt have? Use a command.` | `task` executed, **failed**: `SchemaError(Missing key at ["description"])` |
| 8 | `Create a file dates.txt with today's date inside it.` | `write` executed, **failed**: permission auto-rejected as in prompt 5 |
| 9 | `Search the files here for the word "hello" and tell me which files contain it.` | `task` (Explore Agent) executed, **succeeded** |
| 10 | `Delete hello.txt, then list the directory to confirm it is gone.` | no tool executed |

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 3338 bytes, SHA-256 `0e36e04d09d0262029dddd72037606a37fdd8e5aeabf46a86a388f02fe384f71`
- verify: chain_ok **True**, 14 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `task` | `error` | `reported-by-client` |  |
| 4 | `write` | `error` | `reported-by-client` |  |
| 6 | `task` | `error` | `reported-by-client` |  |
| 8 | `write` | `error` | `reported-by-client` |  |
| 11 | `glob` | `error` | `reported-by-client` |  |
| 10 | `task` | `ok` | `reported-by-client` |  |

- calls: **6**, results: **6**, calls without a result: **0**
- outcomes: `error` × 5, `ok` × 1

`palimpsests pala verify C:\runs\o3\serve.pala` exit code: **2**
Serve access log for the session: **12 posts to `/v1/pala/events`, all
answered 200** — six calls and six results, no refusals.

**The three counts.** Tools the client displayed as executed: **5**.
Pairs on the chain: **6**. Calls without a result: **0**. The chain
carries one tool *more* than the transcript showed: `glob` at seq 11,
nested inside the `task` at seq 10 — the Explore sub-agent's own tool
call, which the headless transcript does not print. Its result is `error`
while the parent `task` resolved `ok`; the sub-agent recovered, and both
facts are on the chain.

### Pass 2 — same ten prompts, `~/.claude/skills` moved aside (`C:\runs\o3b`)

Run 2 of this series named a foreign skills catalogue injected into
OpenCode's system prompt as the reason these local models stop calling
tools. That catalogue was found still present on this machine —
`~/.claude/skills/synced/<id>/`, 14 skills — and the model quoted it back
repeatedly during pass 1 (`available_skills`,
`C:\Users\Username\.claude\skills\synced\...`, "I can't determine which
skill to use"). It was moved out of the way, the ten prompts were
repeated on a fresh `C:\runs\o3b`, and it was moved back afterwards.
Nothing else changed.

| # | What the client displayed |
|---|---|
| 1 | `read` executed and **failed** (`SchemaError(Missing key at ["filePath"])`), then `read notes.txt` executed and **succeeded**; the model answered from the real file contents |
| 2 | `webfetch` executed, **failed**: `URL must start with http:// or https://` |
| 3 | no tool executed |
| 4 | no tool executed |
| 5 | no tool executed |
| 6 | no tool executed |
| 7 | `task` (General Agent) executed, **succeeded** |
| 8 | `write` executed, **failed**: `SchemaError(Missing key at ["content"])` |
| 9 | no tool executed |
| 10 | no tool executed |

- package: `palimpsests 0.13.1`
- file: `serve.pala`, 3341 bytes, SHA-256 `c58ab51b6ec7fd5eb93b7d547b68853753f33c73692709f19cc8f9f8bd040c75`
- verify: chain_ok **True**, 14 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `read` | `error` | `reported-by-client` |  |
| 4 | `read` | `ok` | `reported-by-client` |  |
| 6 | `webfetch` | `error` | `reported-by-client` |  |
| 9 | `read` | `ok` | `reported-by-client` |  |
| 8 | `task` | `ok` | `reported-by-client` |  |
| 12 | `write` | `error` | `reported-by-client` |  |

- calls: **6**, results: **6**, calls without a result: **0**
- outcomes: `error` × 3, `ok` × 3

`palimpsests pala verify C:\runs\o3b\serve.pala` exit code: **2**
Serve access log for the session: **12 posts to `/v1/pala/events`, all
answered 200**.

**The three counts.** Tools the client displayed as executed: **5**.
Pairs on the chain: **6**. Calls without a result: **0**. Again one more
on the chain than in the transcript: `read` at seq 9, nested inside the
`task` at seq 8.

**What moving the catalogue aside changed.** `ok` outcomes went from 1 to
3, and the `ok` pairs now carry `read` rather than only the sub-agent
wrapper `task`. The number of pairs did not change (6 and 6), nor did the
number of prompts that executed no tool at all (5 and 5, though not the
same five). On one session each, this is a single observation, not a
rate: it is consistent with the cause run 2 named and does not measure
its size.

## O6 — the `opencode` row of the 2026-11-02 surface check

From `results/surfaces-2026-11-02.md`, produced by
`scripts/check_surfaces.py` on this machine on the same day:

| Surface | State | Version | Detail |
|---|---|---|---|
| opencode | ⚪ SKIP | 1.18.31 | the client never reached the serve (0 completions) — an environment problem on this machine, not evidence about the surface |

That ⚪ is a checker-environment result and says nothing about the
surface. The runs above are the evidence about the surface, and they are
the opposite of a zero: 12 pairs across two ten-prompt sessions, all
paired, 4 of them `ok`.

## What did not land, and why

- **Both posts in O2 were refused `401`**, so neither the call nor the
  result of a tool the client really executed is on the `C:\runs\o2`
  chain. Cause established: no bearer in the client's environment.
- **Most prompts executed no tool at all** — 5 of 10 in each ten-prompt
  session, and 10 of 12 turns in O1. In every such case the model emitted
  tool-call JSON, often malformed, as answer text. Nothing was lost in
  recording: there was nothing to record. The chain carries no kind-10
  `TOOLS_OFFERED_NO_CALL` for these turns because the serve was not the
  model provider in this run and never saw the completions.
- **Two `write` calls were rejected before they ran** (O3 pass 1, prompts
  5 and 8). The model aimed at `/home/user/hello.txt` and
  `/path/to/dates.txt`, outside the working directory; headless `run`
  without `--auto` auto-rejects such a request. Both are on the chain as
  `error`, which is what happened.
- **No `cancelled` outcome appears.** No session was abandoned mid-call,
  so the plugin's pending-call path was not exercised.
- **The `detail` column is empty for every pair.** Under the
  reported-by-client route the serve records digests, not arguments.
- **`qwen2.5-coder:7b` produced nothing at all** (O1 attempt 2): zero
  executions, zero posts. Why that model never emits a structured call
  through `@ai-sdk/openai-compatible` while `llama3.1:8b` sometimes does
  is **not established here**.

## Limits of this run

One machine, one client version, one engine, two models, CPU inference
only. The serve was never the model provider, so this run says nothing
about the structured-loop route — only about the reported-by-client one.
Every session was headless (`opencode run` / `-c`); the TUI was not
exercised, and neither was `--auto`. The ten-prompt comparison with the
skills catalogue removed was run **once**, so it supports no rate and no
effect size. Nothing here measures behaviour under concurrency, over long
sessions, on another OS, or with a model strong enough to call tools
reliably — and the last of those is the binding limit on this machine:
the ceiling on pairs was set by the model, not by the recording path.

What the run does show, with the chain as evidence: when the client
executes a tool and the plugin can reach the serve, the call and its
result land together, marked `reported-by-client`, carrying the real tool
name, with no call left unpaired in 12 of 12 pairs.

---

This run was carried out with AI assistance.
