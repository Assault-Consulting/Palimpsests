# WS-E smoke-run — run record (§9)

**Task:** verify OpenCode can drive `palimpsests-serve` (OpenAI-compatible
endpoint over the Ollama L1 engine) end-to-end with a recorded PALA-1 tool loop
(EVENT kind 8 TOOL_CALL / kind 9 TOOL_RESULT).

**Operator:** Oleksandr (olksandrvertel@gmail.com). **Platform:** Windows 11 Pro
(git-bash + PowerShell). **Date:** 2026-08-28 … 2026-08-30.

**Verdict:** **DONE, WITH FINDINGS.** The serve records a structured, hash-chained
tool loop correctly and is not the limiting factor; the audited loop (kind 8/9)
materialises only when the model actually emits *structured* OpenAI `tool_calls`.
Under OpenCode's ~9.5K-char system prompt none of the four local models tried did
so — they narrated the tool call as markdown text — so the operator's end-to-end
TUI chain recorded no kind 8/9. This is a **model × prompt** limitation, proven
below, not a serve/adapter defect.

---

## Versions / SHAs (everything under test)

| Component | Version |
|---|---|
| palimpsests | 0.10.0 @ `472156948dca4ba829116a87588e3041c6f2c0a6` (`main`) |
| ollama | 0.33.2 |
| opencode | 1.18.25 |
| qwen2.5-coder:7b | Q4_K_M, 7.6B |
| qwen2.5-coder:14b | Q4_K_M, 14.8B |
| qwen3:8b | Q4_K_M, 8.2B |
| llama3.1:8b (diag control model) | Q4_K_M, 8.0B |

Install pin: `palimpsests[serve] @ git+…@main`; `cbor2==5.6.5` (pycose 1.1.0
compat); `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` (base install, no sqlcipher3 —
chain still hash-chained).

---

## Chronology

1. **TUI false-starts (operator, by hand).** Four attempts through OpenCode's
   TUI — qwen2.5-coder:7b ×2, qwen2.5-coder:14b ×2 — all identical: the model
   returns tool commands/names as **plain text**; no execution blocks; nothing
   recorded to the operator's `serve.pala`.

2. **qwen not tool-capable in Ollama.** Direct curl to Ollama
   `/v1/chat/completions` *and* `/api/chat` for qwen2.5-coder (7b and 14b):
   `tool_calls: null`, the tool JSON returned as text `content`. llama3.1:8b on
   the same two endpoints returns structured `tool_calls`. → qwen2.5-coder is not
   tool-tagged in its Modelfile template.

3. **Serve is clean (curl proof).** With a tool-capable model (llama3.1:8b), the
   serve returns structured `tool_calls` + `finish_reason: tool_calls` + real
   usage (155/34/189) **and records TOOL_CALL to `serve.pala`** (+229 bytes for a
   streaming curl; both stream and non-stream record). The diag chain holds
   **5× kind 8 TOOL_CALL** from these controls.

4. **OpenCode anomaly.** With llama3.1:8b behind OpenCode, the tool loop runs in
   the TUI but the serve records **0** structured cycles. Isolated with a raw TCP
   tee-proxy (11437 → diag serve 11436) capturing every byte.

5. **Root localised — model × prompt (airtight).**
   - OpenCode's request is well-formed: `req#1` = **10 tools**
     `[bash, edit, glob, grep, read, skill, task, todowrite, webfetch, write]`,
     `stream:true`, 2 messages (`system`, `user`), **system_prompt = 9571 chars**
     (`"You are opencode, an interactive CLI tool…"`).
   - Serve response to that exact request: `finish_reason: stop`,
     `tool_calls: false`, content = **narrated markdown**
     `` `echo "smoke-run OK" > hello.txt && cat hello.txt && ls -la` ``.
   - **Control matrix** (llama3.1:8b, OpenCode's *exact* 10 tools, via curl):

     | Tools | Prompt | Result |
     |---|---|---|
     | full 10 | simple 1-line | **structured `tool_calls`** |
     | trimmed 3 (write/read/bash) | simple 1-line | **structured `tool_calls`** |
     | single (write) | simple 1-line | **structured `tool_calls`** |
     | full 10 + 9571-char OpenCode system prompt (verbatim replay) | — | `finish_reason: stop`, **text**, no `tool_calls` |

     Toolset size is *not* the trigger; the heavy system prompt is. The model
     narrates the tool call as markdown, OpenCode text-parses and executes it
     locally, and the serve honestly records no structured cycle.

6. **Green-pair attempt — qwen3:8b (step 3.5, one attempt, no retries).**
   Pulled qwen3:8b (Q4_K_M), added to the operator's `opencode.json` (baseURL
   `127.0.0.1:11435/v1`, operator's serve), operator ran one TUI attempt. The
   operator's chain still recorded **0 kind 8/9** → **not verified-green**.
   qwen3:8b under OpenCode's system prompt behaves like the others. Consistent
   with the model × prompt root cause.

   **UI-render caveat (important).** OpenCode's TUI renders a structured tool
   call and a *text-parsed* one identically — both surface as tool blocks in the
   terminal. So "the run looked green in the TUI" is **not** evidence of an
   audited loop: visible blocks ≠ kind 8/9. The source of truth is the chain, and
   the operator's chain held **kind 8 = 0** on a visually "green" run. Only the
   recorded PALA-1 stream distinguishes a structured, hash-chained tool cycle from
   a narrated one the client executed locally.

---

## Chain results (§4.2)

Two **distinct** chains, both verified read-only/header-only, no `--anchor`
(so `completeness: NOT CHECKED`, advisory `anchor_never_written` — expected,
honest; not a failure):

| Chain | Path | Records | kind 8 TOOL_CALL | kind 9 TOOL_RESULT | `pala verify` | `pala report` |
|---|---|---|---|---|---|---|
| **operator** | `~/.config/palimpsests/serve.pala` | 2 (GENESIS+BOOT) | 0 | 0 | exit **2** PARTIAL, chain intact, consistency clean | exit 0 |
| **diag** | `~/smoke-diag/config/serve.pala` | 8 | **5** | 0 | exit **2** PARTIAL, chain intact, consistency clean | exit 0 |

- **Operator chain** = genesis + boot only: the TUI produced no structured tool
  call to record. Honest emptiness, not a break.
- **Diag chain** = 5 TOOL_CALL from the direct control curls on llama3.1:8b
  through the serve — proof the serve records a structured, hash-chained tool
  loop correctly. kind 9 = 0 because the controls sent only the first hop; no
  `role:tool` result was posted back to close the round-trip. (No CANCELLED
  records surfaced.)

`chain_ok: true` on both; `breaks: []`, `gaps: []`, `violations: []`.

---

## Primary evidence (verbatim, from the tee-proxy capture)

OpenCode's tool request (`req#1`), head of body:

```
{"role":"user","content":"\"Create a file hello.txt with the line \\\"smoke-run OK\\\", then read it back and tell me its exact contents. Then run ls -la and summarize.\""}],"tools":[{"type":"function","function":{"name":"bash","description":"Executes a given bash command in a persistent shell session with optional timeout…"
```

- n_tools = **10**, n_messages = **2**, stream = **true**, system_prompt = **9571 chars**.

Serve response to it (SSE reconstruction): `finish_reason: stop`,
`tool_calls` substring absent, 8 content deltas reconstructing:

```
Creating a file and reading its contents`echo "smoke-run OK" > hello.txt && cat hello.txt && ls -la`
```

---

## WS-E verdict & conditions

The audited tool loop (PALA-1 kind 8/9) is obtained **iff** (1) a tool-capable
model **and** (2) the model actually emits structured `tool_calls`, which is
**model × prompt** dependent. llama3.1:8b emits them for simple prompts but not
under OpenCode's ~9.5K-char system prompt; qwen2.5-coder (7b/14b) is not
tool-tagged at all; qwen3:8b did not emit them under OpenCode either.

**Serve conclusion:** not a serve or adapter defect — a *visibility* limitation
driven upstream of the serve, in the model's decoding under a heavy system
prompt. The serve records faithfully exactly what the model emits.

**Follow-up (maintainer's call):** candidate note / issue that OpenCode-class
system prompts suppress structured tool-calling on these local models; consider a
docs banner on the serve smoke-run that a tool-capable model *and* a
tool-call-friendly prompt are both required for kind 8/9 to appear.

## Artifacts (this dir)

- `operator-report.json`, `operator-report.html`, `operator-export.jsonl`, `operator-opencode.json`
- `diag-report.json`, `diag-report.html`, `diag-export.jsonl`, `diag-opencode.json`
- proxy captures (primary evidence): `proxy_req.log`, `proxy_resp.log`
- diagnostic scripts (as-ran, unpolished): `scripts/proxy.py`, `scripts/parse_bodies.py`, `scripts/control.py`, `scripts/replay_exact.py`

**Redaction note.** The one-time smoke API key (`sk-07b0ade2…`) is masked to
`sk-***REDACTED***` in `proxy_req.log` (Authorization header lines only — request
bodies untouched) and in `scripts/control.py` / `scripts/replay_exact.py`. The
scripts' hardcoded local paths were generalized to relative (`proxy_req.log`),
removing the operator's home path. No other content was altered.
