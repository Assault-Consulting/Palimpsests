# OpenCode run 2 — WS-INT

**The first reported-by-client tool pair is on the chain.** One `TOOL_CALL`
and its `TOOL_RESULT`, both marked `"source": 1`, bound by seq *and* hash,
carrying the real tool name `read` and real digests, produced by OpenCode
executing a tool in text mode against `palimpsests serve`. That is the
thing WS-INT exists to demonstrate, and it is demonstrated.

Everything else in this record is about why there is **one** pair and not
twenty, and the answer is not the serve: it is a foreign skills catalogue
injected into OpenCode's system prompt, which stops these local models
from calling tools at all. The rate at which a clean environment would
produce pairs is **not measured** here and this record does not estimate
it.

Companion to `../opencode-traffic-1/RUN-RECORD.md` (run 1) and to the
hook-probe result described in section 1 of the task, both of which this
run builds on.

## Environment

| | |
|---|---|
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Engine | Ollama 0.33.2 |
| Models | `llama3.1:8b` Q4_K_M, digest `46e0c10c039e019119339687c3c1757c…`; `qwen3:8b` Q4_K_M, digest `500a1f067a9f782620b40bee6f7b0c89…` |
| Install source | `main` checkout, editable — code identical to `b6c845e49c8f0d196a6a87c330e1db5fd1418fef` (the working tree also carries run 1's docs, which do not affect the build) |
| Version string | `0.11.0` (**not** the released 0.11.0 wheel — that build has neither `POST /v1/pala/events` nor kind 10) |
| OpenCode | 1.18.31 throughout (run 1 spanned 1.18.25→1.18.31; this run did not move) |
| OpenCode's Node runtime | v24.3.0 (the shell's own Node is v24.16.0 — the probe reports the former) |
| Audit plugin SHA-256 | `b33f7888dc2ee6f3aca0250fb7ad15ea10414496f6d84373f21fee9bc7b4909e` |
| Probe plugin SHA-256 | `65e206b8b20b5bdb11deff378117c300a7f2575515082a0c96afd96c4ffde00a` |
| Config dir | `<run>/config2` — fresh, so run 2's chain never mixes with run 1's |
| API key | `sk-run-***REDACTED***` |
| Scratch repo | `textkit`, reset to its initial commit before the run |

Both plugins were installed side by side for the whole run, as the task
asks: the probe records which callbacks fired, the audit plugin reports to
the serve, and where their counts disagree each explains the other.

## How the session was driven

Part of run 2 was driven by the operator in the TUI; the rest was driven
headless with `opencode run` by the assistant, after the operator handed
the session over. The reason is recorded because it affects nothing about
the chain but everything about reproducibility: **TUI ping-pong was too
slow to iterate**, and the evidence that matters — probe callbacks and
`POST /v1/pala/events` — is identical either way, since the TUI renders a
narrated tool block and an executed one the same. Where a step below says
"headless", it was `opencode run -m <provider>/<model> "<prompt>"` with
the probe-log, serve-URL and key exported into that process.

## Chronology

1. **Operator, TUI.** A junk turn (a PowerShell line pasted as a prompt,
   aborted with Esc). Then step 1 twice on `qwen3:8b`: both refused, and
   the refusal described a toolset belonging to something else entirely
   (quoted below). A text pseudo-call `/docs.read("README.md")` was
   printed rather than executed. The operator switched the model to
   `llama3.1:8b` and handed the session over.
2. **Headless, `llama3.1:8b` via serve, step 1, attempt 1.** No tool
   executed; the model said the text it was given looked like a Claude
   configuration file.
3. **Attempt 2, worded to force the tool.** No tool executed; the model
   denied being able to run tools at all. Per the operator's instruction
   this was the stop condition, so the raw requests were captured instead
   of pressing on.
4. **Raw capture through a TCP tee in front of the serve.** This is
   section "Prompts on the wire" below, and it exonerates the serve.
5. **Single-variable control: same model, straight to Ollama.** No tool
   executed — a text pseudo-call instead. So the serve path is not what
   distinguishes success from failure.
6. **`qwen3:8b` via serve, headless.** Refused, naming the foreign skills
   catalogue explicitly.
7. **Skills catalogue renamed away; `llama3.1:8b` via serve, one turn.**
   **The tool executed.** `hook:tool.execute.before` fired with
   `tool=read`, and the chain took its first reported pair.
8. **Seven-step session attempted.** All seven ran, but the skills
   directory had been restored automatically two minutes before it
   started, so every step ran contaminated again: zero tool executions
   across all seven.
9. **Three-attempt series with the catalogue renamed away.** Attempt 1
   hung before reaching the model; by attempt 2 the catalogue had been
   restored again — this time within five minutes. The series was stopped:
   it could not hold the condition it was testing.
10. **Stop and collect.** The serve was already down when the assistant
    went to stop it, and the chain is intact with no truncated tail, so it
    ended cleanly rather than being killed mid-write.

## Prompts on the wire — the serve is exonerated

Both paths were captured with a raw TCP tee and the tool-bearing request
compared field by field:

| | Ollama direct | through `palimpsests serve` |
|---|---|---|
| tools | 10 — `bash, edit, glob, grep, read, skill, task, todowrite, webfetch, write` | 10 — identical list |
| `tool_choice` | `auto` | `auto` |
| system prompt | **16 590 chars** | **16 595 chars** |
| `<available_skills>` block | present | present |
| skills enumerated | 9 | 9, same names |

The five-character difference is the working-directory and date text. The
serve neither drops, reorders nor rewrites anything: what OpenCode sends
is what the model receives. **No hypothesis in which the serve mangles
tool definitions survives this comparison.**

## The skills contamination

OpenCode 1.18.31 discovers skills from the user's home directory — the
strings `/.claude/skills/` and `.config/opencode/skill` are both present
in its binary — and injects their names, descriptions and **absolute file
paths** into its own system prompt as an `<available_skills>` block. On
this machine that pulled in eight skills belonging to a different tool
entirely, and grew the system prompt from run 1's 9 571 characters to
**16 595**.

The models were not hallucinating. They were reading what they were sent,
and five independent statements say so:

> **qwen3:8b, via serve:** "The current available tools do not include a
> specific skill for reading or processing Markdown files like
> `README.md`. The listed skills handle formats such as `.docx`, `.pdf`,
> `.xlsx`, `.pptx`, etc., but not Markdown."

> **llama3.1:8b, via serve, attempt 1:** "However, I don't see a README.md
> or textkit/core.py file in the provided text. The provided text appears
> to be a Claude configuration file with information about available
> skills."

> **llama3.1:8b, via serve, attempt 2:** "I don't have the ability to
> execute external tools or access local files."

> **llama3.1:8b, seven-step session, step 1:** "the package is a
> collection of skills and tools for Claude, a conversational AI
> assistant … The package also includes a skill creator tool … and a text
> kit for text processing" — the scratch repository and the foreign
> catalogue merged into one description.

> **llama3.1:8b, same session, step 2:** "I did find a reference to
> `top_words` in a file named `docs` (located at
> `…\.claude\skills\synced\<uuid>\docs\SKILL.md`)" — the model quoted a
> real absolute path to a file that has nothing to do with the project.

That last quote settles the source beyond argument, and it is also the
reason this belongs upstream twice over:

- **as a correctness bug** — a coding agent's system prompt should not be
  filled with another product's catalogue, and on a small local model the
  effect is not degradation but outright refusal to use any tool;
- **as a privacy matter** — the block puts absolute filesystem paths,
  including a home directory and account-scoped identifiers, into every
  prompt sent to whatever model the user has configured, local or
  remote. Nothing here consented to that.

The candidate is OpenCode's skill discovery, not `palimpsests serve` and
not the audit plugin.

## The contrast, and its one-sample limit

| condition | turns | tool executions | chain |
|---|---|---|---|
| `<available_skills>` present | ~10 across both models and both paths | **0** | kind 10 only |
| catalogue renamed away | 1 | **1** (`read`) | `TOOL_CALL` + `TOOL_RESULT`, both `source: 1` |

The direction is unambiguous and the mechanism is visible in the models'
own words. **The rate is not.** One success is not a frequency, and the
attempt to measure one failed for the reason below. This record therefore
claims that the contamination *blocks* tool use on these models, and
claims nothing about how often a clean environment would produce pairs.

### Why the frequency could not be measured

The skills directory is **restored automatically within about five
minutes** of being renamed — first observed as a two-minute gap before the
seven-step session, then as a five-minute gap inside the three-attempt
series, whose own log line records `skills_present=YES` on attempt 2. A
condition that cannot be held for the length of one series cannot be
measured by repetition. A sandboxed `HOME` without `.claude` was tried as
a stable alternative and did not work — see the environment findings.

## Numbers

Chain: `config2/serve.pala`, **23 records**, 5015 bytes.

| | |
|---|---|
| `pala verify` exit code | **2** (PARTIAL — no anchor supplied) |
| consistency | `23 records, chain intact` |
| advisories | 1 — `anchor_never_written` |
| truncated tail | **none** — the serve stopped cleanly |
| `chain_ok` / breaks / gaps / violations | `true` / `[]` / `[]` / `[]` |
| chain head | `b25d1976c9044d87dc98f38e94a34d5f0a62a7f0248699af0bf7d3050b4c4222` |
| chain SHA-256 | `0a8a63a021a0016c0c9f5c2bb425d10f718bffc5a4f8149b9f7d1534adeaddfd` |
| `run-export.jsonl` SHA-256 | `b2272744352736351a899925e0444e1d0df3fb3e6bd69551442ef2eb3ceac067` |
| `run-report.html` SHA-256 | `9d0a5f2198267cc629e6f1e3daa49a84be80608559a5359815534107e0ef7d56` |
| `probe-run2.jsonl` SHA-256 (trimmed, see Files) | `57f8f22e783f334fd968db808efc3eca4c0c3c8e1b97740cc506a5e5a0f9dab2` |

| Counter | Value |
|---|---|
| `TOOL_CALL` (kind 8) | **1** |
| `TOOL_RESULT` (kind 9) | **1** |
| `"source": 1` (reported-by-client) | **2** — the call and its result |
| `"source": 0` (wire-parsed) | **0** |
| `TOOLS_OFFERED_NO_CALL` (kind 10) | 19 |
| outcomes | `error: 1` |
| tool names seen | `read` |
| probe `hook:tool.execute.before` | 1 |
| probe `hook:tool.execute.after` | 0 |

Export and report were written with `-o`, never a shell redirect — run 1's
CRLF finding applies and the task now says so explicitly.

### The pair, as evidence

```
seq 10  EVENT  kind 8  TOOL_CALL    source 1
        0x000c = "read"                    (tool name)
        0x000d = 7d6441497d2a000b…         (argument digest)
        0x0011 = 1                         (reported-by-client)

seq 11  EVENT  kind 9  TOOL_RESULT  source 1
        0x0008 = 10                        (references seq 10)
        0x0009 = ebe16137e74ac2ed…         (= record_hash of seq 10)
        0x000e = 1                         (outcome: error)
        0x000d = 462c753b21607d75…         (result digest)
        0x0011 = 1                         (reported-by-client)
```

The result's `0x0009` is byte-for-byte the call's `record_hash`. The pair
is bound by sequence number *and* by hash, which is precisely the binding
the design claims and the reason a result cannot be re-pointed at a
different call after the fact.

The result carries `error`, and the probe shows `tool.execute.before`
without a matching `after`. Both are consistent with the plugin's own
documented fallback: where `tool.execute.after` does not fire — the
comment in the plugin says "or not on failure" — the terminal state is
picked up from `message.part.updated` instead. So this pair travelled the
fallback path, not the primary one, and still arrived correctly bound.

## The four checks

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | `TOOL_CALL` count > 0 | **PASS** | 1 — `read`, seq 10, the first on any chain |
| 2 | every reported call and result carries `"source": 1` | **PASS** | `source:1` = 2 of 2; `source:0` = 0 — nothing masquerades as a wire-parsed observation |
| 3 | every `TOOL_RESULT` resolves to its call; no `reference_unresolved` / `reference_hash_mismatch` | **PASS** | `pala verify` reports one advisory, `anchor_never_written`, and no reference advisories; the result's `0x0009` equals the call's `record_hash` |
| 4 | at least one `error` outcome, ideally one `cancelled` | **PARTIAL** | `error: 1` present. No `cancelled`: the abandonment step never ran under a clean condition, and the serve ended cleanly with no call left outstanding |

Three of four pass outright, the fourth in half.

## Findings

**1. The serve is not the variable.** Identical requests on both paths, to
the character; the same model fails identically without the serve in it.
Any future "OpenCode does not work with our endpoint" report should
compare the wire first, because that comparison took ten minutes and
closed the question.

**2. The contamination is the blocker, and it is upstream.** Documented
above with five quotes and a byte count. Correctness and privacy angles
both apply.

**3. The reported-pair path works end to end**, through the fallback
surface, with correct tool name, digests, outcome and hash binding.

**4. `tool.execute.after` did not fire for a tool that did execute.**
Exactly the case the plugin's fallback exists for, now observed on real
traffic rather than assumed. Worth keeping the fallback.

**5. The skills catalogue restores itself within ~5 minutes.** This makes
"rename it away" useless as an experimental control and would make it
useless as a user workaround too. Any fix has to be in OpenCode, or in a
setting it honours.

**6. `opencode run` hangs on the first run after the provider `baseURL`
changes.** Observed three times, with the same signature every time: the
log reaches `init`, then `cleanup prune=7.days`, then nothing; Ollama
reports no model resident, so no inference was ever requested. A retry
usually succeeds. Anyone scripting `opencode run` around a config change
should expect this and add a timeout.

**7. A killed `opencode run` leaves a process that blocks the next one.**
Four stale `opencode.exe` processes were found at one point, one holding
1.35 GB. New runs then hang in a way indistinguishable from finding 6.

**8. Repeated hard kills degrade OpenCode's own state.** Its SQLite
write-ahead log reached 4.1 MB against an 888 KB database, and recovery of
that log on startup is the most likely reason later runs hung before
reaching the model. This is self-inflicted — the lesson is that a
headless measurement loop should stop instances gracefully, or it
poisons its own later samples.

**9. The frequency of tool use is unmeasured**, and deliberately not
estimated. See the contrast section.

## What this proves, and what it does not

It proves that a tool OpenCode executed in text mode — where the serve
sees nothing structured on the wire — reached the chain as a
`TOOL_CALL`/`TOOL_RESULT` pair marked `reported-by-client`, bound by seq
and hash, with the real tool name and real digests, from real traffic.

It does **not** prove the tool ran. The chain proves the client asserted a
call and a result, and when. The `error` outcome on this pair is the
client's assertion about its own execution, and nothing in the chain
verifies it.

It does not establish how often this happens in a session, and this record
gives no number for that.

## Claim wording

For the README, the sentence this record supports:

> With the OpenCode plugin installed, a tool that OpenCode executed in
> text mode appeared on the chain as a `TOOL_CALL`/`TOOL_RESULT` pair
> marked `reported-by-client`, bound by sequence number and hash, with the
> tool's real name and real digests — the path demonstrated end to end on
> real traffic. How often a session produces such pairs was not measured;
> in this run a foreign skills catalogue injected into OpenCode's system
> prompt prevented the local models from calling tools at all.

What must **not** be written: any rate or count implying routine capture,
and anything attributing the empty turns to `palimpsests serve` — the
captured requests rule that out.

## Files beside this record

- `run-export.jsonl` — full JSONL export, 23 records + summary (`-o`, not a redirect)
- `run-report.html` — `pala report --html`
- `run-chain.pala` — the chain itself
- `probe-run2.jsonl` — the plugin callbacks of run 2, the independent execution
  counter. **Trimmed for size**: every `loaded` and every `hook:*` line is kept
  in full — those are the evidence — while `event:*` lines are reduced to the
  first occurrence of each type. The full log was 3 256 lines, 2 295 of them
  `event:plugin.added`; the trimmed file carries a `_census` of the original as
  its first line. All 24 hook lines survive, including the single
  `hook:tool.execute.before` that produced the pair.

The raw wire captures are **not** in this directory, for two separate reasons,
both stated rather than glossed: the capture on the serve path was overwritten
by a later run before it could be archived, so only the figures analysed from it
survive (quoted in full above); and the capture on the Ollama-direct path is
intact but carries the operator's absolute home paths and an account-scoped
identifier inside the injected skills block, so it is withheld and quoted in
fragments instead.
