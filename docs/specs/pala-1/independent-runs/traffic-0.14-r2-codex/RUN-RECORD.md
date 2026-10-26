# Codex on real traffic — run 2, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Two stages in one chain. With the command hooks configured but **not
trusted**, a full prompt produced **zero** records — the untrusted hook
did not run, and nothing reached the serve. After trusting them, thirteen
calls and thirteen results landed, none without a result, every one
marked `reported-by-client`, and **every result `unobserved`** — including
the deliberate read of a file that does not exist. That is the correct
answer for this vantage: Codex has no failure hook, so the forwarder
cannot know whether a tool failed, and it does not pretend to.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `C:\runs\venv`) |
| Palimpsests | `palimpsests 0.13.0 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | codex-cli 0.164.0 |
| Model | the client's own default; not configured by this run |
| Adapter file SHA-256 | `palimpsests_hook.py` — `0ce0ce4dd0f3ff0b9823c42d150ededa6de405491bb484b4b55f7a00dbea7fd5` |
| Serve | `palimpsests-serve --api-key ***REDACTED***`, config dir `C:\runs\r2`, fresh at the start, carried across both stages |

## What was done

1. `%USERPROFILE%\.codex\hooks.json` was written with `PreToolUse` and
   `PostToolUse`, each `matcher: "*"`, each running
   `C:/runs/venv/Scripts/python.exe C:/runs/palimpsests_hook.py --client codex`.
   There was no previous file at that path.
2. The serve was started on a fresh `C:\runs\r2`; 200 with the bearer,
   401 without.
3. **A transport check was made before the session** by piping a
   hand-written event into the forwarder. The serve answered **400 Bad
   Request** — the credentials and route were accepted, the invented body
   was not. This produced one `POST /v1/pala/hooks/codex` in the access
   log and **no chain record**. It is noted here so the single pre-session
   post in the log is not read as client traffic.
4. **Stage 1 — hooks not trusted.** `PALIMPSESTS_SERVE_API_KEY` was
   exported, Codex was started in `C:\runs\scratch`, and at the startup
   trust prompt **"Continue without trusting (hooks won't run)"** was
   chosen. One prompt was run to completion: `Read notes.txt.` Codex was
   exited, the serve stopped, and the chain read.
5. **Stage 2 — hooks trusted.** The serve was restarted on the *same*
   directory, so the chain continues rather than restarting. Codex was
   started again, **"Trust all and continue"** was chosen, and the ten
   prompts were run one at a time:

   1. `Read notes.txt and tell me what it says.`
   2. `List the files in this directory.`
   3. `Read missing.txt.`
   4. `Run a command that prints the current date.`
   5. `Create a file hello.txt containing the word hello, then read it back.`
   6. `Append the line "second line" to notes.txt, then show me the whole file.`
   7. `How many lines and how many words does notes.txt have? Use a command.`
   8. `Create a file dates.txt with today's date inside it.`
   9. `Search the files here for the word "hello" and tell me which files contain it.`
   10. `Delete hello.txt, then list the directory to confirm it is gone.`

6. Codex was exited, the serve stopped, and the chain read again.

No step was retried.

## Result

### Stage 1 — hooks present but not trusted

- file: `serve.pala`, 312 bytes, SHA-256 `b88b6434c2ced5c7f4c48550c208109204b25ea3264aaa7e170dcdb7ab46ad24`
- verify: chain_ok **True**, 2 records (GENESIS + BOOT), diagnosis `none`
- calls: **0**, results: **0**, calls without a result: **0**
- outcomes: none

Nothing was posted to the serve by the client during this stage.

### Stage 2 — after trusting, same chain continued

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 7020 bytes, SHA-256 `c6b421c4ef088ec7153514ad9614df83d985542555ddbbfc91581e66e694c3a5`
- verify: chain_ok **True**, 29 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 3 | `Bash` | `unobserved` | `reported-by-client` |  |
| 5 | `Bash` | `unobserved` | `reported-by-client` |  |
| 7 | `Bash` | `unobserved` | `reported-by-client` |  |
| 9 | `Bash` | `unobserved` | `reported-by-client` |  |
| 11 | `Bash` | `unobserved` | `reported-by-client` |  |
| 13 | `Bash` | `unobserved` | `reported-by-client` |  |
| 15 | `Bash` | `unobserved` | `reported-by-client` |  |
| 17 | `Bash` | `unobserved` | `reported-by-client` |  |
| 19 | `Bash` | `unobserved` | `reported-by-client` |  |
| 21 | `Bash` | `unobserved` | `reported-by-client` |  |
| 23 | `Bash` | `unobserved` | `reported-by-client` |  |
| 25 | `Bash` | `unobserved` | `reported-by-client` |  |
| 27 | `Bash` | `unobserved` | `reported-by-client` |  |

- calls: **13**, results: **13**, calls without a result: **0**
- outcomes: `unobserved` × 13

`palimpsests pala verify C:\runs\r2\serve.pala` exit code: **2**

Serve access log, stage 2: 26 posts to `/v1/pala/hooks/codex`, **all 200**,
no refusals.

## What did not land, and why

- **Nothing was lost in stage 2.** Every post was accepted, every call
  paired.
- **Stage 1's zero is the finding, not a loss.** The hooks were on disk
  and correctly formed; Codex simply did not run them without trust. No
  record, no post, no error — the silence is complete, which is what the
  stage was for.
- **Every tool is recorded as `Bash`**, for the same reason as run 1:
  Codex routes file reads, searches and deletions through its shell tool.
  Thirteen pairs carry one tool name.
- **Thirteen pairs from ten prompts**: some prompts used a tool more than
  once. The chain carries no prompt text, so the mapping is not
  recoverable from it.

## Limits of this run

One machine, one client version, one session per stage. No abandonment
was provoked, so no `cancelled` outcome appears. The `unobserved` result
is the honest limit of this vantage rather than a property of the tools:
three of the thirteen calls certainly failed in the world (the read of
`missing.txt` among them), and the chain correctly declines to say so.
Nothing here shows what Codex does across restarts, or whether trust
persists.

### Two places the integration README does not match the client

- **Trust is offered at startup, not through `/hooks`.** `integrations/agent-hooks/README.md`
  says to open `/hooks` in a session and trust the entries there. On
  0.164.0 Codex asks before the first prompt, with
  *Review hooks / Trust all and continue / Continue without trusting*.
  Anyone following the text literally will look for a menu that is not
  there at that moment.
- **Codex asks to configure a sandbox on Windows** before the first
  prompt — *default sandbox (requires Administrator)* or *non-admin
  sandbox*. The README does not mention it. The non-admin option was
  taken here; the run's prompts and files are its own, so the risk that
  option names does not apply.

### The serve start line does not work

As recorded in run 1: `palimpsests serve --api-key …` exits with
`No such option: --api-key`, and moving the key into the environment
starts an endpoint that does not require it. Every run in this series
used `palimpsests-serve --api-key ***REDACTED***`, which enforces it
(401 without the bearer, measured).

---

This run was carried out with AI assistance.
