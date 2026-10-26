# Claude Code on real traffic — run 1, 0.14

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Eleven tool calls and eleven results reached the chain from a ten-prompt
Claude Code session, every one marked `reported-by-client`, none left
without a result. Ten resolved `ok` and one `error` — the deliberate read
of a file that does not exist. Four of the twenty-six hook posts the serve
received were refused with `empty bearer`; the chain is intact and
self-consistent, but those four represent hook deliveries that did not
become records, and the reason is not established.

## Environment

| | |
|---|---|
| Date | 2026-10-26 |
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Python | Python 3.12.10 (venv at `C:\runs\venv`) |
| Palimpsests | `palimpsests 0.13.0 · PALA-1 v1.0 (core, frozen) · inference r6` |
| Client | Claude Code 2.1.310 |
| Model | Claude Fable 5.1 (the client's own model; not configured by this run) |
| Adapter file SHA-256 | none — HTTP hooks, no forwarder file |
| Serve | `palimpsests-serve --api-key ***REDACTED***`, config dir `C:\runs\r1`, fresh for this run |

## What was done

1. The three HTTP hooks were written into
   `%USERPROFILE%\.claude\settings.json` — `PreToolUse`, `PostToolUse`,
   `PostToolUseFailure`, each with `matcher: "*"`, the URL
   `http://127.0.0.1:11435/v1/pala/hooks/claude`, an `Authorization:
   Bearer $PALIMPSESTS_SERVE_API_KEY` header and
   `allowedEnvVars: ["PALIMPSESTS_SERVE_API_KEY"]`. The pre-existing
   file held only `model` and `theme`; both were preserved and a backup
   was kept.
2. The serve was started on a fresh `C:\runs\r1`. Key enforcement was
   checked before the session: `GET /v1/models` returned 200 with the
   bearer and 401 without it.
3. `PALIMPSESTS_SERVE_API_KEY` was exported in the window Claude Code was
   launched from, and the session was started in `C:\runs\scratch`.
4. `/hooks` was run in the session; all three hooks were present.
5. Ten prompts, one at a time, each to completion:

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

6. The session was exited, the serve stopped, and the chain read.

No step was retried.

## Result

- package: `palimpsests 0.13.0`
- file: `serve.pala`, 5856 bytes, SHA-256 `42342327e702959b3c6b1996990d91b545888a6d3b7ffa3d4f526ada02a37c7f`
- verify: chain_ok **True**, 24 records, diagnosis `none`
- advisories: 1 — anchor_never_written

| call seq | tool | outcome | source | detail |
|---|---|---|---|---|
| 2 | `Bash` | `ok` | `reported-by-client` |  |
| 4 | `Bash` | `ok` | `reported-by-client` |  |
| 6 | `Bash` | `error` | `reported-by-client` |  |
| 8 | `Bash` | `ok` | `reported-by-client` |  |
| 10 | `Bash` | `ok` | `reported-by-client` |  |
| 12 | `Bash` | `ok` | `reported-by-client` |  |
| 14 | `Bash` | `ok` | `reported-by-client` |  |
| 16 | `Bash` | `ok` | `reported-by-client` |  |
| 18 | `Bash` | `ok` | `reported-by-client` |  |
| 20 | `Bash` | `ok` | `reported-by-client` |  |
| 22 | `Bash` | `ok` | `reported-by-client` |  |

- calls: **11**, results: **11**, calls without a result: **0**
- outcomes: `error` × 1, `ok` × 10

`palimpsests pala verify C:\runs\r1\serve.pala` exit code: **2**

Serve access log for the session: 26 posts to `/v1/pala/hooks/claude` —
**22 answered 200, 4 answered 401**.

## What did not land, and why

- **Four hook posts were refused with `empty bearer`** and are not on the
  chain. The serve's message names the cause it expects — a hook header
  using `$PALIMPSESTS_SERVE_API_KEY` without that variable listed in
  `allowedEnvVars` — but the variable *was* listed, for all three hooks,
  and the other twenty-two posts from the same session carried the key
  and were accepted. Why four deliveries arrived without it is **not
  established by this run**. Whether they correspond to tool calls absent
  from the chain, or to duplicate deliveries of calls already recorded,
  is also unknown: the chain pairs cleanly and shows no gap.
- **Every tool is recorded as `Bash`.** The ten prompts deliberately
  exercised reading, writing, searching and deleting, but Claude Code
  routes those through its shell tool, so the chain carries one tool name
  eleven times. This is what the client did, not a loss in recording —
  but a reader should not expect tool variety here to reflect prompt
  variety.
- **Eleven pairs from ten prompts**: one prompt used a tool twice. Which
  one is not identifiable from the chain, which carries no prompt text.

## Limits of this run

One machine, one client version, one session, ten prompts. The model was
whatever the client had configured and was not controlled for. No
abandonment was provoked, so no `cancelled` outcome appears. The run
shows that the HTTP hook route records a session's tool loop end to end;
it does not show behaviour under concurrency, over long sessions, or on
any other OS. The four refused posts mean this run cannot claim that
*every* tool call Claude Code executed reached the chain — only that
every call that reached it was paired and marked correctly.

### A defect in the instructions, not in this run

The documented way to start the serve does not work. Section 0 gives
`palimpsests serve --api-key ***REDACTED***`; in 0.13.0 the `serve`
subcommand has only `--host` and `--port`, and that line exits with
`No such option: --api-key`. Worse, the obvious repair — moving the key
into `PALIMPSESTS_SERVE_API_KEY` and running `palimpsests serve` — starts
an endpoint that **does not require the key at all**: measured here,
`GET /v1/models` answered 200 with no credentials. The subcommand does
not read that variable; it is a default for the separate console script's
own argument. The form that enforces the key, and the one used for every
run in this series, is:

    palimpsests-serve --api-key ***REDACTED***

This affects all five runs in the series, and anyone following section 0
literally will hit it before the first prompt.

---

This run was carried out with AI assistance.
