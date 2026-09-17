# OpenCode real-traffic run 1 — WS-INT

One ~45-minute OpenCode session against `palimpsests-serve` on a local
qwen3:8b, driving a real scratch repository. **Zero reported tool pairs
reached the chain**: the client plugin loaded and announced itself but
never emitted an event, on either OpenCode version the session spanned.
What the chain does carry is the serve's own boundary record — nine
`TOOLS_OFFERED_NO_CALL` (kind 10) events, one for every turn where tools
were offered and no structured call came back.

This is a measurement, not a demonstration. The plugin was not fixed and
the session was not re-run.

## Environment

| | |
|---|---|
| Machine / OS | workstation, Windows 11 Pro 10.0.26200 |
| Engine | Ollama 0.33.2, `ollama` L1 (active) |
| Model | `qwen3:8b`, Q4_K_M, 8.2B |
| Model digest | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |
| Install source | **`main` checkout, editable (`pip install -e '.[serve]'`)** — commit `b6c845e49c8f0d196a6a87c330e1db5fd1418fef` |
| Version string | `0.11.0` (`main` is not yet bumped past the release — this is **not** the released 0.11.0 wheel) |
| `palimpsests --version` | does not exist: `No such option: --version` |
| selftest | `sound: this build reproduces the published expectations` |
| selftest characteristic | `characteristic: 20001 records, verify 27,943 rec/s (0.72 s), py-heap peak 4.1 MB = 205 B/record (tripwire 512) — ok` |
| OpenCode | **started 1.18.25, self-updated to 1.18.31 mid-run** — the session spans both |
| Plugin | `integrations/opencode/palimpsests-audit.js` from `main` |
| Plugin SHA-256 | `b33f7888dc2ee6f3aca0250fb7ad15ea10414496f6d84373f21fee9bc7b4909e` |
| Config dir | `palimpsests-run/config` (fresh — the chain is this run only) |
| Scratch repo | `textkit`, a 6-file Python package, `git init` + 1 commit, 3 tests passing at baseline |

### Why not the released wheel

The run was set up against PyPI `palimpsests[serve]==0.11.0` first. That
build cannot exercise this feature at all: its server registers exactly
two routes — `GET /v1/models` and `POST /v1/chat/completions`. There is
no `POST /v1/pala/events` for the plugin to report into, and no
`KIND_TOOLS_OFFERED_NO_CALL`. Both exist only on `main`. The install was
therefore switched to the `main` checkout and the claim scoped to `main`
accordingly — "the released wheel works with OpenCode" is a different
sentence, and this run does not support it.

## What was done

Seven steps were planned; six were performed and one was skipped. Times
are the model's wall-clock per turn, from the operator's notes.

1. **Read** — attempt 1: the model *refused*, answering "I cannot read
   files directly"; no tool was invoked (3m24s). Attempt 2, reworded to
   "use your read tool", performed the read (3m19s).
2. **Search** — attempt 1: wrong tool — a WebFetch against the OpenCode
   docs instead of a grep over the repository, and no substantive answer
   (1m51s). Attempt 2, "use your grep tool", performed the grep (1m8s);
   the prose summary was left unfinished.
3. **Write** — three `edit_file` calls in one turn (2m34s): `char_count`
   into `textkit/core.py`, an export written to `textkit/init.py`
   (**the model dropped the underscores** — it should have been
   `__init__.py`), and five asserts into `tests/test_core.py`. Not
   corrected: this is real traffic.
4. **Run** — `bash` with `python -m pytest -q /think` — the model glued
   its reasoning marker `/think` onto the command (1m48s). The result was
   not surfaced in the TUI.
5. **Failure** — `python -m pytest tests/test_missing.py`, a file that
   does not exist; executed (40.6s).
6. **Cancellation** — **skipped**. The `sleep(120)` finished before it
   could be interrupted (the block appeared already complete, 2m8s), so
   no `cancelled` outcome arose naturally. Section 2 permits skipping
   with a note.
7. **Prose** — a plain question answered with no tool use (1m18s).

Mid-session the operator restarted OpenCode once (~18:19Z) to diagnose a
suspected missing plugin banner. That was a false alarm — the banner had
scrolled past before the log tail started. The restart is why the
OpenCode version changed underneath the run, and it incidentally created
a second plugin directory (see Findings).

## Numbers

Chain: `config/serve.pala`, 11 records, 2301 bytes.

| | |
|---|---|
| `pala verify` exit code | **2** (PARTIAL — no anchor supplied) |
| consistency | `11 records, chain intact` |
| advisories | 1 — `anchor_never_written` |
| `chain_ok` / breaks / gaps / violations | `true` / `[]` / `[]` / `[]` |
| chain head | `087957683c812a7175ab388171f86093dedbbd073f47f99142e2a6367358b8c2` |
| chain SHA-256 | `89d925ea9821cefa7cfa94e67013e9d4f976afd9c36800fa63daac05c43f7b19` |
| `run-export.jsonl` SHA-256 | `f452d36c1f446bcc89866af508fdc44b474c17178aca1d9692a3a67c9f113c91` |
| `run-report.html` SHA-256 | `7733403438e138d15d4a71c74a815751d2a9ead4039fc09ef0b4a6722a61bcfa` |

Record census: `GENESIS` x1, `BOOT` x1, `EVENT` x9.

| Counter | Value |
|---|---|
| `TOOL_CALL` (kind 8) | **0** |
| `TOOL_RESULT` (kind 9) | **0** |
| `"source":1` (reported-by-client) | **0** |
| `"source":0` (wire-parsed) | **0** |
| `TOOLS_OFFERED_NO_CALL` (kind 10) | **9** |
| outcomes (0 ok / 1 error / 2 timeout / 3 cancelled) | none — there are no `TOOL_RESULT` records |
| tool names seen | none — there are no `TOOL_CALL` records |

The nine kind-10 records, 18:08:05Z through 18:47:36Z, each carry
`EVT_TOOLS_OFFERED = 11` and the same `EVT_TOOLS_DIGEST`
`5eecda0d43969ad5def0b951eb0c0d11eeba009fa509dca004c3e5d8db258e1b`
(one distinct toolset across the whole session). Origin role on every
record: `engine.native`.

Serve access log for the session: **11 x `POST /v1/chat/completions` 200**,
**0 x `POST /v1/pala/events`**. Two of the eleven completions offered no
tools (OpenCode's own title-generation turns), which is why nine turns
produced a kind-10 record and eleven did not.

## The four checks

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | `TOOL_CALL` count > 0 | **FAIL** | `TOOL_CALL (kind 8): 0`; census is `{GENESIS:1, BOOT:1, EVENT:9}` and all nine EVENTs are kind 10 |
| 2 | every reported call and result carries `"source":1` | **vacuous — nothing to check** | `"source":1 = 0` *and* `"source":0 = 0`; there are no call or result records at all, so nothing is masquerading as a wire-parsed observation either |
| 3 | every `TOOL_RESULT` resolves to its call — no `reference_unresolved` / `reference_hash_mismatch` | **PASS (vacuously)** | `pala verify` reported exactly one advisory: `advisory: 1 note(s) — anchor_never_written`. No reference advisories |
| 4 | at least one `error` outcome, ideally one `cancelled` | **FAIL** | no `TOOL_RESULT` records, hence no outcomes. Step 5 did run a failing command client-side; step 6 was skipped (above) |

Check 1 failing puts this run in section 5, row 1.

## Findings

**1. The plugin loaded and stayed silent — on both OpenCode versions.**
This is the run's central finding. The banner
`message="reporting tool events to http://127.0.0.1:11435/v1/pala/events"`
appears three times: `18:02:32.918Z` (run `772e5ca2`, the 1.18.25
session) and `18:19:17.629Z` + `18:19:17.630Z` (run `2ba2a9af`, the
1.18.31 session). After that the plugin never posted anything. It is not
a connectivity failure: the plugin logs `call report failed: ...` /
`result report failed: ...` on a rejected fetch, and the log contains
**zero** such lines — all 122 lines are `level=INFO`, with no `WARN` and
no `palimpsests-audit` service line. No fetch was attempted, so neither
`tool.execute.before` / `tool.execute.after` **nor** the
`message.part.updated` fallback ever ran. Section 5, row 1: hooks never
fired, and the fallback stayed silent with them. This spans **1.18.25 and
1.18.31** — the version change mid-run widened the finding rather than
explaining it. Upstream #25918 / #27900 territory.

**2. The serve's own boundary record is the only thing that fired — and
it fired on every eligible turn.** Nine tool-offering completions, nine
kind-10 records, no gaps. The endpoint correctly recorded "tools were
offered, nothing structured came back" without any client cooperation.
That path is independent of the plugin and demonstrably works on real
traffic.

**3. qwen3:8b produced no structured tool calls either.** `"source":0`
is also 0, so the model never emitted OpenAI-structured `tool_calls`
under OpenCode's system prompt — it worked in text mode throughout. This
reproduces the #189 smoke-run finding on a different model, and it is
exactly the configuration the reported-pairs path exists to cover.

**4. Duplicate plugin load.** The diagnostic restart left a copy of the
plugin in a `plugin\` directory alongside the intended `plugins\`.
OpenCode loaded **both** — hence two banners one millisecond apart at
18:19:17Z. Neither emitted events, so the counters are unaffected, but a
duplicate load is silent and worth knowing about.

**5. OpenCode self-updated mid-run** (1.18.25 to 1.18.31 on restart),
unprompted. For a run whose whole subject is version-specific hook
behaviour, an unpinned auto-updating client is a hazard: the version you
set up is not necessarily the version you measured.

**6. `palimpsests --version` does not exist.** Section 1.1 of the task
asks for that line; the CLI answers `No such option: --version` and
offers no `version` subcommand. The version had to be taken from
`pala selftest` and `palimpsests.__version__`.

**7. `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1` is required for the serve to
be usable.** Without it — and a plain `[serve]` install has no
`sqlcipher3` — `GET /v1/models` raises `AuditIntegrityError`, so OpenCode
cannot list models at all. The PALA recorder itself is unaffected:
`default_audit()` writes `serve.pala` through `PalaWriter` and never
touches the encrypted audit DB, so the banner reads "structured tool
loops recorded to serve.pala" either way. A user following the task text
verbatim on a machine without the encryption extra hits this before the
first turn.

**8. Model-quality observations** (qwen3:8b, real toolset and real
prompt — not defects in this project, but they shape what a run like this
can exercise): it denied having tools on the first turn; it chose the
wrong tool on an implicit request (WebFetch instead of grep); it needed
explicit "use your X tool" phrasing to act; it glued its `/think`
reasoning marker into a bash command; and it wrote `textkit/init.py`
where `__init__.py` was meant.

**9. Anchor.** `palimpsests models` warns `audit head anchor could not be
stored in the OS keychain; rows are chained but unanchored`. Expected on
this machine — no anchor store configured — and it is the reason
`pala verify` exits 2 with `anchor_never_written`.

**10. On Windows, the section 3 capture command changes the export's
bytes.** The task's `pala export "$CH" > run-export.jsonl` sends stdout
through the console's text mode, which rewrites every LF line ending as
CRLF: the export as first captured here had 12 CRLF line endings and
SHA-256 `e03cb9b0be7591c7d1e3e14c64c772b49c71d44112cda6baf8139a0d7c8d44c5`.
The content is identical — converting those line endings back to LF gives
the tool's own output byte for byte — but that digest cannot be
reproduced from the chain on any other platform. The export in this
directory was therefore written with `pala export -o`, which writes the
bytes itself; the digest in the Numbers table is what anyone regenerating
from `run-chain.pala` gets. On Windows, capture with `-o`, not a redirect.
`run-report.html` was written with `-o` from the start and is unaffected.

## What this proves, and what it does not

It proves that the serve records its own boundary honestly on real
traffic: for every completion where tools were offered and nothing
structured came back, there is a kind-10 record, bound in the chain, with
the count and a digest of the offered tool-name list.

It does **not** prove that OpenCode tool calls appear on the chain as
reported pairs. On this client, on both versions tested, they did not —
the reporting plugin never fired. Nothing here says a tool ran; nothing
here is a `TOOL_CALL`. Had reported pairs appeared, the discipline would
still hold: *the chain proves the client asserted a call and a result,
and when* — never that the call executed.

The chain carries no scratch-repository metadata. A full TLV scan of all
11 records yields only the origin role `engine.native`, the kind, the
offered-tool count, and a 32-byte digest; a byte scan of the chain finds
no file paths, tool names, or user name. The chain is published here in
full for that reason.

## Claim wording

For the README, the sentence this record supports:

> On a local qwen3:8b driving a real editing session, `palimpsests serve`
> recorded a `TOOLS_OFFERED_NO_CALL` event for every turn where OpenCode
> offered tools and the model returned no structured call — nine of nine,
> on an intact chain. The client-side reporting plugin did not fire on
> OpenCode 1.18.25 or 1.18.31, so that session produced no
> reported-by-client tool pairs; see the run record.

What must **not** be written yet: any sentence claiming that OpenCode
tool calls land on the chain as reported pairs, or that the released
0.11.0 wheel does any of this — it has neither the ingestion route nor
kind 10.

## Files beside this record

- `run-export.jsonl` — the full JSONL export (11 records + summary line)
- `run-report.html` — `pala report --html`
- `run-chain.pala` — the chain itself, published in full (see the scan above)
