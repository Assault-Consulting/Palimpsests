<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Surface check 2026-11-02 — notes on the run and on the checker

Companion to `surfaces-2026-11-02.md`, which is the checker's own output
and is reproduced there unedited. This file records what the run showed
about the checker itself. Machine: workstation, Windows 11 Pro
10.0.26200, Python 3.12.10, `palimpsests 0.13.1`, `.venv-p06` with the
`[serve]` extra plus litellm, mcp, pydantic-ai-slim and the OTLP
exporter.

Per `docs/SURFACE-CHECKER.md` §4a, the two defects in part 2 are
checker-side (🟠 class), so **no integration README was touched** on the
strength of this run.

## 1. The three Windows fixes behave as intended

- **`.cmd` resolution.** Both npm-installed clients launched and reported
  their versions, and no probe reported `probe crashed`. The
  `shutil.which` path resolution works on this machine.
- **Report-before-print, and stdout encoding.** The official run above
  happened in a code-page 65001 console, so the cp1251 condition did not
  arise. It was covered by a separate, targeted run: with `chcp 1251`,
  the litellm probe printed its state mark and exited **0**, and the
  `--report` file was written. In the source the order is visible —
  the report is written before the table is printed, and `_print`
  reconfigures stdout to UTF-8 with `errors="replace"`.
- **Missing `[serve]` extra.** Run under a Python without the extra, the
  checker reported **⚪ SKIP** with the explanatory sentence and exited
  **0**.

## 2. Two defects, both in the checker

Neither the ⚪ on `opencode` nor the 🔴 on `claude-code` in
`surfaces-2026-11-02.md` is a statement about those surfaces. Both probes
isolate the client by setting `HOME` to a temporary directory, and on
Windows these clients read `USERPROFILE`, not `HOME`.

### 2a. The client probes do not isolate on Windows

Evidence, from four diagnostic runs of a patched copy of the script (the
working tree was restored to `HEAD` afterwards; nothing in this PR
changes the checker):

1. **As shipped** (`HOME` only). `claude-code` → 🔴 RED, `0 call(s), 0
   result(s)`, while `completions > 0` — so the client ran, using its
   *real* configuration directory, while the probe's hooks sat in an
   ignored temporary `HOME`. A false RED. `opencode` → ⚪ SKIP with 0
   completions, because the machine's global OpenCode config had been
   moved aside and the client had no provider.
2. **`USERPROFILE` pointed at the same temporary home.** `claude-code` →
   ⚪ SKIP: given a fresh home the client never completes a turn at all.
   Setting `CLAUDE_CONFIG_DIR` to a fresh directory gives the same ⚪.
3. **Hooks written into the project's `.claude/settings.json`, `HOME`
   untouched.** The client kept its own state and ran; `PreToolUse`
   arrived — `seq=2 TOOL_CALL source=1` — and no result did, giving 🔴
   RED `1 call(s), 0 result(s), sources [1]`. For contrast, run 1 of the
   0.14 traffic series used the same client version, 2.1.310, with hooks
   in the *user-level* settings and an interactive session, and produced
   11 calls and 11 results. So this is about project-level settings under
   `-p`, not about the hook surface.

Taken together: on Windows this probe has no way to exercise the
documented configuration without writing into the user's real settings.
That is the defect, and it is a design question rather than a typo —
hence it is reported rather than patched here.

### 2b. The `opencode` probe cannot reach GREEN by construction

With `USERPROFILE` also pointed at the probe's home, the OpenCode client
did reach the stub serve, and a per-record diagnostic inside `pairs()`
printed:

```
seq=2 TOOL_CALL   source=0
seq=3 TOOL_CALL   source=1
seq=4 TOOL_RESULT source=1 outcome=ok
```

The plugin delivered both halves, and the result is `ok` — the surface
works. The verdict was 🔴 anyway, because `_verdict` requires
`sources == [expect_source]`, i.e. `[1]`, and in this probe the stub
serve is *also* the model provider, so it records its own structured call
with `source=0` on the same chain. `sources == [1]` is therefore
unreachable: the probe is RED whatever the plugin does. This one is
independent of Windows.

Suggested direction, for whoever fixes it: assert that the expected
source is *present* (and, where it matters, that no unexpected source is)
rather than that it is the only one; or give the OpenCode probe a model
provider separate from the serve under test.

## 3. Scope

One machine, one OS, one run of each probe. The three GREEN rows
(`litellm`, `mcp`, `otel`) are unaffected by the above: those probes do
not depend on a client's configuration directory.
