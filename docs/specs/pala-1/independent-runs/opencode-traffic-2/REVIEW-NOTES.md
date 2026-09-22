<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Review notes — OpenCode run 2

Written at review, in a separate file so that `RUN-RECORD.md` stays
exactly as its operator wrote it. Nothing here changes a number in the
record; it names two questions the record's own evidence leaves open.

## 1. Why did run 1 produce nothing?

This run shows `tool.execute.before` firing on 1.18.31. In run 1 the
model *did* execute tools on the same version — edits, a grep, a bash
command — and the plugin sent nothing at all: no report, no fetch
attempt, no failure line. If the hook fires on that version, something
else differed between the two runs.

The leading candidate is that the plugin's environment variables did
not reach the OpenCode process in run 1; this run records explicitly
that they were exported into that process. That is a hypothesis. Until
it is confirmed or ruled out, run 1's first finding stands as recorded,
and the two runs are read together rather than one replacing the other.

## 2. The fallback is proven for a failed call only

The single pair here has outcome `error`. A missing
`tool.execute.after` on a *failed* call is exactly the known upstream
behaviour (anomalyco/opencode#27900). Whether `message.part.updated`
also delivers the result of a *successful* call when `after` stays
silent is not shown by this run.

The plugin README states this limit. No claim about successful calls
should rest on this record.

## What this run changed elsewhere in the repository

- `integrations/opencode/README.md` — the status section no longer says
  the plugin records nothing on 1.18.x; it shows both runs side by side.
- `docs/SURFACE-CHECKER.md` — "0 calls, 0 results" is no longer
  diagnosed as "hooks do not fire" without first ruling out that the
  model never called a tool.
- `scripts/check_surfaces.py` — kills OpenCode's whole process tree on
  timeout (findings 7 and 8), and retries once for the first-run hang
  after a `baseURL` change (finding 6).
