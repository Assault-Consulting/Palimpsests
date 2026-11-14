<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The verification report: from `/1` to `/2`

`palimpsests` 0.15 writes `pala-verification-report/2`. Versions 0.10 to
0.14 wrote `/1`. This note is for whoever consumes the report — renders
it, stores it, validates it or gates on its verdict.

The format id moved once, for everything that was waiting on it. `/1`'s
schema is closed (`additionalProperties: false` on every object), so no
key could be added to a `/1` report without failing a consumer that
validates against the schema it holds.

## What changed

| | `/1` | `/2` |
|---|---|---|
| `format` | `pala-verification-report/1` | `pala-verification-report/2` |
| `verdict` | `sound`, `partial`, `violation` | `sound`, `partial`, **`empty`**, `violation` |
| `chain.violation_codes` | absent | `[[seq, code], …]`, parallel to `chain.violations` |
| `diagnosis.code` | absent | the violation's code for the pattern `record_violation`; `null` otherwise |
| `manifest` | absent | `null`, or `{filename, status, sha256, detail}` |
| unknown keys | an error | allowed: the format is open to additions |

Nothing was removed or renamed, and no key that `/1` had changed its
meaning. Every other section — `subject`, `verifier`, `checked_at`,
`container`, `anchor`, `completeness`, `existence`, `advisory`, `safety`,
`time_basis` — is as it was.

### The verdict `empty`

A container with no records passes the chain check vacuously: nothing is
there to contradict (clarification C-8). Under `/1` the report graded
that like any chain — `partial` without an anchor. Neither word of `/1`
fits: `partial` reads "sound as far as checked", and nothing was checked.

| the file | the anchor | `/1` | `/2` |
|---|---|---|---|
| no records | none | `partial` | `empty` |
| no records | the head of some chain | `violation` | `violation` |
| no records | 32 zero bytes — the head of no records | `sound` | `empty` |
| bytes that are not a container | any | `violation` | `violation` |
| one record or more | any | as before | as before |

The third row is the one that mattered: an empty file, checked against the
head of an empty chain, was reported `sound` — everything checked, held.

The facts under the verdict did not move. `chain.chain_ok` is still `true`
for an empty container and `completeness.complete_to_anchor` is still
whatever the comparison gave; `diagnosis.pattern` is still
`empty_container`. Only the grade is new.

**A consumer that gates on the verdict treats `empty` as it treats
`partial`: not a failure, and not a pass.** `pala verify` does the same —
exit code 2, with `"verdict": "empty"` in `--json` — and for the third row
that is a change: it exited 0 before.

### Violation codes

`chain.violations` keeps its `[seq, reason]` pairs; the reason is a
sentence and may be reworded in any release. `chain.violation_codes`
carries `[seq, code]` for the same violations in the same order. Branch on
the code. The vocabulary is open and listed in
`docs/INTEGRATION-SURFACE.md`; render a code you do not know with the
reason beside it.

### The manifest's identity

When a segment's first record declares a continuation, the diagnosis is
decided against the `<stem>.segments.json` manifest beside the file. The
report now names that second file: its `filename` (a name, not a path —
the report holds no directory of the machine that ran the check), the
`status` the diagnosis used (`matches`, `contradicts`, `declared_only`),
the `sha256` of the bytes that were read and judged, and a `detail`
sentence when the status needs one. `manifest` is `null` when the verdict
read no second file. A consumer that identifies what it verified by digest
records both `subject.sha256` and `manifest.sha256`.

### An open format

`/2`'s schema says what must be present and does not forbid what it does
not name. A later release may add a key to any object; none will be
removed, renamed or given another meaning without a new format id.
**Ignore a key you do not know.** Two things stay closed: the verdict set,
and the constants (`format`, `verifier.spec`, the `time_basis` axis, the
advisory note).

## What to do

1. **Accept `format: pala-verification-report/2`**, and validate against
   `palimpsests/audit/_schemas/pala-verification-report-2.schema.json`
   from the installed wheel.
2. **Handle four verdicts.** Anything that switches on the verdict needs a
   branch for `empty` — a colour, a sentence, an exit code. Do not fold it
   into `partial` for display: the point of the word is that the file had
   nothing in it.
3. **Drop any workaround for the empty container** that read
   `diagnosis.pattern == "empty_container"` to correct the gloss of
   `partial`; the verdict says it now. Keep the workaround only for stored
   `/1` reports.
4. **Read codes from the report** where you read them from the reader for
   want of a place in `/1`.
5. **Stop rejecting unknown keys.**

## Reports already written

A `/1` report on disk is still a `/1` report. The `/1` schema ships in the
wheel beside the `/2` one; `derive_verdict` handed a `/1` report answers by
the rule that report was written under, so it re-derives to the verdict it
carries; `render_html` renders it and names its format in the footer.
Nothing converts a `/1` report into a `/2` one, and nothing should: a
report attests a check made at a stated time by a stated version. To have
a `/2` report of the same file, run the check again.
