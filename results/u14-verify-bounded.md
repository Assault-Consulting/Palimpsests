<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# U14 / PR-6 + PR-7 — `verify()` bounded: measured

**Date:** 2026-09-05 · **Before:** main at `7b001d3` (post-#224, PR-6 in) ·
**After:** the PR-7 branch (one header pass; bounded referential pass).
**Environment:** single-threaded container, 3997 MB RAM cap, Python 3.12 —
**NON-CANONICAL**: ratios travel between machines, absolute values do
not. Method and harness: `benchmarks/bench_reader_verify.py`, three
repeats each in a fresh child process, ranges over repeats, fixtures
from `benchmarks/gen_reader_fixtures.py` at 40 000 records (composition
recorded per fixture in the raw JSON beside this file).

## What changed, in one sentence each

* **D1.** `verify()` stepped the headers twice — once for the §7.1
  verdict, once more for the advisory the first pass had computed and
  thrown away. Now once (`verify_headers_with_advisory`).
* **Bounded referential pass.** The pass that resolves an ack to its
  candidate and a shred to its targets used to decode *every* record to
  find the few that reference anything. Now it reads the seq map off
  the headers, finds referencing records by probing each body's first
  TLV in place, and decodes only those and the records they name.
* **(PR-6, already in main)** the report path reads headers and decodes
  SAFETY records alone, so removing `verify()`'s whole-chain decode did
  not push that cost into the report.

Every answer is byte-identical before and after: `Verification.chain`,
every advisory item in order, and every field of the verification
report — on these three fixtures, on the companion vectors, on a chain
built to emit every referential code the reader knows, and across the
existing suite (751 tests).

## Numbers

| fixture (40k) | metric | before (PR-6 in) | after PR-7 |
|---|---|---|---|
| calm-40000 | `verify()` wall | 3.12–3.44 s | 0.92–0.94 s |
| calm-40000 | referential pass (derived) | 2.96–3.26 s | 0.74–0.78 s |
| calm-40000 | `build_report(reader=)` wall, after `verify()` | 0.66–0.67 s | 1.06–1.16 s |
| calm-40000 | RSS after `verify()` | 225.79–226.85 MB | 73.18–73.24 MB |
| calm-40000 | Python-heap peak in `verify()` | 67.13–67.14 MB | 17.55–17.55 MB |
| encrypted-40000 | `verify()` wall | 2.10–2.17 s | 0.59–0.63 s |
| encrypted-40000 | referential pass (derived) | 1.96–2.03 s | 0.45–0.48 s |
| encrypted-40000 | `build_report(reader=)` wall, after `verify()` | 0.62–0.65 s | 0.89–0.92 s |
| encrypted-40000 | RSS after `verify()` | 156.78–156.94 MB | 68.27–68.34 MB |
| encrypted-40000 | Python-heap peak in `verify()` | 48.76–48.76 MB | 15.84–15.84 MB |
| toolheavy-40000 | `verify()` wall | 3.25–3.57 s | 2.64–2.85 s |
| toolheavy-40000 | referential pass (derived) | 3.09–3.41 s | 2.48–2.69 s |
| toolheavy-40000 | `build_report(reader=)` wall, after `verify()` | 0.72–0.74 s | 1.23–1.25 s |
| toolheavy-40000 | RSS after `verify()` | 241.65–241.83 MB | 229.33–229.44 MB |
| toolheavy-40000 | Python-heap peak in `verify()` | 72.47–72.47 MB | 68.35–68.35 MB |

**Reading the table.**

* On the profiles that resemble a serving cycle (`calm`, `encrypted`),
  `verify()` is **3.4–3.6× faster** and the resident set after it is
  **−56 % / −68 %**. The Python-heap peak — the part that scales with
  the chain — drops ~3.8× / ~3.1×. The residual referential time is the
  O(n) probe over headers and first TLVs, not decoding.
* On `toolheavy` (28.6 % of records carry a reference — the ceiling
  profile, not a norm) the gain is small by construction: most records
  are exactly the ones the pass must decode. It is not slower.
* `build_report(reader=)` measured *after* `verify()` is **slower by
  ~0.3–0.5 s** on every profile. Before, it rode the full decode cache
  that `verify()` had just built; now it does its own header work (two
  header walks, for boots and spans) and, on `toolheavy`, decodes SAFETY
  records once. The sum `verify()` + report is still 1.5–1.9× faster on
  the serving-like profiles and flat on `toolheavy`. Collapsing the two
  header walks into one, and the `_walk()` floor itself, are PR-8.
* RSS after `verify()` on `toolheavy` (229 MB) is dominated by the
  sparse cache of decoded SAFETY/tool records plus the seq map — the
  same objects the old path held, minus the bystanders.

## Not claimed

Nothing here is a property of the format. These are the characteristics
of one reader implementation on one machine, before and after two
changes, with the fixtures' composition stated. The 1M-record figures in
the U14 track notes were taken on this same container class and are
consistent in ratio with the rows above; a run on operator hardware
(PR-4 of the track) is still the only thing that turns any absolute
value here into a number worth quoting.

## Addendum — PR-8, the `_walk()` floor (2026-09-05)

`_walk()` copied every header out of the container into its own `bytes`
and kept all of them; PR-8 replaces that with three offset/length arrays
and slices a header only when a caller asks for it. The bounded passes
(`verify()`'s referential pass, the views, the safety section, the
report's seq bounds) read the two or three words they need in place
and never slice. `boots()` and `spans()` are one pass (`structure()`),
which the report uses.

Measured **without** tracemalloc this time — the harness runs under
`tracemalloc`, which inflates the wall time of allocation-heavy code
several-fold and is not the right instrument for a change whose point
is fewer allocations. Fresh process per run, two or three repeats,
ranges; `calm` profile; PR-7 is `main` at `5a3a10f`.

| chain | metric | PR-7 | PR-8 |
|---|---|---|---|
| calm-40k | RSS after `open()` | 41–43 MB | **28 MB** |
| calm-40k | RSS after `verify()` | 47–48 MB | **34 MB** |
| calm-40k | `verify()` wall | 0.16–0.18 s | 0.20–0.21 s |
| calm-250k | RSS after `open()` | 154–156 MB | **73–74 MB** |
| calm-250k | RSS after `verify()` | 190–191 MB | **110 MB** |
| calm-250k | `open()` wall | 0.21–0.22 s | 0.16–0.17 s |
| calm-250k | `verify()` wall | 1.16–1.25 s | 1.20–1.32 s |
| calm-250k | `build_report(reader=)` wall | 1.02–1.05 s | 1.01–1.05 s |

**Reading it.** The floor drops by ~330 bytes per record — the copied
header plus its object overhead — which is the slope that turned a
million records into a SIGKILL. Wall time is flat to slightly worse:
the one slice per header that `open()` used to do up front now happens
inside `verify()`'s header pass, so `open()` gets faster and `verify()`
slower by about the same amount; on 250k the sum is within noise. What
remains resident after `verify()` at 250k is the seq map for the
referential pass and the verifier's per-record head list — known,
bounded, and the subject of the track's remaining items.
