<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# U14 — `verify()` bounded, measured on Windows hardware

**Date:** 2026-09-28 · **Before:** `v0.11.0` (`d70a61a`) ·
**After:** `main` at `2b1321f`. Both installed editable from one clone,
`before` as a worktree on the tag, so the two halves ran minutes apart on
one machine.
**Environment:** Intel Core Ultra 9 185H (16 cores / 22 threads,
2.5 GHz base), 31.5 GB RAM, Windows 11 Pro 26200, Python 3.12.10,
Balanced power scheme. RSS here is the Windows **working set**
(`rss_source: windows WorkingSetSize`), which is close to but not the
same measure as the Linux figures in `u14-verify-bounded.md`; the two
files are not to be merged into one number.
**Non-idle machine** — see *Caveats*. Method and harness:
`benchmarks/bench_reader_verify.py`, three repeats each in a fresh child
process, ranges over repeats, fixtures from
`benchmarks/gen_reader_fixtures.py`; raw JSON and the environment capture
sit beside this file.

## Why this run exists

`u14-verify-bounded.md` states plainly that its container numbers are
non-canonical: ratios travel, absolutes do not. This run takes the same
harness to real hardware, adds the **1 000 000-record** chain the
container could not finish, and runs `before` and `after` in one sitting
so they are comparable to each other.

## Numbers — 1 000 000 records (`calm`)

| metric | before (v0.11.0) | after (main) |
|---|---|---|
| RSS after `verify()` | 4767.39–4767.72 MB | **568.72–568.78 MB** |
| Python-heap peak in `verify()` | 1690.45 MB | **145.91 MB** |
| RSS after `open()` | 934.86–935.08 MB | **241.02–242.07 MB** |
| `verify()` wall | 101.69–107.48 s | **42.59–46.47 s** |
| referential pass (derived) | 98.72–104.58 s | **39.02–41.97 s** |
| `open()` wall | 13.88–14.62 s | **6.76–8.03 s** |
| chain pass alone | 2.91–3.44 s | 3.58–4.50 s |
| `build_report(reader=)` wall | 18.08–20.94 s | 44.48–45.31 s |

**`before` did not fail here.** With 31.5 GB installed there was no
memory pressure, so the SIGKILL the container saw did not reproduce —
and the reason is in the table rather than hidden by it: 4767 MB of
working set on its own exceeds a 3997 MB cap, before the interpreter and
the 200 MB file are counted. The hardware run measures the slope that
made the container die instead of reproducing the death.

## Numbers — 40 000 records

| fixture | metric | before (v0.11.0) | after (main) |
|---|---|---|---|
| calm-40000 | `verify()` wall | 2.66–3.27 s | 1.36–1.52 s |
| calm-40000 | referential pass (derived) | 2.55–3.16 s | 1.23–1.38 s |
| calm-40000 | `build_report(reader=)` wall | 0.77–0.83 s | 1.39–1.50 s |
| calm-40000 | `open()` wall | 0.30 s | 0.19–0.20 s |
| calm-40000 | RSS after `open()` | 62.68–63.44 MB | 32.81–32.96 MB |
| calm-40000 | RSS after `verify()` | 227.36–227.85 MB | 45.92–45.98 MB |
| calm-40000 | Python-heap peak in `verify()` | 67.42–67.45 MB | 5.82 MB |
| encrypted-40000 | `verify()` wall | 2.17–3.03 s | 0.86–0.92 s |
| encrypted-40000 | referential pass (derived) | 2.08–2.91 s | 0.75–0.81 s |
| encrypted-40000 | `build_report(reader=)` wall | 0.53–0.84 s | 0.75–0.88 s |
| encrypted-40000 | `open()` wall | 0.33–0.44 s | 0.17–0.19 s |
| encrypted-40000 | RSS after `open()` | 61.66–62.06 MB | 32.44–32.84 MB |
| encrypted-40000 | RSS after `verify()` | 158.74–159.06 MB | 34.88–35.18 MB |
| encrypted-40000 | Python-heap peak in `verify()` | 49.06 MB | 4.41 MB |
| toolheavy-40000 | `verify()` wall | 3.72–4.16 s | 3.45–3.73 s |
| toolheavy-40000 | referential pass (derived) | 3.61–4.05 s | 3.34–3.62 s |
| toolheavy-40000 | `build_report(reader=)` wall | 0.80–1.00 s | 1.94–2.20 s |
| toolheavy-40000 | `open()` wall | 0.31–0.34 s | 0.17 s |
| toolheavy-40000 | RSS after `open()` | 62.97–63.14 MB | 33.33–33.59 MB |
| toolheavy-40000 | RSS after `verify()` | 242.25–242.45 MB | 214.20–214.51 MB |
| toolheavy-40000 | Python-heap peak in `verify()` | 72.77 MB | 63.80 MB |

## Reading the tables

**Memory is the headline, and it holds at scale.** At a million records
the resident set after `verify()` falls **8.4×** and the Python-heap peak
**11.6×**; the three repeats agree to within 0.06 MB, so this is not
noise. At 40 000 the same shape appears on the serving-like profiles —
`calm` −80 %, `encrypted` −78 % resident — while `toolheavy` gains only
−12 %. That difference is the point rather than an inconsistency:
`toolheavy` is dense in the bodies the referential pass has to decode
whatever it does, so bounding the pass saves least exactly where the
work is real.

**`verify()` time follows, at 1M.** 2.4× faster, and essentially all of
it comes out of the referential pass (98.7–104.6 s → 39.0–42.0 s).
`open()` halves.

**Two things got worse, and they are not rounding.**

* `build_report(reader=)` at 1M: **18.1–20.9 s → 44.5–45.3 s**, about
  2.2× slower. The container run already showed this direction at 40k
  (0.66–0.67 s → 1.06–1.16 s there); at a million records it is the
  single largest regression in this table, and at 40k here it reaches
  **2.4×** on `toolheavy`.
* chain pass alone at 1M: 2.91–3.44 s → 3.58–4.50 s, about 24 % slower —
  consistent with the PR-8 note that the per-header slice moved out of
  `open()` and into the header pass.

Net at 1M, verify-then-report end to end is still ahead — roughly
120–128 s before against 87–92 s after — but the balance inside it has
shifted, and a caller who only builds reports pays more than it did in
0.11.

## Caveats

* **Non-idle machine, by choice.** 43 browser processes, 12 Docker
  processes, Ollama, several editors and a resident WSL VM
  (~714 MB) were running; 14.4 GB of 31.5 GB free at the start. The
  before/after ratios are the defensible part — both halves ran within
  minutes of each other under the same load. Absolute values carry that
  noise. Full capture in the `.environment.txt` beside this file.
* **Balanced power scheme**, not High performance; unchanged across both
  halves.
* **`after` is not only U14.** 223 commits separate `v0.11.0` from
  `2b1321f`. The reader/report work in that range is PR-6 through PR-9
  (`0f2d2e2`, `1fddab4`, `aecfbd4`, `167af73`, `7e4554f`, `15ec1fb`);
  the measured delta should not be attributed to those alone.
* **The harness marks these results `"canonical": false`** with the note
  *container/laptop runs are non-canonical; ratios travel, absolutes do
  not*. That flag is emitted by the benchmark itself and is preserved in
  the raw JSON. Whether a plugged-in desktop workstation should still be
  labelled non-canonical is a judgement for the benchmark's owner; this
  file does not overrule the flag it shipped with.
* **Maintainer run**, not an independent one.

## Reproducing

The Windows instructions used for this run generate three of the four
fixtures. The `encrypted` profile needs `cryptography`, which arrives
with the `[pala]` extra, and a plain `pip install -e .` leaves it out:

```
BodiesUnavailable: record-body encryption needs the 'cryptography'
package; install the [pala] extra.
```

The failure is a zero-byte `encrypted-40000.pala` and no companion
`.composition.json`. This run installed `cryptography>=42.0` (resolved:
50.0.1) into **both** environments before regenerating, so the halves
stay comparable. Instructions that ask for all four profiles should
install `-e '.[pala]'`.

Windows resident-memory measurement is itself new (`0055c03`); this run
is its first confirmation on hardware — the ten-second gate reported
positive RSS on the first attempt, with no `-1.00`.

## Files beside this one

- `u14-verify-bounded-windows.before-40k.json` / `.after-40k.json`
- `u14-verify-bounded-windows.before-1m.json` / `.after-1m.json`
- `u14-verify-bounded-windows.environment.txt` — machine capture and the
  background-load snapshot taken immediately before the run
