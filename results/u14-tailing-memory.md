# U14 / PR-5 — TailingReader memory growth: measured

**Date:** 2026-09-02 · **Commit under test:** `0af95b6` (main, post-#209)
**Environment:** single-threaded container, 3997 MB RAM cap, Python 3.12 —
**NON-CANONICAL**: slopes (bytes per record) travel between machines;
absolute RSS does not. Method and harness: `benchmarks/bench_tailing_memory.py`.

## The question

From the U14 plan: `IncrementalVerifier._seen` holds one 32-byte object
per record for the whole pass — bounded by the file in batch mode,
unbounded in a live reader that is meant to grow. **Does a live
`TailingReader`'s resident memory grow linearly with record count?**

Reading the implementation before measuring added a second suspect,
larger than the one the plan named: `TailingReader._verified` is a
`bytearray` mirroring **every verified byte** in memory (it is what
`snapshot()` re-verifies), and `snapshot()` copies it wholesale before
re-running batch verification over it.

## Method

One process per repeat (fresh child): a live `PalaWriter` appends
`KV_SAVE` records (~210 B each) in 50k batches to 300k total; a
`TailingReader` (poll 1 ms) keeps up; RSS (`VmRSS`), Python heap
(`tracemalloc`), and the two internal accumulators are sampled at each
batch boundary. Two variants × two repeats each: tail-only, and with
`snapshot()` called at 100k / 200k / 300k (`VmHWM` captured around each
call). Internal-field reads are labeled instrumentation: attribution,
not public surface.

## Answer: yes — linear, and precisely attributable

| Slope, bytes per record | n=2, min–max |
|---|---|
| Python heap (tail-only) | **312.2 – 312.2** |
| … of which `_verified` mirror | 210.0 (exactly the file's byte rate) |
| … of which `_seen` + list slot | ≈ 100 (32 B payload + object + slot) |
| RSS (tail-only) | 506.1 – 509.7 |
| RSS (with 3 snapshots) | ≈ 2310 (fragmentation aftermath; see below) |

The Python-heap slope decomposes without remainder: the `_verified`
mirror grows at exactly the container's byte rate, `_seen` adds ~100 B
per record of CPython object overhead around its 32 payload bytes. RSS
runs ~1.6× the Python heap on the clean path (allocator overhead).

## `snapshot()` — linear in time, transiently doubled in memory

| At prefix | wall time (n=2) | `VmHWM` jump (n=2) |
|---|---|---|
| 100k records | 13.2 – 13.9 s | +537 MB |
| 200k records | 24.8 – 25.5 s | +426 MB |
| 300k records | 36.6 – 37.3 s | +588 MB |

Three costs stack per call: the wholesale copy of `_verified`
(`bytes(bytearray)`), a full `AuditReader` decode of the copy, and the
referential advisory pass inside `verify()` (~0.12 ms/record here — the
same U14 cost the batch path pays). After snapshots, retained RSS slope
rises ~4.5× over the clean tail (2310 vs ~508 B/rec): the transient
allocations fragment the heap and the pages do not return.

## What the arithmetic says at scale

Container slopes, so read as shape, not as absolutes: a tail-only live
reader reaches ~312 MB of Python heap (~0.5 GB RSS) at 1M records and
~3.1 GB (~5 GB RSS) at 10M — for a reader whose stated purpose is to run
against a chain that grows for months. One `snapshot()` at 1M
extrapolates to roughly two minutes of wall time and a multi-GB
transient. Unbounded growth is structural, not incidental: both
accumulators exist to serve `snapshot()` and anchor lookup, and neither
is needed in that form (the prefix is on disk; a known anchor reduces
`_seen` to a flag and a counter — U14 plan, PR-5 note).

## Status

Measurement only; no fix in this PR. The findings feed U14 phase 2
(candidates: snapshot by re-reading the on-disk prefix; streaming
anchor check instead of `_seen`; both keep the live/batch equivalence
that `snapshot()` exists to prove). Raw run data:
`results/u14-tailing-memory-raw.json`.
