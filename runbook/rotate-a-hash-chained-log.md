---
title: Keep a log for six months without filling the disk
slug: rotate-a-hash-chained-log
group: check
order: 2
updated: 2026-11-22
description: Let the server cut its log into pieces as it writes, state how long you keep them, delete old pieces whole, and still check what is left as one chain.
next: detect-log-tampering, prove-a-log-is-append-only, audit-evidence-bundle
seo_title: Log rotation for a hash chain: keep six months, not more
seo_description: Cut a hash-chained log into pieces as it is written, state how long you keep them, delete old pieces whole, and still check what is left as one chain.
---

A log that only grows fills the disk. A log that is a chain cannot simply lose its oldest lines, because every record points at the one before it. Palimpsests cuts the chain into pieces at record boundaries and writes down, in the chain itself, what came before each cut. Old pieces can then be deleted whole, and what remains still checks.

## You need

- palimpsests 0.15.0 or newer. The server could not cut its own log before that.

## Steps

### 1. Tell the server when to cut and how long you keep

```bash
export PALIMPSESTS_AUDIT_ROTATE_BYTES=16MiB
export PALIMPSESTS_AUDIT_RETENTION=180d
palimpsests serve
```

At start the server says how it will cut, which file it is writing, and the command that checks the set.

Sizes take `KiB`, `MiB` or `GiB`. The keeping period takes `s`, `m`, `h` or `d`. You can cut by count with `PALIMPSESTS_AUDIT_ROTATE_RECORDS`, or by age with `PALIMPSESTS_AUDIT_ROTATE_AGE`. A record is roughly 200 bytes, so 16 MiB is about a week at ten thousand records a day.

### 2. See the pieces

```text
serve.pala
serve.pala.00001
serve.pala.00002
serve.pala.00003
serve.pala.segments.json
```

The first file is closed for good once the first cut is made. The server writes to the last one. The `.json` file is the list of pieces; keep it for as long as any piece lives.

### 3. Check the whole set

```bash
palimpsests pala segment-verify ~/.config/palimpsests/serve.pala.segments.json
```

```text
  ok     serve.pala  (seq 0..19)
  ok     serve.pala.00001  (seq 20..39)
  ok     serve.pala.00002  (seq 40..59)
  ok     serve.pala.00003  (being written)
COMPLETE: 4 segment(s), all present, from a GENESIS.
```

### 4. Delete what is older than your period

Delete whole files only, oldest first, and never the list or the last piece. Then check again:

```text
  absent serve.pala  (seq 0..19)
  ok     serve.pala.00001  (seq 20..39)
  ok     serve.pala.00002  (seq 40..59)
  ok     serve.pala.00003  (being written)
CONSISTENT, NOT COMPLETE: what is present verifies; 1 listed segment(s) are not on disk
```

The exit code is 2: nothing is wrong with what is there, and the beginning is gone. The first record of each later piece says what the piece before it ended with and what keeping period was declared, so a reader sees a log that was shortened by a stated rule.

## What it does not do

- **The server deletes nothing.** The keeping period is a statement written into the chain. Deleting is yours to do, by whatever your rules require.
- **Six months is your decision, not ours.** The EU AI Act asks deployers of high-risk systems to keep logs for at least six months; other rules may ask for longer. This is a tool, not a compliance product.
- **Do not delete the piece being written.** The server would continue from the last closed piece, and the log would be shorter with nothing in it to show that. Only a head saved elsewhere catches a cut at the end; see [check a log for tampering](https://palimpsests.dev/runbook/detect-log-tampering/).
- **A deleted piece is gone.** What remains proves it continues the piece that was removed. It does not bring the records back.
- **A wrong value stops the server at start,** and the message names the variable. `16MB` is refused; write `16MiB`.

## Last checked

- palimpsests 0.15.0 from PyPI, Linux, 22 November 2026: a server cutting every 20 records with a declared 180 days, 67 records in four pieces. The outputs in steps 3 and 4 are from that run, before and after the first piece was deleted. The size setting `16MiB` was started once and accepted, and `16MB` was refused with a message naming the variable.
- A run over weeks, with forced stops, is under way and is not finished.

## Reference

- [Retention: sizes, the six-month duty, cutting and pruning](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/RETENTION.md)
- [The server's settings](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/SERVE-SURFACE.md)
- [The EU AI Act, Article 12, requirement by requirement](https://palimpsests.dev/eu-ai-act-article-12/)
