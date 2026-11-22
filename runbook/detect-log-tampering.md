---
title: Check a log for tampering
slug: detect-log-tampering
group: check
order: 1
updated: 2026-11-22
description: Keep a copy of the log's latest fingerprint somewhere else, and one command tells you later whether any record was changed, removed or cut off the end.
next: audit-evidence-bundle, prove-a-log-is-append-only, rotate-a-hash-chained-log
seo_title: Detect log tampering with a hash chain and one command
seo_description: Keep the log's latest fingerprint somewhere else, and one command tells you later whether a record was changed, removed or cut off the end.
---

A Palimpsests log is a chain: every record carries a fingerprint of the one before it. Change a record in the middle and the fingerprints stop matching from there on. The one change a chain cannot show by itself is a cut at the end, because a shorter chain is still a chain. For that you keep the latest fingerprint, called the head, in a second place.

This page checks a log both ways. It needs no key and never opens what the records hold.

## You need

- A log written by Palimpsests. The server keeps its own at `~/.config/palimpsests/serve.pala`.
- A place for a 64-character line that the person who could change the log cannot change: another machine, a ticket, a printed page.

## Steps

### 1. Save the head

When the server stops, it prints the head:

```text
audit chain closed: 64 record(s), head 78ede38854665e99b1552873f6a5ab34468cb86b881ecddde22c73e25224200b
```

While it runs, ask it:

```bash
curl -s -H "Authorization: Bearer $PALIMPSESTS_SERVE_API_KEY" http://127.0.0.1:11435/v1/pala/status
```

The reply has `chain.head`. Put that line in a file, here `head.txt`, and keep the file away from the log.

### 2. Check the log against it

```bash
palimpsests pala verify ~/.config/palimpsests/serve.pala --anchor-file head.txt
```

```text
consistency: 64 records, chain intact
anchor: 78ede388… from file head.txt
completeness: chain head matches the supplied anchor
```

The command exits with 0. Nothing was changed, and nothing is missing from the end.

### 3. Know what a failure looks like

One byte changed inside a record:

```text
consistency: BROKEN — body digest mismatch at seq [20]
```

The last four records removed:

```text
consistency: 60 records, chain intact
completeness: FAILED — the anchored head names no record in this chain — the log was replaced, rolled back, or truncated
```

Both exit with 1. The second one is the reason for step 1: the chain is intact, and only the saved head shows that records are gone.

## Exit codes

- `0` the chain is intact and its end matches your saved head.
- `1` a violation: a break, a gap, a changed record, or an end that does not match.
- `2` the chain is intact, but you gave no head, so a cut at the end would not have been seen.
- `3` the file could not be read.

## What it does not tell you

- **A saved head is for one moment.** If the log has grown since you saved it, the check fails with "chain extends N record(s) beyond the anchored head". Save the head again each time you stop the server or take a copy, and check a copy against the head of its own moment.
- **It says the log was not changed. It does not say the log is true.** If a wrong thing was recorded, it is still there, unchanged.
- **It does not say who or when.** The exit code states the finding, never a cause.
- **A head kept next to the log protects nothing.** Whoever rewrites the log rewrites the file beside it.
- A line "advisory: anchor_never_written" is a note that the log holds no anchor record of its own. It does not change the result.

## Last checked

- palimpsests 0.15.0 from PyPI, Linux, 22 November 2026: a log of 64 records written by the server, checked as on this page. The three outputs above are from that run: intact, one byte changed, and the last four records removed.

## Reference

- [Verify without reading](https://palimpsests.dev/verify-without-reading/)
- [What makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/)
- [Protecting an audit log from being rewritten from scratch](https://palimpsests.dev/notes/protecting-an-audit-log-from-being-rewritten/)
- [Usage: the audit commands](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/USAGE.md)
