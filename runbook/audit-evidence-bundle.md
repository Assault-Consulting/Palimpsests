---
title: Hand an auditor one file of evidence
slug: audit-evidence-bundle
group: check
order: 3
updated: 2026-11-22
description: Pack the log, the result of checking it and the list of what is inside into one file that the person receiving it can check again without trusting you.
next: detect-log-tampering, prove-a-log-is-append-only, rotate-a-hash-chained-log
seo_title: Audit evidence bundle: one file an auditor can re-check
seo_description: Pack a log, the result of checking it and a list of contents into one file the person receiving it can check again without trusting you.
---

When someone asks for the record, a loose log file is a poor answer. They also need to know what it was checked against, what the result was, and that the file they received is the file you sent. The bundle is one plain `tar` file with all of that inside. It is not signed and does not need to be: everything in it can be checked again from the published format.

## You need

- A log, and the head you saved for it. See [check a log for tampering](https://palimpsests.dev/runbook/detect-log-tampering/).

## Steps

### 1. Make the bundle

```bash
palimpsests pala bundle ~/.config/palimpsests/serve.pala --anchor-file head.txt -o evidence.tar
```

```text
bundled 64 record(s) (0 with inclusion proofs) to evidence.tar
source head: 78ede38854665e99b1552873f6a5ab34468cb86b881ecddde22c73e25224200b
consistency inside: holds
```

### 2. Look inside

```bash
tar tf evidence.tar
```

```text
records.pala
proofs.json
verification.json
time-claims.json
MANIFEST.json
```

- `records.pala` is the log, byte for byte.
- `verification.json` is the result of the check, with the head it was checked against and where that head came from.
- `time-claims.json` lists every time in the log with how far the writer trusted its clock.
- `MANIFEST.json` lists the SHA-256 of each of the other files, and the version of the tool that made the bundle.

### 3. What the receiver does

```bash
tar xf evidence.tar
sha256sum records.pala          # compare with MANIFEST.json
palimpsests pala verify records.pala --anchor-file head.txt
```

They use the head you gave them by another road, not one taken from the bundle. They can also use a reader of their own: the format is published, with test files.

### For a person, not a program

```bash
palimpsests pala report ~/.config/palimpsests/serve.pala --anchor-file head.txt --html -o report.html
```

This writes one page with no scripts and no outside files, stating the verdict and what it rests on.

## What it does not do

- **It is not signed.** The bundle proves nothing about who made it. Its worth is that the receiver can repeat the check.
- **A part of a log does not check alone.** `--from-seq` and `--to-seq` pack a range, and `verification.json` still describes the whole log. The range's records start in the middle of the chain, so `pala verify` on them reports a missing beginning.
- **The server's log has no inclusion proofs,** as the first output line says. Those need a log that carries tree roots in its own records, and the server's log does not.
- **A broken log is packed as it is.** The result inside says so. The command does not refuse bad evidence.
- **The contents are not opened.** The bundle holds what the log holds: operations and fingerprints.

## Last checked

- palimpsests 0.15.0 from PyPI, Linux, 22 November 2026: a log of 64 records written by the server. The bundle's `records.pala` was the same bytes as the log and checked against the saved head. The outputs above are from that run.

## Reference

- [The bundle format](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/specs/bundle/pala-bundle-1.md)
- [The verification report: its schema](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/specs/report/pala-verification-report-2.schema.json)
- [Verify without reading](https://palimpsests.dev/verify-without-reading/)
