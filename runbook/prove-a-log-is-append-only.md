---
title: Prove that a log was only added to
slug: prove-a-log-is-append-only
group: check
order: 4
updated: 2026-11-22
description: Write down one number and one fingerprint today. Later, a short proof shows that everything the log held then is still its beginning, unchanged.
next: detect-log-tampering, audit-evidence-bundle, rotate-a-hash-chained-log
seo_title: Prove a log is append-only with a consistency proof
seo_description: Write down one number and one fingerprint today. Later, a short proof shows that everything the log held then is still its beginning, unchanged.
---

Someone looked at your log in March. In June they want to know that the log they saw is still there, with new records added after it and nothing rewritten before. You could send them the whole log twice. A consistency proof says the same thing in a few lines: the first N records of today's log are exactly the N records of then.

It is the same kind of proof that certificate transparency logs use.

## You need

- A log in one file.
- A place to keep one number and one 64-character line where the log's owner cannot change them.

## Steps

### 1. Today: write down the count and the root

```bash
palimpsests pala consistency ~/.config/palimpsests/serve.pala --first 1
```

The command prints a small JSON document. Two fields matter now: `second`, the number of records, and `second_root`, a fingerprint of all of them together.

```text
"second": 40
"second_root": "651553e124439172662f6f11741b3b185174edc9060bb2d5aee9a774f73392de"
```

Give both to the person who will ask later, or keep them where they can be trusted.

### 2. Later: make the proof

The log has grown. Ask for a proof that its first 40 records are the old 40:

```bash
palimpsests pala consistency ~/.config/palimpsests/serve.pala --first 40 -o proof.json
```

```text
consistency proof 40 -> 64 (4 nodes) written to proof.json
```

### 3. Check it against the saved root

```bash
palimpsests pala consistency-verify proof.json --first-root 651553e124439172662f6f11741b3b185174edc9060bb2d5aee9a774f73392de
```

```text
CONSISTENT: records 0..39 are a prefix of 0..63
```

The receiver needs only `proof.json` and the root they already hold. They do not need the log. With a root that is not the one in the proof, the answer is:

```text
INCONSISTENT: --first-root differs from the proof's first_root
```

and the exit code is 1.

## What it does not do

- **It says nothing was changed among the first N. It does not say nothing was cut after them.** For the end of the log, keep its head; see [check a log for tampering](https://palimpsests.dev/runbook/detect-log-tampering/).
- **The proof is only as good as where the root was kept.** A root stored beside the log proves nothing. The command says so itself: where the roots came from is your evidence.
- **It is not signed.** It connects two roots. It does not say who made it.
- **It needs the whole log in one file.** For a log cut into pieces, the list of pieces records each closed piece's root when it is cut; see [keep a log for six months](https://palimpsests.dev/runbook/rotate-a-hash-chained-log/).
- **Step 1 borrows a command made for something else.** It asks for a proof from the first record and reads the root out of the answer. It works, and the root is the same one a later proof names; there is no shorter command for it yet.

## Last checked

- palimpsests 0.15.0 from PyPI, Linux, 22 November 2026: the root taken from a log of 40 records was the `first_root` of a proof made after the log had grown to 64. The outputs above are from that run, including the wrong root.

## Reference

- [The consistency proof document](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/specs/pala-1/consistency-proof.md)
- [Retention: pruning with a proof](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/RETENTION.md)
- [Protecting an audit log from being rewritten from scratch](https://palimpsests.dev/notes/protecting-an-audit-log-from-being-rewritten/)
