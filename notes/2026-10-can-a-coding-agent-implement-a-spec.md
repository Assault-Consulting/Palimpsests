---
title: Can a coding agent implement a binary format from its spec alone?
slug: can-a-coding-agent-implement-a-spec
date: 2026-10-27
description: A small, strict test for coding agents. Give one a frozen specification and its test vectors, no reference code, and ask it to reproduce eleven values byte for byte in a language it chooses.
tags: verification, specification, coding-agents
---

Coding agents now write whole programs from a short description. Most of the tasks they are tested on are forgiving, though. A web page that looks roughly right is fine. A function that passes the tests someone wrote for it is fine.

Here is a less forgiving task. Give an agent the specification of a binary file format and a set of test vectors. No reference implementation, nothing to copy. Ask it to write a verifier in a language of its choice and reproduce eleven published values exactly, down to the last byte of a SHA-256 hash. Then ask it to break the format seven different ways and confirm that the verifier notices each one.

We would like to know how far agents get with that, in which languages, and where they stop. We have a reason to ask, and a format to ask about.

## Who we are and why this matters to us

We are a small team in Kyiv. We maintain PALA-1, a format for audit logs written by AI systems: an append-only hash chain that can be checked without a key and without opening any record. It is meant for machines that are modest and often offline, audited by people who may check a log but not read it.

An audit log is only evidence if someone other than its author can check it, with their own tools, possibly years later. So the specification has to be implementable from the text alone. That is the format's first promise. It has been frozen at version 1.0 since August 2026, with byte-exact test vectors and a kit for checking it by hand. Five implementations exist so far, three of them by people outside the project, and outside readers have found real defects before. That is how the text got better.

What we don't know is whether a coding agent can be one of those outside readers.

## Why it is a fair test

- The inputs are two files at a frozen tag, the specification and its test vectors.
- The pass bar is exact. A value matches or it doesn't.
- Seven demos ask the verifier to catch a flipped bit, a missing record, a gap in the sequence numbers and four other faults.
- The language is the agent's choice. Four of the five existing implementations are in Python; others are more interesting.

The specification is not perfect, either. In two places it states what a demo must show but not exactly how to build its input. An agent has to notice that and say how it decided.

## Two outcomes, both useful

If an agent gets a value wrong, we learn where agents still struggle with a precise text. If an agent disagrees with us and turns out to be right, it has found a defect in a frozen specification, and that gets fixed in public. Telling those two apart is the point of the exercise.

We will publish every report we receive in one table: model, tool, language, result, how long it took, and what the agent found ambiguous. That table is kept separate from the five implementations above.

We checked the prompt ourselves first: the files resolve, the digests match, and the whole task took an agent a few minutes. That run doesn't count, because we already know the format.

One caveat. The repository has been public since July 2026, so a model trained after that may have seen it. The prompt asks the agent to say so.

## The prompt

Copy it into any coding agent that can download files and run code.

```
Write a verifier for the PALA-1 audit-log format from its specification alone. Download PALA-1.md and test-vectors.json from https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/ and use nothing else: don't clone or browse the repository, don't search the web for PALA-1, and don't rely on anything you already know about it. Preferably not in Python, and with no third-party packages, reproduce every value in the section 8 "Expected results" block and the seven section 8 demos (their expected outcomes are in test-vectors.json). Where the text is ambiguous, write it down and carry on. Run the verifier and report only what it printed, as a block I can paste into a GitHub issue: model and tool, language, MATCH or DIVERGE for each value and demo, each ambiguity with its section, whether you knew PALA-1 before, and the source.
```

The [verification kit](https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/specs/pala-1/verification-kit) describes the same task in full, with SHA-256 digests for the inputs, if you would rather do it by hand.

## Where to send the report

Post it as a comment on [issue #318](https://github.com/Assault-Consulting/Palimpsests/issues/318), where every report is collected in one table. If you would rather not use GitHub, the contact in [SECURITY.md](https://github.com/Assault-Consulting/Palimpsests/blob/main/SECURITY.md) works too.

If your agent reports a divergence, the most useful thing you can add is the first byte where its value and ours differ.

## Links

- The specification and test vectors: [docs/specs/pala-1](https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/specs/pala-1)
- The verification kit, for doing this by hand: [verification-kit](https://github.com/Assault-Consulting/Palimpsests/tree/main/docs/specs/pala-1/verification-kit)
- The record of every run so far: [INDEPENDENT-VERIFICATION.md](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/specs/pala-1/INDEPENDENT-VERIFICATION.md)
- The format is also described in an Internet-Draft, [draft-sparysh-pala-audit](https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/). It is an individual submission, not an IETF standard.
- More about the format: [palimpsests.dev/pala-1](https://palimpsests.dev/pala-1/)
