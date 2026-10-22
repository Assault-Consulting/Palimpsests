---
title: AI logging standards in draft: ISO/IEC 24970, prEN 18229-1 and how we map them
slug: ai-logging-standards-24970-18229
date: 2026-10-20
description: Where the AI logging standards stand in October 2026, why they matter for the EU AI Act, and how Palimpsests maps their requirements to code while the text is still moving.
tags: ai-logging, iso-iec-24970, eu-ai-act
---

Article 12 of the EU AI Act says high-risk AI systems must record events automatically. It doesn't say which events, in what format, or how a record should be protected. That level of detail is meant to come from harmonised standards. Once a standard is harmonised and its reference is published in the Official Journal, following it gives a presumption of conformity with the parts of the Act it covers.

In October 2026, the two documents that matter most for logging are both still drafts.

## The two drafts

ISO/IEC 24970, "Artificial intelligence — AI system logging", comes from ISO/IEC JTC 1/SC 42. It describes common logging capabilities, requirements and an information model, and it's meant to be used together with a risk management system. It has reached the final draft stage, the last step before formal approval. A European adoption, prEN ISO/IEC 24970, is going through CEN/CENELEC JTC 21 and adds an annex that links it to the AI Act.

prEN 18229-1, "AI trustworthiness framework — Part 1: Logging", is a European draft from CEN/CENELEC JTC 21. It covers terminology, concepts, requirements and guidance for logging AI systems, aimed at organisations that place AI systems on the market. Its enquiry draft was published in mid-2026 and the vote on it closed in August.

Neither text is final. Clause numbers and details can still change, and the final versions will be sold like any other standard.

## Why map against a moving target

Waiting for the final text sounds safer. In practice the obligations start on 2 December 2027 for systems listed in Annex III, and a logging setup has to run for months before anyone can show six months of retained records.

The 24970 draft already sets out the broad shape. Events are chosen by risk. The system logs them automatically and keeps the logs intact and available. The organisation documents what its logging covers. That was enough to start mapping, as long as the mapping couldn't be mistaken for a conformity claim.

## How the mapping works

The [ISO/IEC 24970 mapping](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/compliance/24970-MAPPING.md) and the [EU AI Act Article 12 mapping](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/compliance/EU-AI-ACT-MAPPING.md) sit in the repository, next to the code they describe. Each requirement gets a row with one of four statuses:

- Shipped, with the release it shipped in;
- Planned, for scheduled work that only adds to the format;
- Deployer, where the obligation belongs to the organisation running the system;
- N/A, where it's outside what an inference runtime does.

The Deployer rows matter as much as the Shipped ones. Deciding which events are worth logging is a risk decision for the organisation, and so is documenting the logging programme. A runtime can't make those decisions, and a mapping that suggested it could would be misleading.

Both documents also say where their clause references come from: the public draft structure, to be checked against the final text before anyone relies on them.

## One example: limited storage

The 24970 draft deals with logs that run out of space, including logs that overwrite their oldest entries. For a hash-chained log, overwriting in place isn't possible. Every record carries the hash of the one before it, so rewriting an old record would break every link after it.

We took another route. Since version 0.13, [Palimpsests](https://palimpsests.dev/) rotates its log into segments. Each new segment opens with a continuation record that names the previous segment's last hash, its own number, the retention period in force and a root that commits to every earlier record. Old segments can then be deleted under the retention policy, and what's left still explains itself. A reader can tell a declared deletion from a missing beginning that nobody accounted for.

That's the general approach. Where a draft describes an outcome, we look for a way to reach it that keeps the log checkable. Where the requirement belongs to the deployer, the mapping says so plainly.

## What happens next

When ISO/IEC 24970 is published, every row will be checked against the final text and its references updated. The same will happen for prEN 18229-1 once it moves past the enquiry stage. Until then, read the mapping as our reading of a draft.

The legal side of Article 12 is summarised in [EU AI Act Article 12: what it asks of AI you run yourself](https://palimpsests.dev/notes/eu-ai-act-article-12-self-hosted-ai/). What makes the log itself trustworthy is in [what makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/).
