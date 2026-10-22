---
title: OpenSSF Gold software and the Cyber Resilience Act
slug: openssf-gold-cyber-resilience-act
date: 2026-10-20
description: What the EU Cyber Resilience Act asks of products built from open-source components, what an OpenSSF Gold badge shows about a component, and what it doesn't.
tags: cyber-resilience-act, openssf, supply-chain
---

If you sell software or connected hardware in the EU, the Cyber Resilience Act now applies to you in stages. Regulation (EU) 2024/2847 entered into force in December 2024. Since 11 September 2026, manufacturers have had to report actively exploited vulnerabilities and severe incidents. Most of the rest arrives on 11 December 2027, when the essential requirements, technical documentation and CE marking become mandatory.

Products today are built largely from open-source components. The CRA puts the responsibility for those components on the manufacturer that ships them, not on the people who wrote them. So when you choose a library, you're also choosing the evidence you'll need about it later. This note looks at what an OpenSSF Best Practices Gold badge tells you about a component, using our own project as the example.

## Who the CRA applies to

Free and open-source software developed outside any commercial activity is outside the regulation. Once software is placed on the market in the course of a commercial activity, the company doing that is treated as a manufacturer and carries the full set of obligations. There's also a lighter role, the open-source software steward: an organisation that supports open-source software intended for commercial use without selling it itself. Stewards have limited duties, and their reporting only starts in December 2027.

Palimpsests is free and licensed under Apache-2.0. If you build it into a product you sell in the EU, your company is the manufacturer of that product, and the CRA's questions about its components are yours to answer.

## What the CRA asks about components

Several parts of Annex I touch on this directly:

- a software bill of materials in a common machine-readable format, covering at least the top-level dependencies;
- a process for handling vulnerabilities, with a published way to report them and security updates delivered without delay;
- protection of the integrity of data, commands and configuration;
- recording and monitoring of relevant internal activity, such as access to or changes of data, services or functions, with an opt-out for the user.

The last point is easy to miss. A product has to be able to show what happened inside it, and a log nobody can check is weak evidence of that. That's the subject of a separate note on [what makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/).

## What the Gold badge says

The OpenSSF Best Practices badge has three levels: passing, silver and gold. The project answers each criterion publicly on bestpractices.dev, with a justification anyone can read, and a few answers are checked automatically. Most of it is self-assessment. Its value is that every answer is specific and can be checked against the repository. OpenSSF also maintains the OSPS Baseline, a shorter list of security controls written with the CRA in mind.

For [Palimpsests](https://palimpsests.dev/), the Gold level rests on things you can open and inspect:

- every change goes through a pull request approved by someone other than its author, and the organisation requires two-factor authentication;
- CI refuses to merge if statement coverage drops below 90% or branch coverage below 80%;
- coverage-guided fuzzing and static analysis run in CI;
- releases go to PyPI through Trusted Publishing with Sigstore attestations, and each GitHub release carries a CycloneDX SBOM of the base install;
- the v0.10.0 wheel was rebuilt from source and matched the published file byte for byte;
- the security policy explains how to report a vulnerability privately and lists the risks we know about and haven't fixed yet.

The full list, criterion by criterion, is in the [public registry entry](https://www.bestpractices.dev/projects/13534) and in our [badge status file](https://github.com/Assault-Consulting/Palimpsests/blob/main/docs/BADGE-STATUS.md).

## What it doesn't say

A badge isn't a CE mark, and the project isn't certified under the CRA or any other scheme. The badge says nothing about your product, your configuration or the way you deploy a component. It doesn't replace a security review either. Ours so far has been an internal one, done with AI assistance, and the audit log implementation hasn't had an independent penetration test.

What a manufacturer gets from it is a set of facts for the technical file, each with a link, instead of a vendor questionnaire answered from memory.

## Using it in practice

If Palimpsests is one of your components, these are the documents to collect:

- the SBOM attached to the release you ship;
- the Sigstore provenance of the wheel, which shows the repository and workflow that built it;
- [SECURITY.md](https://github.com/Assault-Consulting/Palimpsests/blob/main/SECURITY.md), with the reporting channel and the accepted risks;
- the [release process](https://github.com/Assault-Consulting/Palimpsests/blob/main/RELEASING.md), which explains how to verify the attestations yourself.

The same reasoning works for any open-source component. Ask whether its claims point to evidence you can open, and whether its known weaknesses are written down somewhere. The logging side of the AI rules is covered in [AI logging standards in draft](https://palimpsests.dev/notes/ai-logging-standards-24970-18229/).
