---
title: EU AI Act Article 12: what it asks of AI you run yourself
slug: eu-ai-act-article-12-self-hosted-ai
date: 2026-10-04
description: Which systems the logging rules cover, what the articles require, when they start and how the fines work, in plain language.
tags: eu-ai-act, logging, compliance
---

Running a language model on your own servers keeps the data at home. It doesn't change what the EU AI Act asks of the system itself. If the system is classed as high-risk, it has to keep logs, and those logs have to last.

This note goes through the parts of the Act that matter for logging. It's a summary, not legal advice.

## Which systems are covered

The logging rules apply to high-risk AI systems. Annex III of the Act lists them by area of use, including hiring, credit scoring, education, access to essential services and critical infrastructure. AI built into products that are already regulated, such as some medical devices, comes under Annex I instead.

The classification is yours to make. The test is in Article 6 and Annex III, and if the answer isn't clear, get a lawyer to settle it before any engineering work starts.

## What the articles require

Article 12 says a high-risk system must be able to record events automatically for as long as it's in use. The system writes its own logs. Notes kept by a person don't count.

Two other articles say how long the logs stay. Article 19 covers the provider, meaning the company that builds or supplies the system. Article 26(6) covers the deployer, the company that uses it. Both must keep the logs they control for at least six months.

Nowhere does the text say the logs must be tamper-proof. It does expect them to be useful later, when someone tries to reconstruct what happened. A log that could have been edited without leaving a trace is weak for that job.

## When the rules start

The Digital Omnibus on AI, Regulation (EU) 2026/1744, moved the dates. For systems listed in Annex III the obligations apply from 2 December 2027. For AI inside products covered by Annex I, they apply from 2 August 2028.

That sounds like plenty of time. It's less than it looks, because logs can only be shown once they exist, and six months of retention means six months of the system running with logging switched on.

## How the fines work

Article 99 sets the ceilings. Breaking the obligations for high-risk systems, logging included, can cost up to €15 million or 3% of worldwide annual turnover. A large company faces the higher of the two figures. A small or medium-sized company, start-ups included, faces the lower one.

There are two other levels. Prohibited practices can cost up to €35 million or 7%, and they have nothing to do with logging. Giving authorities incorrect or misleading information can cost up to €7.5 million or 1%.

All of these are maximums. National authorities set the actual amount case by case and take into account things like cooperation and what was done to limit harm.

## What a usable log looks like

A few properties make a log much easier to rely on when the question finally comes:

- every request, model action and tool call is written automatically;
- each entry is linked to the one before it, so an edit or a deletion shows up when the log is checked;
- the latest link is also stored somewhere else, which is the only way to notice records removed from the end;
- someone can check all of this without reading the content, which matters when prompts contain personal data.

Logging is a single obligation. Risk management, human oversight, data governance and technical documentation are separate ones, and no logging tool covers them for you.

The articles, dates and fine levels are collected on one page: [EU AI Act Article 12](https://palimpsests.dev/eu-ai-act-article-12/). Our own runtime handles the logging part for models running on your hardware: [palimpsests.dev](https://palimpsests.dev/).
