---
title: An audit trail for AI agents: what it is and how to keep one
slug: ai-agent-audit-trail
updated: 2026-11-26
description: An AI agent acts through tools: it reads files, runs commands, sends requests. An audit trail is the record of those actions that someone else can check later.
eyebrow: AI agents · audit trail
crumb: Audit trail for AI agents
seo_title: AI agent audit trail: what it is and how to keep one
seo_description: An AI agent acts through tools. An audit trail is the record of those actions that someone else can check later: what goes in it, and how to keep one.
---

## What an agent does that is worth recording

A model produces text. An agent does things: it reads a file, runs a command, calls an API, writes to a database. Each of those is a tool call, and the tool call is the moment the agent touches something outside itself.

So the question after the fact is rarely "what did the model say". It is "what did the agent do, in what order, and did each thing work". An audit trail answers that.

## A log is not yet an audit trail

Most agents already write logs. A log becomes an audit trail when a person who did not write it can rely on it. That takes three things.

- **The order is fixed.** Every record carries a fingerprint of the one before it, so records cannot be moved, removed or inserted without the fingerprints breaking.
- **A change shows.** Nobody can make a file impossible to edit. What can be done is to make every edit visible, and that is what tamper-evident means. See [what makes an audit log tamper-evident](https://palimpsests.dev/notes/what-makes-an-audit-log-tamper-evident/).
- **The other side can check it.** The check needs the file and a published format. It does not need your software, your account or your decryption key. See [verify without reading](https://palimpsests.dev/verify-without-reading/).

## What goes on the record

For each tool call, two records: the call and its result.

- **The call**: which tool, and a fingerprint of its arguments.
- **The result**: how it ended. `ok` means a result came back. `error` means the tool reported a failure. `unobserved` means the recorder could not see which, and says so. `cancelled` means no result ever came.
- **Who says so**: a record is marked as seen by the server itself, reported by the client, or read out of telemetry. These are different strengths of evidence and are kept apart.
- **When**: a counter that always runs, and the date together with how far the clock can be believed.
- **What went wrong around it**: a restart, a writer that stopped without closing, reports that were refused. A gap that is written down is one you can explain later.

The contents are not stored. Arguments and results go in as fingerprints, so the trail shows that something happened and lets you prove what it was if you kept it, without the trail itself holding private data.

## Three ways to connect an agent

**A hook in the client.** Some clients can report each tool call as it happens. This is the closest view of what the agent ran.

- [Log Claude Code tool calls on your own machine](https://palimpsests.dev/runbook/log-claude-code-tool-calls/)
- [Log the tools OpenCode runs with a plugin](https://palimpsests.dev/runbook/opencode-tool-call-logging/)

**A proxy in front of the tools.** The agent talks to its tools through a small program that records each call on the way.

- [Record the tool calls of an MCP server](https://palimpsests.dev/runbook/mcp-tool-call-logging/)

**A callback or telemetry you already have.** If the calls already pass through a library or are already exported as traces, the record is taken from there.

- [Log LiteLLM tool calls with one callback](https://palimpsests.dev/runbook/litellm-tool-call-logging/)
- [Record tool calls from OpenTelemetry traces](https://palimpsests.dev/runbook/opentelemetry-genai-tool-calls/)

Every route, with what was run and on which version, is on the [integrations page](https://palimpsests.dev/integrations/).

## Where the trail lives

On your machine. The model may run in the cloud; the tools run where you are, and so does the record of them. Nothing in the trail has to leave your hardware. See [an audit log for agents that run on cloud models](https://palimpsests.dev/notes/audit-log-for-agents-on-cloud-models/) and [air-gapped deployments](https://palimpsests.dev/air-gapped/).

## What it proves, and what it does not

It proves that these reports were made, in this order, and have not been changed since. With the latest fingerprint kept somewhere else, it also proves that nothing was cut off the end.

It does not prove the rest, and it is better to know that now.

- **Not that the tool did what it reported.** A result of `ok` is a report that a result came back.
- **Not that everything was reported.** A client that runs a tool without telling anyone leaves no record. A hook without its key reports nothing and shows no error; see [Claude Code hooks are not recording anything](https://palimpsests.dev/runbook/claude-code-hooks-not-working/).
- **Not that the agent was right.** A wrong action is recorded as faithfully as a correct one.
- **Not who was at the keyboard.** The trail names a client and a session, not a person.
- **Not compliance.** A trail is evidence you can hand over. Meeting an obligation is still yours to do.

## Check one yourself

- [Check a log for tampering](https://palimpsests.dev/runbook/detect-log-tampering/)
- [Hand an auditor one file of evidence](https://palimpsests.dev/runbook/audit-evidence-bundle/)
- [Keep a log for six months without filling the disk](https://palimpsests.dev/runbook/rotate-a-hash-chained-log/)

## Questions

### Is an audit trail the same as tracing or observability?

No. Tracing tells the team that runs a system where time and money went, and is usually kept for days or weeks. An audit trail tells someone outside the team what happened, in a form they can check, and it is kept for months or years. One does not replace the other.

### Does the trail store prompts or the contents of tool calls?

No. Arguments and results are stored as SHA-256 fingerprints. Their contents never enter the trail.

### Does it work when the model runs in the cloud?

Yes. What is recorded is the agent's tool calls on your machine, not the model. The trail stays on your hardware whether the model is local or behind an API.

### Can the owner of the trail rewrite it?

The owner of a file can always write a new file. What stops a quiet rewrite is a copy of the latest fingerprint kept where the owner cannot change it. Without that copy, a trail shows changes inside it but not a replacement of the whole.

### Which agents are supported?

Claude Code, Codex, OpenCode, anything that calls models through LiteLLM, any framework that exports OpenTelemetry tool spans, and MCP servers that speak over standard input and output. Each is listed on the integrations page with the run it rests on.
