---
title: Log the tools OpenCode runs with a plugin
slug: opencode-tool-call-logging
group: record
order: 6
updated: 2026-11-22
description: Copy one file into OpenCode's plugins folder, and each tool it runs is reported to a tamper-evident log on your machine, whichever model is behind it.
next: opencode-with-a-local-model, claude-code-hooks-not-working, detect-log-tampering
seo_title: OpenCode plugin: log every tool call, tamper-evident
seo_description: Copy one file into OpenCode's plugins folder, and each tool it runs is reported to a tamper-evident log on your machine, whichever model is behind it.
---

OpenCode runs tools on your machine: it reads files, writes them, runs commands. A plugin inside OpenCode sees each tool as it runs and can report it to Palimpsests, which writes it into a log that cannot be changed without the change showing.

The plugin is one JavaScript file with no dependencies. It works with a cloud model or a local one.

## You need

- OpenCode.
- Python 3.11 or newer for the Palimpsests server.

## Steps

### 1. Start the server with a key

```bash
pip install 'palimpsests[serve]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
palimpsests serve
```

The second line is explained on the [runbook's first page](https://palimpsests.dev/runbook/).

### 2. Copy the plugin

For every project:

```bash
mkdir -p ~/.config/opencode/plugins
curl -o ~/.config/opencode/plugins/palimpsests-audit.js https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/v0.15.0/integrations/opencode/palimpsests-audit.js
```

For one project only, put the file in `.opencode/plugins/` inside it.

### 3. Start OpenCode from a shell that has the key

```bash
export PALIMPSESTS_SERVE_API_KEY=choose-a-long-random-string
opencode
```

The plugin reads the key from that variable. This step is the one people miss.

### 4. Check

```bash
palimpsests doctor opencode
```

If the file is in neither folder, it says so:

```text
FAIL  palimpsests-audit.js is in neither .opencode/plugins/ nor ~/.config/opencode/plugins/  [opencode_plugin_missing]
```

Then ask OpenCode to read a file, and look for the call:

```bash
palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_'
```

## What is recorded, and what is not

- Each tool OpenCode ran: its name, a fingerprint of its arguments, and how it ended.
- The records are marked `reported-by-client`. They are OpenCode's report, kept faithfully. They are not the server's own observation.
- Arguments and outputs go to the Palimpsests server, which keeps only their fingerprints.
- **Without the key in the window OpenCode starts from, nothing is recorded and nothing says so.** The reports are refused, the tools still run, and the session looks normal. `palimpsests doctor opencode` shows refused reports, and since 0.15 the server's log keeps a count of them.
- **Small local models often do not call a tool at all.** They answer with the tool call written out as text, and then no tool runs. That is the model, not a loss in the record.
- **Which callbacks OpenCode fires has changed between its versions.** On 1.18.31 the result arrived by the plugin's second path, not its first. The plugin's README keeps the status for each version tried.

## Last checked

- Windows 11, OpenCode 1.19.6, `main` shortly before 0.15.0, 22 November 2026: one call and its result reached the log, in a [surface check](https://github.com/Assault-Consulting/Palimpsests/blob/main/results/surfaces-2026-11-22.md).
- Linux: OpenCode was not checked on Linux for 0.15.
- `palimpsests doctor opencode`: palimpsests 0.15.0 from PyPI, Linux, 22 November 2026, with no plugin installed. The line above is from that run.
- Windows 11, OpenCode 1.18.31, palimpsests 0.13.1: two sessions of ten prompts with a local model, six calls and six results in each, none left without a result.
- [Every check, with its date and machine](https://github.com/Assault-Consulting/Palimpsests/blob/main/integrations/COMPATIBILITY.md)

## Reference

- [OpenCode plugin: README, with its status on each version](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/integrations/opencode/README.md)
- [Use a local model in OpenCode](https://palimpsests.dev/runbook/opencode-with-a-local-model/)
- [Integrations](https://palimpsests.dev/integrations/)
