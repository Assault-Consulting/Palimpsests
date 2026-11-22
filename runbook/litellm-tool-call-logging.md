---
title: Log LiteLLM tool calls with one callback
slug: litellm-tool-call-logging
group: record
order: 4
updated: 2026-11-22
description: Add one file to a LiteLLM client or proxy, and every tool the model asks for, with the result your code fed back, lands in a tamper-evident log on your machine.
next: opentelemetry-genai-tool-calls, mcp-tool-call-logging, detect-log-tampering
seo_title: LiteLLM logging callback for tool calls, tamper-evident
seo_description: Add one file to a LiteLLM client or proxy, and every tool the model asks for, with the result fed back, lands in a tamper-evident log on your machine.
---

LiteLLM sits between your code and a model. It sees the model's answer, including the tools the model asks for, and on the next request it sees the results your code sends back. A callback placed there can report both to Palimpsests, which writes them into a log that cannot be changed without the change showing.

The callback is one Python file that needs nothing beyond LiteLLM. It never blocks a completion and never changes one.

## You need

- Python code that calls models through LiteLLM, or a LiteLLM proxy.
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

### 2. Download the callback

```bash
curl -O https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/v0.15.0/integrations/litellm/palimpsests_audit.py
```

Put it next to your code.

### 3. Register it

In Python:

```python
import litellm
from palimpsests_audit import PalimpsestsAudit

litellm.callbacks = [PalimpsestsAudit()]
```

For the proxy, put two lines in a `custom_callbacks.py` beside `config.yaml`:

```python
from palimpsests_audit import PalimpsestsAudit
palimpsests_audit = PalimpsestsAudit()
```

and name it in the configuration:

```yaml
litellm_settings:
  callbacks: custom_callbacks.palimpsests_audit
```

The callback reads the key from `PALIMPSESTS_SERVE_API_KEY`, and the server's address from `PALIMPSESTS_SERVE_URL` when it is not `http://127.0.0.1:11435`. Set them in the shell your code or proxy starts from.

### 4. Check

```bash
palimpsests doctor litellm
```

After one completion that used a tool and fed the result back:

```text
ok    the serve answers; its chain holds 5 record(s)  [serve_reachable]
ok    2 report(s) accepted on /v1/pala/events since the serve started  [reports_arriving]
```

And in the log:

```bash
palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_'
```

## What is recorded, and what is not

- A tool the model asked for: its name and a fingerprint of its arguments.
- A result your code sent back for that call, with the outcome `unobserved`. LiteLLM never sees the tool run, so the log does not say whether it worked.
- Both are marked `reported-by-client`. They are your code's report, kept faithfully. They are not the server's own observation.
- A call whose result never comes back is closed as `cancelled` when the server stops.
- Arguments and results go to the Palimpsests server, which keeps only their fingerprints.
- Prompts and replies are not recorded.
- **Without the key in the shell your code starts from, nothing is recorded and your code sees no error.** Run the check in step 4.
- Once a request carries `tools`, LiteLLM itself needs the `mcp` package: `pip install litellm mcp`.

## Last checked

- Linux, LiteLLM 1.110.2, palimpsests 0.15.0 from PyPI, 22 November 2026: two completions with LiteLLM's built-in mock answers, no provider, through the callback file from the 0.15.0 tag. One call and its result reached the log, marked `reported-by-client`, the result `unobserved`. The `doctor` output above is from that run.
- Linux, LiteLLM 1.110.2, `main` shortly before 0.15.0, 22 November 2026: one call and its result reached the log, in a [surface check](https://github.com/Assault-Consulting/Palimpsests/blob/main/results/surfaces-2026-11-22-2.md).
- Windows: not checked for 0.15. On the machine used, a security policy blocked a library LiteLLM needs.
- No run with a real provider is on record for this page.
- [Every check, with its date and machine](https://github.com/Assault-Consulting/Palimpsests/blob/main/integrations/COMPATIBILITY.md)

## Reference

- [LiteLLM callback: README](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/integrations/litellm/README.md)
- [Recording agent tool calls](https://palimpsests.dev/notes/recording-agent-tool-calls/)
- [Integrations](https://palimpsests.dev/integrations/)
