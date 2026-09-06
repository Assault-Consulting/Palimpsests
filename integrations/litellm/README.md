# Palimpsests audit callback for LiteLLM

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

One file, standard library only. Attach it to a LiteLLM client or to the
LiteLLM proxy, and every **structured** tool loop that passes through
LiteLLM — which is every framework that routes through the proxy — lands
on a Palimpsests chain as `TOOL_CALL` / `TOOL_RESULT` records marked
`reported-by-client`, through the serve's ingestion surface.

## What it sees, and therefore what it can honestly report

LiteLLM sits between an application and a model provider. It sees the
model's *response* — including the `tool_calls` the model asked for — and,
on the *next* request, the `role: tool` messages the application fed back.
It never sees the tool run.

| It reports | As | Meaning |
|---|---|---|
| a `tool_calls` entry in a response | `TOOL_CALL` — registered name + argument digest | the model asked for this tool with these arguments |
| a `role: tool` message for a call it reported | `TOOL_RESULT`, outcome `ok` | a result re-entered generation — **not** that the action took effect |
| a call whose result never comes back | `cancelled`, written by the serve at shutdown | abandonment, recorded as abandonment |

Same pairing rule the serve applies to loops on its own wire; the
difference is the mark. A wire-parsed pair is the runtime's observation. A
pair reported from here is the client's assertion, faithfully recorded —
the chain proves the report and its digests, not that the tool ran.
Arguments and tool outputs are sent to the serve, which stores only their
digests; content never enters the chain.

## Install

Python client:

```python
import litellm
from palimpsests_audit import PalimpsestsAudit   # this file, on your path

litellm.callbacks = [PalimpsestsAudit()]
```

Proxy — `custom_callbacks.py` beside `config.yaml`:

```python
from palimpsests_audit import PalimpsestsAudit
palimpsests_audit = PalimpsestsAudit()
```

```yaml
litellm_settings:
  callbacks: custom_callbacks.palimpsests_audit
```

| Variable | Meaning | Default |
|---|---|---|
| `PALIMPSESTS_SERVE_URL` | base URL of the serve | `http://127.0.0.1:11435` |
| `PALIMPSESTS_SERVE_API_KEY` | bearer key when the serve runs with `--api-key` | unset |
| `PALIMPSESTS_AUDIT_REPORT` | `0` disables reporting | enabled |

## For your coding agent — paste this

```text
Install the Palimpsests audit callback for LiteLLM.

1. Copy `integrations/litellm/palimpsests_audit.py` from the
   Assault-Consulting/Palimpsests repository next to the code (or the
   proxy's custom_callbacks.py). It has no dependencies beyond LiteLLM
   itself; do not pip-install anything for it.
2. Register it: `litellm.callbacks = [PalimpsestsAudit()]`, or in the
   proxy config `litellm_settings.callbacks: custom_callbacks.palimpsests_audit`.
3. Start the serve: `pip install 'palimpsests[serve]' && palimpsests serve`
   (default http://127.0.0.1:11435). If it runs with --api-key, export
   PALIMPSESTS_SERVE_API_KEY with the same value.
4. Run one completion that uses tools and feeds the result back, then:
   `palimpsests pala export serve.pala | grep -c '"kind_name":"TOOL_CALL"'`
   should be > 0 and those lines carry `"source":1`.

Rules: the callback never blocks or alters a completion; a failed report
is logged and the completion proceeds. Reported records prove that the
model asked for a call and that a result was fed back — not that the tool
ran, and not that the action took effect. Do not describe this as
"verified tool execution"; describe it as a hash-chained record of the
tool loop as LiteLLM observed it, marked as reported.
```

## Contract

- **Never blocks, never alters.** Reports run beside the completion; a
  failure is a `logging` warning (`palimpsests.audit.litellm`).
- **One result per call.** A call id is reported once, ever; its result
  once; duplicates are ignored.
- **Hook order does not matter.** LiteLLM runs success hooks off the
  request thread, so the hook for turn N+1 (carrying a tool result) can
  fire before the hook for turn N (carrying the call). A result whose call
  has not been reported yet is held and sent right after the call, in one
  batch, in order.
- **Streaming** is handled by LiteLLM before the hook runs: streamed tool
  calls arrive assembled.

## Tested

`tests/test_adapters.py` drives the `Reporter` on OpenAI-shaped
responses against a live serve (pairing, the never-answered call, the
early-result race, the disabled switch) and, when LiteLLM is installed,
the real `CustomLogger` wiring through `litellm.completion(...,
mock_tool_calls=...)` with no provider.
