---
title: Record tool calls from OpenTelemetry traces
slug: opentelemetry-genai-tool-calls
group: record
order: 5
updated: 2026-11-22
description: An agent framework that already sends OpenTelemetry traces can send them to Palimpsests too. Three variables, and every tool it runs lands in a tamper-evident log.
next: litellm-tool-call-logging, mcp-tool-call-logging, detect-log-tampering
seo_title: OpenTelemetry GenAI tool calls in a tamper-evident log
seo_description: An agent framework that already sends OpenTelemetry traces can send them to Palimpsests too: three variables, and every tool it runs lands in the log.
---

Many agent frameworks describe their work with OpenTelemetry. The conventions for AI put one span on each tool an agent runs, named `execute_tool` and the tool's name. Point the framework's trace exporter at Palimpsests, and those spans become records in a log that cannot be changed without the change showing.

Nothing is installed in the application. A trace viewer shows you what happened; this keeps a record that someone else can check.

## You need

- An application or framework that exports OpenTelemetry traces over HTTP and follows the GenAI conventions for tool spans.
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

### 2. Point the exporter at it

In the shell your application starts from:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:11435/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer $PALIMPSESTS_SERVE_API_KEY"
```

`http/json` works too. gRPC is not accepted.

### 3. Optional: fingerprints of arguments and results

Without this, a record holds the tool's name, the call's id and whether the span ended in an error. To add fingerprints of what went in and what came out, turn on your instrumentation's content capture. For the Python GenAI instrumentations:

```bash
export OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
```

The content goes to the Palimpsests server, which keeps only its fingerprint.

### 4. Check

```bash
palimpsests doctor otel
```

```text
ok    1 report(s) accepted on /v1/traces since the serve started  [reports_arriving]
ok    the trace exporter points at this serve  [otel_endpoint_set]
```

It reads the exporter variables of the shell it runs in, which may not be the shell your application started from. Then look in the log:

```bash
palimpsests pala export ~/.config/palimpsests/serve.pala | grep '"kind_name":"TOOL_'
```

## What is recorded, and what is not

- One call and one result for each `execute_tool` span that names its tool.
- The result is `error` if the span ended with an error status, and `ok` otherwise. `ok` means the span ended without an error. A tool that *returned* an error as its answer is a success to OpenTelemetry, and `ok` here.
- Each record is marked `derived-from-telemetry`: it was read out of a trace, and is kept apart from a pair a client reported itself.
- Other spans, such as model calls, are not recorded. This is not a trace backend.
- A tool span with no tool name is not recorded, and the reply to the exporter counts it.
- **The GenAI conventions are still changing.** The version a span declares is written beside its record, or `unstated`.
- If the MCP proxy and this route both see the same calls, each call is recorded twice. Use one.
- A batch sent again by a retrying exporter is recorded once.

## Last checked

- Linux, palimpsests 0.15.0 from PyPI, 22 November 2026: one tool span written by hand and sent as OTLP/JSON. One call and its result reached the log, marked `derived-from-telemetry`, the result `ok`. The `doctor` output above is from that run.
- Linux and Windows 11, pydantic-ai 2.71.0 with the OTLP/HTTP exporter 1.45.2, `main` shortly before 0.15.0, 22 November 2026: one call and its result reached the log, in [surface checks](https://github.com/Assault-Consulting/Palimpsests/blob/main/integrations/COMPATIBILITY.md).
- Other frameworks: none is on record. A framework is named here only after a run.

## Reference

- [OpenTelemetry route: README](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/integrations/otel/README.md)
- [Recording agent tool calls](https://palimpsests.dev/notes/recording-agent-tool-calls/)
- [Integrations](https://palimpsests.dev/integrations/)
