# OpenTelemetry GenAI — recording the tool loop from traces

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

An application or agent framework instrumented with OpenTelemetry already
describes every tool it runs: the GenAI semantic conventions put one span
on each tool execution — `gen_ai.operation.name = execute_tool`, named
`execute_tool <tool name>`. Point its OTLP trace exporter at the serve and
those spans land on the chain as `TOOL_CALL` / `TOOL_RESULT` pairs, marked
`reported-by-client`. Nothing to install on the application side.

## Setup

1. Run the serve (`pip install 'palimpsests[serve]'`, then
   `palimpsests serve`; add `--api-key` if anything beyond your own shell
   can reach the port).
2. Point the application's exporter at it — the standard OTLP variables:

   ```bash
   export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:11435/v1/traces
   export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/protobuf   # or http/json
   export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer $PALIMPSESTS_SERVE_API_KEY"
   ```

   OTLP/HTTP only — JSON or protobuf, optionally gzip. gRPC is not
   accepted.
3. To get **digests of the arguments and results**, turn on the
   instrumentation's content capture (for the Python GenAI
   instrumentations: `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`).
   Without it a span carries the tool's name, call id and status, and the
   pair is recorded **without digests** — a weaker record than the agent
   hooks give. With it, `gen_ai.tool.call.arguments` and `.result` are
   digested by the profile's canonical rule; the content itself never
   reaches the chain.

## What lands, and what it means

| On the span | On the chain |
|---|---|
| `execute_tool` span with a tool name (attribute or span name) | one `TOOL_CALL` + one `TOOL_RESULT`, in the batch's start-time order |
| status `ERROR` | outcome `error`; `error.type` in the call's detail |
| status `OK` or unset | outcome `ok` — the span ended without an error status |
| `schemaUrl` of the scope or resource | `semconv <version>` in the call's detail, or `unstated` |
| any other span (`chat`, `invoke_agent`, …) | nothing — this is not a trace backend |
| an `execute_tool` span with no tool name anywhere | not recorded; counted in the reply's `partialSuccess` with the reason |

**What `ok` claims, exactly.** The conventions mark a failed tool by the
span's error status, so this vantage does see failure — unlike Codex's
hooks, whose results are `unobserved`. What it cannot see is a tool that
*returned* an error as its result: to OpenTelemetry that is a success,
and on the chain it is `ok` — a return, never a confirmed effect.

## Limits, stated

- **The GenAI conventions are in Development** and change between
  releases. A span of any declared version is recorded, its version
  written beside it; the adapter reads `gen_ai.operation.name`,
  `gen_ai.tool.name`, `gen_ai.tool.call.id`, `.arguments`, `.result` and
  `error.type`, and takes the tool name from the span name
  (`execute_tool <name>`, required since 1.41) when the attribute is
  absent.
- **Order across batches is arrival order.** Within one export the pairs
  are written by each span's start time; an exporter that sends an
  earlier span in a later batch has it recorded after the later one. The
  chain is append-only — it records when it was told.
- **MCP tool calls appear twice if two recorders see them.** MCP spans
  also carry `execute_tool`; with both this route and the
  [MCP proxy](../mcp/) on the same calls, each call lands once from each.
  Use one.
- **Retries are recorded once.** An exporter that re-sends a batch it
  thinks failed does not create duplicates: the serve remembers the last
  16 384 span ids.
