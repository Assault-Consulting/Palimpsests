<!--
SPDX-FileCopyrightText: Assault Consulting
SPDX-License-Identifier: Apache-2.0
-->

# The serve's HTTP surface

What `palimpsests serve` answers over HTTP, and how far each part of it
can be relied on. The reading surface has its own contract
([INTEGRATION-SURFACE.md](INTEGRATION-SURFACE.md)), and so has the writer
([WRITER-SURFACE.md](WRITER-SURFACE.md)); this is the third: the routes an
integration posts to.

The routes are not of one kind, so they do not share one promise.

| Routes | Class | Why |
|---|---|---|
| `POST /v1/pala/events`, `POST /v1/pala/hooks/claude`, `POST /v1/pala/hooks/codex`, the bearer check, the dry run, `GET /v1/pala/status`, `palimpsests doctor --json` | **public** (since 0.15) | The project's own protocol. Every integration it ships posts here |
| `POST /v1/traces` | **provisional** (since 0.15) | It reads another project's schema — the OpenTelemetry GenAI conventions — which is itself still changing |
| `POST /v1/chat/completions`, `GET /v1/models` | **compatibility** | They follow the OpenAI API. What is promised is what this document states, not that API as a whole |

**Public** and **provisional** mean what they mean in
[INTEGRATION-SURFACE.md](INTEGRATION-SURFACE.md): a public part breaks
only with a minor version bump and a changelog entry naming the break,
and from 1.0 not within a major; a provisional part may change in a minor
release, named in the changelog. Everywhere below, a JSON object is
**open**: a release may add a key, and a client ignores a key it does not
know. `tests/test_serve_surface.py` holds the public part to this
document.

Not part of any class: the wording of an error `message`, log lines, and
anything this document does not state.

## Authentication

With `--api-key` (or `PALIMPSESTS_SERVE_API_KEY`), every route requires
`Authorization: Bearer <key>`. Anything else is answered

```
401  {"error": {"message": "…", "type": "invalid_request_error", "code": "invalid_api_key"}}
```

Without a key the serve answers every request and reports
`"auth_required": false` in its status. That is a serve for one machine;
see [SECURITY.md](../SECURITY.md).

A refusal is counted (below) and written nowhere on the chain.

## Reporting tool events — `POST /v1/pala/events`

For a client that runs its own tools and tells the serve about them.
Each call and each result becomes one record, marked
`reported-by-client`.

Request:

```json
{"events": [
  {"type": "tool_call",   "id": "c1", "name": "read_file", "arguments": {"path": "a.txt"}},
  {"type": "tool_result", "call_id": "c1", "outcome": "ok", "content": "…"}
]}
```

| Event | Field | |
|---|---|---|
| `tool_call` | `id` | required — the client's own id for the call |
| | `name` | required — the tool |
| | `arguments` | optional — digested by the serve (RFC 8785 canonical JSON, then SHA-256), never stored |
| | `args_digest` | optional, hex — a digest the client computed; used as given, instead of `arguments` |
| `tool_result` | `call_id` | required — the `id` of a call reported earlier |
| | `outcome` | optional — `ok`, `error`, `timeout`, `cancelled`, `unobserved`. **Absent means `unobserved`**: a client that does not state success has not stated it |
| | `content` | optional — digested, never stored |
| | `result_digest` | optional, hex — used as given, instead of `content` |

Reply, `200`:

```json
{"results": [
  {"id": "c1", "seq": 12, "record_hash": "…"},
  {"id": "c1", "record_hash": "…"}
]}
```

One entry per event, in order. An event that could not be recorded has
`error` in place of `record_hash`, and the events around it are recorded
all the same: the chain is append-only, so a batch is not all-or-nothing
and there is no unwriting. A result whose `call_id` is unknown, or whose
`outcome` is not one of the five, is such an entry; the call stays open.

`400` when `events` is not a non-empty list. `503` when the serve has no
audit chain.

## Agent hooks — `POST /v1/pala/hooks/claude`, `POST /v1/pala/hooks/codex`

The body is the hook event as the agent sends it (the Claude Code hook
schema, which Codex shares). Read from it: `hook_event_name`, `tool_name`,
`tool_use_id`, and — digested, never stored — `tool_input` and the tool's
response.

| `hook_event_name` | Recorded as |
|---|---|
| `PreToolUse` | a tool call |
| `PostToolUse` | its result — `ok` from Claude Code; `unobserved` from Codex, which sends this event for a failure too |
| `PostToolUseFailure` | its result, `error` — Claude Code only |
| any other | accepted, not recorded |

**The reply never carries a decision.** It is `200 {}`, so the tool
always proceeds: the serve records, it does not gate. An event delivered
twice is answered `200 {}` and recorded once.

`400` for a body that is not an object, a tool event without `tool_name`
and `tool_use_id`, or a `PostToolUseFailure` on the Codex route. `503`
when the serve has no audit chain.

## The dry run — `X-Palimpsests-Dry-Run: 1`

On any of the four reporting routes, this header runs the same bearer
check and the same parsing and **writes nothing**: not to the chain, not
to the open calls, not to the accepted counters. The reply says what
would have been recorded:

```json
{"dry_run": true,
 "would_record": [{"record": "TOOL_CALL", "tool": "read_file",
                   "source": "reported-by-client", "payload_digest": true}],
 "results": [{"id": "c1"}]}
```

`would_record` entries carry `record` (`TOOL_CALL` or `TOOL_RESULT`),
`source` (`reported-by-client`, or `derived-from-telemetry` on the traces
route), `payload_digest` (whether a digest would be kept), and `tool`
or `outcome`. There is no `seq` and no `record_hash`: nothing was written
to refer to. The hook routes add `reply`, the reply the agent would have
had.

It exists so that checking an integration never puts a call on the chain
that nobody made.

## What reached the serve — `GET /v1/pala/status`

```json
{"format": "pala-serve-status/1",
 "auth_required": true,
 "ingest": {"/v1/pala/events": {"accepted": 3,
                               "refused": {"empty_bearer": 0, "wrong_bearer": 1},
                               "rejected": 0, "dry_run": 2,
                               "last_accepted_ns": 1790000000000000000,
                               "last_refused_ns": null}},
 "pending_calls": 1,
 "chain": {"records": 41, "head": "…", "durability": "record"}}
```

- `ingest` has one entry per reporting route. `accepted`, `rejected`
  (answered with another error) and `dry_run` count requests, not
  records. `refused` separates an empty bearer from a wrong one: an
  agent's hook that names an environment variable it is not allowed to
  read sends an empty one, silently.
- `pending_calls` — calls reported with no result yet.
- `chain` — `null` when the serve has no audit chain; otherwise its
  length, its head, and when a record is on stable storage
  ([WRITER-SURFACE.md](WRITER-SURFACE.md) §4).

Behind the same bearer as every route. It reads state and writes
nothing. `pala-serve-status/1` is open to added keys and added routes.

## The integration check — `palimpsests doctor <integration> --json`

```json
{"format": "pala-doctor/1", "integration": "claude-code", "ok": false,
 "findings": [{"level": "fail", "code": "claude_allowed_env_missing",
               "message": "…", "fix": "…"}]}
```

`level` is `ok`, `warn` or `fail`; `ok` at the top is false when any
finding failed, and the command then exits 1. `code` is the field to
branch on, from an open vocabulary; `message` and `fix` are sentences.

## Provisional — `POST /v1/traces`

OTLP/HTTP trace export, JSON or protobuf, optionally gzip. Only
`execute_tool` spans are recorded, one call and one result each, marked
`derived-from-telemetry` (until 0.15: `reported-by-client`); the rest of a
trace is accepted and not kept — this
is not a trace backend. Tool spans that cannot be recorded are reported as
OTLP `partialSuccess`, not as an error, so an exporter does not retry what
will never be recorded. Protobuf needs the `[serve]` extra.

Provisional because the attribute names it reads are those of the
OpenTelemetry GenAI semantic conventions, which are not yet stable; a
span of an unknown convention version is recorded with the version
marked.

## Compatibility — `POST /v1/chat/completions`, `GET /v1/models`

The request and response shapes are the OpenAI API's, to the extent a
client of that API needs for chat with tools and streaming. What this
project promises about them is its own part: with an audit chain
configured, a tool call the model emits and a tool result the next
request carries are recorded as parsed from the wire, and a call with no
result at shutdown is closed as `cancelled`. Which fields of the OpenAI
API are honoured is not a contract.
