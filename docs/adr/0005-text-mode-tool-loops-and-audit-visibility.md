# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

# ADR-0005 — Text-mode tool loops and audit visibility

Status: accepted (2026-08-30) · Scope: serve — what the tool-loop audit can and cannot witness

## Context

Smoke-run #189 (`docs/specs/pala-1/independent-runs/oleksandr/
ws-e-opencode-smoke/`) established, with a control matrix and verbatim
wire captures, that the audited tool loop (PALA-1 kind 8 `TOOL_CALL` /
kind 9 `TOOL_RESULT`) materialises **iff the model emits structured
tool calls that cross the endpoint**. Under OpenCode's ~9.5K-character
system prompt, every local model tried (qwen2.5-coder 7b/14b, qwen3:8b,
llama3.1:8b) narrated the call as markdown text instead; the client
parsed and executed it locally; the serve — correctly — recorded
nothing. The same matrix cleared the serve and the adapter: with a
simple prompt the identical toolset yields structured calls, returned
*and* recorded, stream and non-stream alike.

Two aggravating observations from the run:

- **A terminal renders both modes identically.** OpenCode's TUI shows a
  structured call and a text-parsed one as the same tool block; a
  visually "green" run held zero kind 8/9. The chain is the only
  witness that distinguishes an audited cycle from a narrated one.
- **Shutdown cancellation could be skipped.** Five pending `TOOL_CALL`s
  closed with zero `CANCELLED` results: cancellation hung solely on the
  ASGI shutdown event, which a Windows console Ctrl-C can bypass.

## Decision

1. **The serve records only structured tool loops parsed from the
   wire.** Text-mode loops are outside its evidential reach *by
   definition* — no OpenAI-compatible proxy can see a cycle the client
   negotiates in prose and executes locally.
2. **No prose-mining, ever.** Extracting "calls" from narrative text
   the model never committed as structure would fabricate evidence.
   A malformed or narrated call is the model's utterance; the audit
   layer does not guess on its behalf.
3. **Claims say exactly this.** The serve banner reads "structured tool
   loops recorded"; the module docstring states the limitation with the
   run-record as its citation; "works with OpenCode" promises the
   pairing, not an evidence trail, outside verified model × prompt
   configurations.
4. **Cancellation is hardened to two seams.** `_cancel_pending` is
   idempotent and is invoked both by the ASGI shutdown *and* by
   `main()`'s atexit closer immediately before the writer closes, so a
   skipped lifespan no longer loses the `CANCELLED` records. A hard
   console kill remains best-effort — stated, not hidden.

## Consequences

- An OpenCode-class session over a model that narrates tools leaves an
  honest but *silent* emptiness in the chain today: nothing false is
  recorded, and nothing is recorded. Until the first accepted direction
  below ships, distinguishing "no tools offered" from "tools offered,
  none returned structured" requires the client-side context.
- Documentation and the smoke-run instruction carry the verified
  baseline (llama3.1:8b for structured calls on simple prompts) and the
  measured caveat about heavy client prompts.

## Accepted directions (recorded here; scheduling belongs to the 0.12 plan)

1. **Advisory record — "tools offered, no structured call returned."**
   A new EVT kind in the profile's additive space, emitted by the serve
   when a request carried `tools` and the reply parsed to none. Turns
   the silent emptiness into a visible one, in-chain, without guessing
   at content. Design note first; wire stays frozen (additive only).
2. **Client-hook ingestion with origin labelling.** A minimal client
   plugin (OpenCode's plugin system first) reports executed tools to an
   authenticated serve ingestion point; the serve records
   `TOOL_CALL`/`TOOL_RESULT` carrying an origin mark distinguishing
   `reported-by-client` from `parsed-from-wire` — different evidential
   strength, honestly labelled. Closes the text-mode gap independently
   of any model's decoding behaviour.
3. **Verified-pairs table.** A living document of model × prompt
   configurations measured to hold structured calling (candidates:
   devstral, qwen3:14b, llama3.3), so "supported configurations"
   replaces folklore.
4. **Upstream report.** The control matrix is useful to OpenCode
   itself: their system prompt suppresses structured calling on small
   local models. Filing it is a goodwill contribution, not a
   dependency of anything above.
