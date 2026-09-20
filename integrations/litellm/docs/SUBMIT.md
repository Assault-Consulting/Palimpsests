<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Submitting the LiteLLM docs page

The page next to this file is staged, not submitted. This is the recipe
for getting it upstream, and what to check before doing so.

## Where it goes

The documentation left the main LiteLLM repository — `BerriAI/litellm`
has no `docs/` directory any more. The site source is now
**`BerriAI/litellm-docs`** (Docusaurus 3, deployed by Vercel on push to
`main`).

| What | Where |
|---|---|
| The page | `docs/observability/palimpsests_integration.md` |
| Navigation | `sidebars.js` (repository root; **not** `sidebars-release-notes.js`) |
| Their rules | `CONTRIBUTING.md` and `AGENTS.md`, both at the root — read before opening the PR |

The sidebar entry belongs in the **"LLM observability platforms"**
category, which is alphabetical by file name. Between `opik_integration`
and `promptlayer_integration`:

```js
            "observability/opik_integration",
            "observability/palimpsests_integration",
            "observability/promptlayer_integration",
```

## Check before submitting

1. **The page renders.** `npm install && npm start` in a fork of
   `litellm-docs`, then open the page from the sidebar. A Docusaurus
   build fails on a broken MDX construct, and this page has tables,
   fenced code and no JSX — but check rather than assume.
2. **The quickstart does what it says.** The page tells a reader to
   install the callback, run a completion with tools, feed the result
   back, and grep the chain. Run exactly that. Verified on
   litellm 1.102.0 against an in-process serve: two completions produced
   a `TOOL_CALL` / `TOOL_RESULT` pair, both `"source": 1`
   (`reported-by-client`), chain of 4 records, `chain_ok: true`.
3. **Every claim in the page is one we can defend.** The page says the
   chain proves the report and its digests, never that a tool ran. If a
   reviewer asks for a stronger sentence, the answer is no.

## What the page deliberately does not say

- It does not claim LiteLLM "supports" Palimpsests, or that the
  integration is endorsed. It describes a callback a user can install.
- It does not quote adoption numbers. There are none worth quoting.
- It does not mention the OpenCode plugin's state on 1.18.x. That is
  our repository's business, not a LiteLLM reader's.

## The stronger listing, for later

LiteLLM's own contribution guide describes a **generic webhook** path:
one entry in their `generic_api_compatible_callbacks.json` and the
Standard Logging Payload is POSTed to an endpoint, after which
`callbacks: ["palimpsests"]` works **by name** in any config — no file
for the user to copy. That needs the serve to accept their payload
shape and derive the tool events server-side (the same pairing logic
the callback does today). It is a better listing than a custom-callback
page and a separate piece of work; this page does not block on it.
