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
category. That list is **not** alphabetical — it reads `agentops,
argilla, arize, phoenix, athina, braintrust, grafana_cloud, opik,
deepeval, helicone, …` — so do not try to place the entry by name.
**Add a new line directly after `opik_integration`, leaving that line
in place.** Overwriting a neighbour removes someone else's page from
the navigation, which is how the first attempt at this went; a
reviewer reads that as "deleted a competing integration" and closes
the PR without reading further.

Before:

```js
            "observability/grafana_cloud",
            "observability/opik_integration",
            "observability/deepeval_integration",
```

After — one line added, none changed:

```js
            "observability/grafana_cloud",
            "observability/opik_integration",
            "observability/palimpsests_integration",
            "observability/deepeval_integration",
```

Check it in the PR's **Files changed** tab before submitting:
`sidebars.js` must show **+1 / −0**. Any deletion means a neighbour was
overwritten.

## Check before submitting

1. **The page renders.** Two ways, in order of cost:
   - *Cheap and enough for the failure that matters:* compile the page
     with the site's own MDX compiler. From a checkout of `litellm-docs`
     after `npm install`, a four-line script calling
     `@mdx-js/mdx`'s `compile()` on the file catches the
     valid-Markdown-but-invalid-MDX case, which is what breaks a
     reviewer's build. Verified this way before the first submission;
     the page compiled clean, as did a control page.
   - *Full check:* `npm start` and open the page. Note that a full
     `npm run build` of this site needs a lot of memory — it was killed
     twice on a 4 GB container after compiling successfully — so a
     failure there is not necessarily the page's fault.
   - The Vercel preview on the PR renders it for free. That is the
     honest last step: it shows what a reader sees.
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

## Submitted

PR: https://github.com/BerriAI/litellm-docs/pull/1591 (2026-09-20) —
two files, +140/−0, one page and one sidebar line.

## The stronger listing, for later

LiteLLM's own contribution guide describes a **generic webhook** path:
one entry in their `generic_api_compatible_callbacks.json` and the
Standard Logging Payload is POSTed to an endpoint, after which
`callbacks: ["palimpsests"]` works **by name** in any config — no file
for the user to copy. That needs the serve to accept their payload
shape and derive the tool events server-side (the same pairing logic
the callback does today). It is a better listing than a custom-callback
page and a separate piece of work; this page does not block on it.
