### Documentation

- **A runbook on the site, `/runbook/`.** One task per page, in steps, each
  saying what it needs, how to check that it worked, what it does not record
  and when it was last checked: a local OpenAI-compatible server, a long chat
  on a small model, a local model in OpenCode, Claude Code tool calls, Claude
  Code hooks that report nothing, and MCP tool calls. The pages are built by
  `scripts/build_notes.py` from `runbook/*.md`, and the build now stops on a
  link to a page of the site that does not exist.
