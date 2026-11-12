### Added

- **`palimpsests doctor <integration>`** (R1, part 3): does an integration's
  reports reach the serve? For `claude-code`, `codex`, `opencode`, `litellm`,
  `mcp` or `otel` it reads the serve's status route, runs a dry run of the
  integration's route — the real key check and parsing, nothing written to
  the chain — and reads the client's configuration where it can. Each finding
  has a code, a level and a fix. It names the three silent losses measured in
  this repository's runs: Claude Code's empty bearer (a hook header that uses
  a variable not listed in `allowedEnvVars`), a client holding another key,
  and a route nothing has reached — with, for Codex, the reminder that an
  untrusted hook is skipped without a word. Exit code 1 if anything failed;
  `--json` for machines (`pala-doctor/1`). It writes nothing: not to the
  chain, not to any client's files.
