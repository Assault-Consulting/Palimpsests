### Added

- **`GET /v1/pala/status`: what reached the serve** (R1, part 1). Per
  ingestion route (`/v1/pala/hooks/claude`, `/v1/pala/hooks/codex`,
  `/v1/pala/events`, `/v1/traces`): requests accepted, refused by the bearer
  check — an empty bearer counted apart from a wrong one — and rejected
  otherwise, with the time of the last of each; the pending tool calls; the
  chain's length and head. A client whose reports are refused or never sent
  looks normal from its own side — measured in runs R1 (Claude Code, empty
  bearer), R2 (Codex, untrusted hooks) and OpenCode run 3 (no key, 401) —
  and these counters let an operator tell the three apart. Behind the same
  bearer as every route; writes nothing to the chain. The shape
  (`pala-serve-status/1`) is experimental until the HTTP surface gets a
  stability class.
