### Fixed

- **Surface checker: the verdict counts the records with the expected
  source.** It demanded that *every* record carry it, which the OpenCode
  probe could never meet: its stub serve is also the model provider and
  records its own wire-parsed call (source 0). Other sources are now listed
  in the Detail as not judged. No record with the expected mark is still red.
- **Surface checker on Windows: client probes get their own home through
  `USERPROFILE` as well as `HOME`.** With `HOME` alone, OpenCode and Claude
  Code read the user's real configuration — a false red for Claude Code.
  The `claude-code` probe is SKIP on Windows until the client can be given a
  temporary home without failing to start a turn; the checker does not write
  into the user's real settings. Found in the 2026-11-02 surface check.
