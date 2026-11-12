### Added

- **A dry run of the ingestion path** (R1, part 2). A request to
  `/v1/pala/hooks/claude`, `/v1/pala/hooks/codex`, `/v1/pala/events` or
  `/v1/traces` carrying `X-Palimpsests-Dry-Run: 1` passes the real bearer
  check and the real ingestion code, and the reply says what would have been
  recorded (`would_record`) — while the chain, the pending calls and the
  accepted counters stay exactly as they were. A check of an integration can
  therefore exercise the whole path without putting a call nobody made onto
  an append-only audit chain. The status route counts dry runs apart from
  accepted reports.
