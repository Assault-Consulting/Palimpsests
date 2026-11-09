### Fixed

- **The report's existence note says what was checked.** Without a WITNESS
  record in the chain it read "tier A: none available" — a limit of a tier
  the report never reads; a tier-A head can be registered and receipted. It
  now reads "no WITNESS record in this chain; receipts held outside the chain
  (for example SCITT) are not consulted by this report". The note is a
  sentence, not a contract field; the report format is unchanged. Raised by
  Auditor.

### Added

- **`palimpsests.audit.report_html.render_html`** joins channel 2 beside
  `build_report`: the package's HTML page for a report's `.data`. The page is
  a rendering, not a format — its markup carries no contract and may change in
  any release; the JSON is the machine-readable form. Requested by Auditor.
