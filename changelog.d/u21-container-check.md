### Added

- **`AuditReader.container_check()`** (U21) and its result `ContainerCheck`
  (`well_formed`, `malformed`, `bytes_parsed`, `bytes_total`,
  `body_digest_mismatches`): the second half of question one — is the
  container well-formed, and does every body match its header's digest —
  as a call of its own. Until now it was reachable only by building a
  report. `verify()` reads headers alone and cannot see a swapped body;
  this can. Computed once per reader. The report's `container` section is
  now this object, so the reader and the report cannot disagree; the
  report's output is unchanged.
