### Fixed

- **An empty file checked against an anchor is diagnosed as a missing log.**
  The `empty_container` diagnosis (new in this release) took precedence even
  when an anchor named a head, so the report said `violation` while its
  sentence said the check passed because there was nothing to check. An
  anchor proves a log was written; an empty file in its place is now
  `replaced_or_rolled_back`, with a sentence saying the log is not here.
  Without an anchor, an empty file is `empty_container`, as before.
