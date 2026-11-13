### Added

- **The record export is in the declared surface.**
  `palimpsests.audit.export.export_jsonl` and its format `pala-jsonl/1` join
  channel 2 beside the report, with an `__all__`, a contract test and — for
  the first time — a description of the format
  (`docs/specs/export/pala-jsonl-1.md`). The format is open: keys may be
  added, none removed or renamed. Requested by Auditor.
- **A line carries what the reader decodes**: `outcome` / `outcome_name` on a
  tool result, `disposition` / `disposition_name` and `operator_id` on an
  oversight acknowledgement, and `detail` — each present only where the
  record has it, as `source` already was. A consumer of the export no longer
  reads a TLV's hex to learn whether a tool result was `ok`, `error` or
  `unobserved`.
- **The summary says more, and says what it did not check**:
  `violation_codes` beside the sentences; `well_formed`, `malformed`,
  `bytes_parsed`, `bytes_total`; `body_digest_mismatches`; `consistent` —
  `pala verify`'s consistency, by the same rule; and
  `completeness_checked: false`, since the export reads no anchor.
  `export_jsonl` takes any bytes-like object, a file's mapping included.

### Fixed

- **The export marks a body that is not the one its record binds.** It
  decoded and printed bodies without checking them against the digest in
  their headers, so a body altered after writing was shown, unremarked, under
  a summary that said `chain_ok` — while `pala verify` reported the mismatch
  for the same file. Such a line now carries `body_digest_mismatch`, the
  summary lists its seq, and `consistent` is `false`. `chain_ok` keeps its
  meaning: the header chain.
- **The export no longer fails on a container cut mid-record.**
  `export_jsonl` raised `MalformedRecord` — and `pala export` printed a
  traceback and wrote nothing — for a file whose last record was incomplete:
  a writer caught mid-write, or a crash. It now exports every whole record
  and says in the summary where the walk stopped, as its own description
  always promised.
- **The export's memory no longer grows with the chain.** It decoded every
  record into a list before writing the first line: 448 MB for 200,002
  records of tool loops (42 MB on disk). It now reads, writes and forgets one
  record at a time — 77 MB on the same chain, 42 of them the file itself.
