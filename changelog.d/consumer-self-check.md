### Added

- **`AuditReader.is_consistent()`** — question one as one answer: the header
  chain verifies, the container walks to its end, every body matches its
  header's digest. The export, the bundle and `pala verify` each had this
  answer; the reader gave only its parts, and a consumer that assembled it as
  `chain_ok and diagnosis is None` reported a whole chain as "not whole"
  whenever its anchor lagged.
- **`Diagnosis.question`** — which of the three questions a diagnosis is
  about: `consistency`, `completeness`, or `None`. There is one diagnosis for
  all three, and `unanchored_tail` and `replaced_or_rolled_back` are findings
  about the anchor, not about the chain. The report carries it as
  `diagnosis.question` (`pala-verification-report/2` is open to added keys).
- **The open vocabularies as data** in `palimpsests.audit.reader`:
  `DIAGNOSIS_PATTERNS`, `DIAGNOSIS_QUESTIONS`, `ADVISORY_CODES`,
  `VIOLATION_CODES`, `MANIFEST_STATUSES` — what the installed build can say.
  A consumer that keeps guidance per pattern or a sentence per code can now
  test that its table covers them.
- `assurance_tier_name` and `time_trust_name` are importable from
  `palimpsests.audit.reader` (the same objects as in `palimpsests.audit.names`,
  which stays), and `palimpsests.audit.report` has an `__all__`.

### Fixed

- **`build_report` no longer holds the file twice.** Called without a
  `reader` — as it must be when an anchor is given — it read the whole file
  into memory and then mapped it as well. The digest and the size now come
  from the one mapping; the report is byte-identical.
