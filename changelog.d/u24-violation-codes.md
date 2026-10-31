### Added

- **Every chain violation carries a code** (U24): `VerifyResult.violation_codes`,
  parallel to `violations` (same order, one per violation), and
  `Diagnosis.code` for `record_violation`. Ten codes, listed in
  `docs/INTEGRATION-SURFACE.md` and `palimpsests.audit.pala.incremental.VIOLATION_CODES`;
  an open vocabulary. Branch on the code — the reason beside it is a
  sentence and may change. The reader now recognises a missing prefix by its
  code, not by matching the sentence.
- The verification report (`pala-verification-report/1`) does not carry the
  codes: its schema closes the `chain` object, so they arrive with `/2`.
