### Added

- **`verify_statement` can take the expected head from the chain.** With a
  `reader` and no `expected_head`, a SCITT statement is compared with the
  hash of the record at its own `last_seq` in that chain: "is this
  statement about this chain", for a chain that has grown since the
  statement was signed, without the caller reading the payload first. The
  range is judged before the chain is consulted; a chain with no record at
  that seq is refused as `chain_too_short`. `StatementCheck.head_seq` is
  the seq compared at, `None` when the caller supplied the head. A call
  that passes a head is unchanged. One call changes its answer: `None` as
  the head *with* a reader was always `head_mismatch` and is now this
  check.
- **The verification report's fixed sentences have names.** `NOTES` and
  `HEALTH_BASES` are exported from `palimpsests.audit.report`, and a report
  carries `note_id` beside each `note` and `basis_id` beside each `basis`,
  so a consumer can show them in another language by name instead of by
  matching English text. The format stays `pala-verification-report/2`:
  the fields are additions, optional in the schema, and a report written by
  0.15.0 still validates.
