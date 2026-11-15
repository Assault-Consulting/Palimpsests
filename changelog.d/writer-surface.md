### Added

- **The writer has a contract: `docs/WRITER-SURFACE.md`.** What is declared
  (`palimpsests.audit.pala_writer.__all__`), the rules of a chain's life,
  the record each method writes, what the writer guarantees — what it writes
  verifies; one process, many threads; a torn tail is truncated and recorded
  — and what it does not: **it does not `fsync` each record**, so a power
  loss can lose the last ones. Public and experimental until 1.0;
  `tests/test_writer_surface.py` holds the document to the code, the table
  of methods included.
- **`palimpsests.audit.testing` — damaged chains for a consumer's tests.**
  Eight builders, each one named defect made from a well-formed chain
  (`alter_body`, `break_link`, `violate_must`, `remove_record`,
  `drop_first_records`, `drop_last_records`, `cut_mid_record`,
  `not_a_container`), and `DAMAGE`, which states what the reader reports for
  each. A consumer no longer rewrites bytes at offsets copied from the
  specification, or goes without the case: `seq_gap` and `record_violation`
  could not be built through the writer at all.
- `PalaWriter.incident_candidate(..., return_seq=True)` returns
  `(seq, record_hash)`, like `tool_call` and the guards: an `OVERSIGHT_ACK`
  names its candidate by seq, and `writer.seq - 1` read afterwards can be
  another thread's record.
