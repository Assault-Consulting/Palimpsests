### Security

- **`verify_statement` accepts one encoding of a statement.** A COSE_Sign1
  signature does not cover how the envelope is written or the unprotected
  header at all, so one signed statement could be written tens of thousands
  of ways — a longer tag, a longer or indefinite array head, longer or
  chunked byte strings, an unprotected header that was not even a map — all
  verifying, all with different hashes. None was a forgery, but a reference
  by digest, a deduplication or a comparison of two copies depended on who
  last touched the bytes. Now the envelope, the protected header and the
  payload must be the RFC 8949 §4.2.1 deterministic encoding, and the
  unprotected header a definite-length map with no label twice; anything
  else is refused. What the unprotected header holds is not judged: a
  transparency service writes its receipts there.

### Added

- `StatementCheck.statement_id`: the SHA-256 of the statement with its
  unprotected header emptied. The hash of the bytes as built; unchanged when
  a receipt is attached. The name to refer to a statement by.
- Two refusal codes: `non_deterministic_encoding` and
  `unprotected_header_malformed` (21 in all).
- `docs/interop/scitt-statement-identity-vectors.json`: the id of each
  published statement, and seven statements that verify with something in
  the unprotected header and keep the same id.
- 19 cases in `scitt-statement-refusal-vectors.json` for the two codes
  (83 in all). The 64 cases published before keep their ids, bytes and codes.

### Changed

- **A payload that is not in the deterministic encoding is refused**
  (`non_deterministic_encoding`). Before, it was accepted and reported as
  `payload_encoding == "not deterministic"`. `payload_encoding` is now always
  `"deterministic"`; the field stays until 1.0.
- A statement whose protected header is not in the deterministic encoding
  is refused; before, it was accepted without a word.
- Every statement this package builds, and every published statement
  vector, verifies as before: they were already in the one encoding.

### Documentation

- `docs/INTEROP-SCITT.md` §11, "One statement, one encoding, one name": the
  rule, the id, what the id is not, and what it does not settle (which bytes
  a transparency service hashes into its log is that service's rule).
