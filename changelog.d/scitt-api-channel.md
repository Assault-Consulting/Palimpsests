### Added

- **The SCITT statement API is a public channel** (channel 8 of
  `docs/INTEGRATION-SURFACE.md`), with a contract and a contract test:
  `build_signed_statement`, `head_payload`, `verify_statement`,
  `StatementCheck`. It needs the `[scitt]` extra; a key is a `cryptography`
  key object the caller loads; it verifies statements and never receipts.
- **`StatementRefused`, with a `code`.** Every statement `verify_statement`
  does not accept raises it — 18 codes, listed in `STATEMENT_REFUSAL_CODES`
  and in the surface document. It is a `ValueError`, so `except ValueError`
  keeps working. The code names the check that failed, never a cause.

### Fixed

- **`verify_statement` raised four other kinds of exception on malformed input**
  where it promised `ValueError`: `CBORDecodeEOF` and `CBORDecodeError` on
  bytes that are not CBOR, `TypeError` and `AttributeError` on a message of
  the wrong shape, and `TypeError` on a signed payload or protected header
  whose keys mix integers and text. All are `StatementRefused` now. A run of
  6,000 single-byte mutations of valid v2 and v3 statements is in the suite:
  the verifier answers every one, accepted or refused.

### Changed

- **A statement followed by further bytes is refused** (`trailing_bytes`).
  It verified: the decoder read one item and ignored the rest, so an
  artifact that was a statement plus something else passed as the statement.
  The same holds inside the signature: a protected header or a payload that
  is a CBOR map followed by more bytes is refused, where a payload of that
  kind was reported as `not deterministic` and accepted. What follows a map
  can be a second map, and a reader that takes the last item reads other
  values — the reason a repeated key is refused. The published statements
  and vectors are unaffected.
- **`check_statement_against_head` is deprecated**; use `verify_statement`,
  whose result carries `.payload`. It emits a `DeprecationWarning` and goes
  at 1.0.
