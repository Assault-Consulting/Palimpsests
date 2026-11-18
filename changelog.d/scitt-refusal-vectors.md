### Added

- **Refusal vectors for SCITT statements:**
  `docs/interop/scitt-statement-refusal-vectors.json`. A refused
  statement for every one of the 19 refusal codes, 64 cases in all: sixty
  are a published statement with one change, four are inputs that are not
  a statement. Each carries the code `verify_statement` refuses it with;
  the file states the order of the checks, the keys as JWK and the record
  hashes of the chain the root cases are verified against. Another verifier can compare its
  refusals with these without running this package. The file regenerates
  byte for byte from the three published statement vectors, which are
  unchanged (`docs/INTEROP-SCITT.md` §10).
