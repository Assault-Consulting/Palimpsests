### Added

- **Refusal vectors for SCITT statements:**
  `docs/interop/scitt-statement-refusal-vectors.json`. A refused
  statement for every one of the 19 refusal codes, 61 cases in all, each
  a published statement with one change, with the code `verify_statement`
  refuses it with, the order of the checks, the keys as JWK and the chain
  the root cases are verified against. Another verifier can compare its
  refusals with these without running this package. The file regenerates
  byte for byte from the three published statement vectors, which are
  unchanged (`docs/INTEROP-SCITT.md` §10).
