### Added

- **COSE alg `-19` (Ed25519, RFC 9864) in SCITT statements.**
  `build_signed_statement(..., alg=ALG_ED25519)` writes it and
  `verify_statement` accepts it, for v2 and v3 alike. It is an addition to
  the set of algorithms, not a new construction: against the same statement
  under `-8` the payload and the `kid` are identical, and one signed byte of
  the protected header differs. Statements under `-7` and `-8` are unchanged,
  and the builder's default is still `-7`. A verifier from before 0.15
  refuses a `-19` statement as an unsupported algorithm. Vector:
  `docs/interop/scitt-statement-vector-alg19.json`. No independent party has
  yet reproduced a `-19` statement (`docs/INTEROP-SCITT.md` §9).

### Changed

- **A key that is not of the type the algorithm means is refused**
  (`key_type_mismatch`, a 19th refusal code). `-8` and `-19` mean Ed25519
  and `-7` means P-256. A statement signed with Ed448 under `-8` verified
  against the Ed448 key, while its `kid` was computed as if the key were
  Ed25519; it is refused now, and the builder raises `ValueError` rather
  than write one. A verification key of the wrong type, a private key or no
  key was reported as `signature_invalid`; it is `key_type_mismatch` now. A
  wrong key of the right type is still `signature_invalid`.
