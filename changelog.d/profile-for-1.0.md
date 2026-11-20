### Fixed

- A writer named the wrong profile revision in its own `WRITER_OPEN` record:
  `inference r8`, while it wrote r9's records. It now names r9, and a test
  holds that statement to the profile document and the packaged vectors.

### Documentation

- **Inference profile r9 is named as the revision Palimpsests 1.0
  implements** (profile §9.1). From this release r1–r9 are not edited in
  place — a correction is a new revision — their vectors keep their bytes,
  and later revisions only add. No open issue is carried into 1.0; what the
  profile cannot say is stated as a limit where it applies.
