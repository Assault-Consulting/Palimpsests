### Added

- **One place to import the reading surface from** (U19): `palimpsests.audit.reader`
  now also exports `VerifyResult`, `Header`, `Advisory`, `AdvisoryItem`,
  `boot_statistics` and `step_catalog` with their result types, the core
  numbers (`RT_*`, `TIER_*`, `TIME_*`, `FORMAT_VERSION`), the inference
  profile's (`KIND_*`, `OUTCOME_*`, `SOURCE_*`, `DISP_*`), and the sentinels
  `NO_SPAN` and `NO_PREDECESSOR`. Every name keeps its home module too.
- **`palimpsests.audit.profiles.inference`** — the inference profile's
  allocations, which used to live in the writer; the writer re-exports all
  of them, so existing imports keep working.
- **A contract test for the reading surface** (U20,
  `tests/test_consumer_surface.py`): the exported names, the frozen numbers
  of the core and the profile, the result types' fields, the reader's
  methods, and the diagnosis, advisory and name vocabularies checked
  against `docs/INTEGRATION-SURFACE.md`.
