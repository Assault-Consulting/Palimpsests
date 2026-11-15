### Added

- **`assemble_bundle(reader=…)`.** A consumer that holds the chain open
  hands the reader over and the file is not opened again, as with
  `build_report`. The bundle is byte-identical either way; `reader` and
  `anchor_source` together raise `ValueError`.
- **`__all__` on the public channels that had none**: `pala.proofs`,
  `pala.bundle`, `timehealth`, `bootstats`, `pala.selftest` and
  `pala.vectors`. Their result types and format ids are declared with the
  functions (`InclusionProof`, `BundleResult`, `BUNDLE_FORMAT`,
  `CONSISTENCY_FORMAT`, …). The contract test now holds every channel
  module's `__all__` to the surface document.

### Changed

- **A report and a bundle hold no path of the machine that made them.**
  Read against an anchor file, the report's `anchor.source_detail` and the
  bundle's `verification.json` carried the file's full path — a directory
  layout and often a user name, in the two documents made to be sent. They
  carry the file's name now, as the report already did for a segments
  manifest; an attempt's `error` that quoted the path names the file too. A
  bundle is therefore the same bytes on any machine. `Verification.anchor`
  and `anchor_attempts` of the reader are unchanged and still carry the
  path, locally.

### Fixed

- **`assemble_bundle` read the source file whole into memory and then
  mapped it as well.** It reads through the reader's mapping now.
- The bundle read four header fields at offsets written out in its own
  module. It takes them from the codec's field map (`HEADER_FIELDS`), like
  the rest of the package.
