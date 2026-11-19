### Fixed

- **Ten modules read header fields at offsets written out beside the code**
  — `unpack_from("<Q", hb, 12)`, `hb[20:36]` — a second statement of the
  header's layout that the codec's contract test did not reach. Each now
  takes the field from the codec's field map by its name
  (`palimpsests.audit._header_fields`): the health channel, the export, the
  proofs, the checkpoints, the segments and their set, live reading, the
  writer's resume scan and the bundle. A test scans those modules for a
  literal offset. No behaviour changes: bundles and reports are
  byte-identical, and the timings on a million-record chain are the same.
