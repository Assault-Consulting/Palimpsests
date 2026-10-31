### Added

- **`palimpsests.audit.segment_set.verify_segment_set(manifest_path)`** (U18):
  a segmented chain verified as one set against its `pala-segments/1`
  manifest — each segment from its declared start, its bodies, its head and
  seq range against the manifest, every seam between entries, and a rotating
  writer's live segment found by its link. Two answers kept apart:
  `consistent` (everything present verifies and agrees with the manifest) and
  `complete` (also nothing missing, from a GENESIS) — a segment deleted under
  retention makes a set incomplete, never inconsistent. The manifest is named
  by the SHA-256 of the bytes read.
