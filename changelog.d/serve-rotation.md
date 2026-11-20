### Added

- **`palimpsests serve` can cut its chain into segments.** The writer has
  rotated since 0.11, but the serve had no way to ask for it: its chain was
  always the one file `serve.pala`, kept whole or lost whole.
  `PALIMPSESTS_AUDIT_ROTATE_BYTES`, `PALIMPSESTS_AUDIT_ROTATE_RECORDS` and
  `PALIMPSESTS_AUDIT_ROTATE_AGE` set the thresholds;
  `PALIMPSESTS_AUDIT_RETENTION` declares the retention of closed segments in
  the chain. Sizes take `KiB`, `MiB`, `GiB`; durations `s`, `m`, `h`, `d`. A
  value that cannot be read stops the serve. Nothing deletes a segment: that
  stays the operator's act.
- **`palimpsests pala segment-verify <manifest>`** verifies a segmented chain
  as one set — every segment on disk, every seam, and the segment still being
  written. Exit 0 complete, 2 consistent with segments missing, 1
  inconsistent, 3 not a manifest. `--json` gives
  `pala-segment-set-verification/1`. Before, the set could be verified only
  from Python (`verify_segment_set`).
- `GET /v1/pala/status`: `chain.segment` (the file being written) and
  `chain.rotation` (the policy in force, or `null`).

### Changed

- **A serve whose chain was ever cut continues at its live segment**, found
  from the manifest, whatever the rotation settings are now. It does not start
  if the manifest is there and that segment is not: starting again at
  `serve.pala`, a closed segment, would write a second history.
