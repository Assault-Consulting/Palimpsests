### Added

- `scripts/compare_dist.py`: compares a rebuilt wheel or sdist with a
  published one by contents — member names in order, each member's SHA-256,
  timestamp and mode — and says whether a difference is in the contents or
  in the compression alone.

### Documentation

- **`docs/REPRODUCIBLE-BUILD.md` states where byte-for-byte ends.** A
  rebuild of 0.15.0 from a clean clone of the tag, on a different Python
  3.12 build than the release runner's, gave archives with different
  SHA-256 and identical contents: the compression library decides the
  compressed bytes. The document said a rebuild matches a published file
  byte for byte; it now says to compare hashes first and contents second.
- `docs/compliance/EU-AI-ACT-MAPPING.md`: three rows that still read
  `Shipped (main)` are `Shipped (v0.11)`, and prefix-consistency proofs,
  listed as planned, are `Shipped (v0.12)` — 25 of 27 rows. Checked against
  the published 0.15.0 package.
- The runbook pages are checked against 0.15.0 from PyPI and link to its
  tag. The page on hooks that report nothing gains the refusals the log
  itself keeps since 0.15; the OpenCode page shows the configuration as
  printed with a key set.
- A note, "AI on small devices, and the log they keep": what is hard about
  keeping a record on a device, what PALA-1 does about each part, and what
  is not built.
- `RELEASING.md` records what the first provenance bundle on a GitHub
  Release holds (0.15.0).
