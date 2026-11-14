### Fixed

- **The evidence bundle says when a log does not hold together.**
  `verification.json` in a `pala-bundle/1` archive carried the header
  chain's answer and nothing about bodies, so a body altered after writing
  was bundled under `chain_ok: true` with no mark, and `pala bundle` printed
  `chain verdict inside: sound`. And a source cut in the middle of a record
  made the assembler fail and write nothing, where its own documentation
  promised that a damaged chain bundles too. Now `verification.json` carries
  `container` (the walk and the check of every body against its header's
  digest — the same object as the report's section), `violation_codes`, and
  **`consistent`**, the one answer to read; a torn source bundles its whole
  records and says where the walk stopped. `pala verify` was right
  throughout. **A bundle made by 0.10 to 0.14 has `chain_ok` covering the
  headers only: run `pala verify` on its `records.pala`.**

### Documentation

- **`pala-bundle/1` has a specification**, `docs/specs/bundle/pala-bundle-1.md`:
  the archive, each member's keys, what a damaged source produces, and how
  to re-verify a bundle without the assembler. The format is declared open —
  keys are added, never removed, renamed or given another meaning. Every key
  a 0.10 bundle had is kept and unchanged; the three members other than
  `verification.json` are byte-identical to what 0.14.1 writes.
