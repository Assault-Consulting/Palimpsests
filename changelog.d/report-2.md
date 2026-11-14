### Changed

- **The verification report is `pala-verification-report/2`.** The format
  id moves once, for everything that waited on it — `/1`'s schema is closed,
  so nothing could be added to it. What a consumer does about it:
  `docs/specs/report/MIGRATING-1-TO-2.md`.
  - **A fourth verdict, `empty`**, for a container with no records: nothing
    was checked, and nothing was found intact. It was `partial` before —
    and, checked against the head of an empty chain (32 zero bytes),
    `sound`. An empty file that misses a supplied anchor is still a
    `violation`. A consumer that gates treats `empty` as it treats
    `partial`: not a failure, not a pass.
  - **Violation codes**: `chain.violation_codes`, parallel to
    `chain.violations`, and `diagnosis.code`. The code is what to branch on.
  - **The manifest's identity**: the `manifest` block names the segments
    manifest a diagnosis was decided against — file name, status, the
    SHA-256 of the bytes read — or is `null`.
  - **The format is open**: a release may add a key; none is removed,
    renamed or given another meaning without a new id. The verdict set
    stays closed.

  `/1` is no longer written and is still read: its schema ships in the
  wheel beside the new one, `derive_verdict` answers a `/1` report by the
  rule it was written under, and `render_html` renders one.
- **`pala verify` gives the report's verdict for an empty file.** It says
  the container holds no records instead of `0 records, chain intact`,
  `--json` carries `"verdict": "empty"`, and the exit code is 2. With
  `--anchor` set to 32 zero bytes it exited 0, `verified`, before. The two
  commands now follow one rule in one order, and a test holds them together.
