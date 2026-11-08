### Fixed

- **Surface checker: a report is never overwritten.** The report's file name
  was the date alone, so a second run the same day — one probe, or another
  machine — replaced the first. A second report the same day is now
  `surfaces-DATE-2.md`, then `-3`; `scripts/build_compatibility.py` reads
  them and lists the later run first.
- **The report's `Machine:` line names the commit that was run.** An
  editable install of unreleased `main` reports the last released version
  in its metadata, so the 2026-11-07 report reads "palimpsests 0.13.1" for a
  run of `main`; the line now adds `(git <sha>)` in a checkout.
