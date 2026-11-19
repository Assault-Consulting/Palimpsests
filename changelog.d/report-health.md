### Added

- **An advisory health section in the report.** `build_report(health=True)`
  and `pala report --health` fill a new `health` key with a fixed-size
  summary of the health channel: boots, the widest gap between anchors,
  wall-clock steps and regressions, drift, open spans. Each group names the
  clock it is measured on. No figure is a threshold and `derive_verdict`
  does not read the section. The HTML page shows it when it is there.
  `health_summary(reader)` returns the same section on its own.

### Changed

- **The report has one more top-level key, `health`,** `null` unless it was
  asked for. `pala-verification-report/2` is open to added keys; a consumer
  that compares the exact set of top-level keys sees the new one.
