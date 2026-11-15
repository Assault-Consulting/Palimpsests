### Changed

- **Exit code 1 is named `VIOLATION`, not `TAMPERED`.** The number is
  unchanged. The check was made and did not hold; a file cut short by a
  crash, a text file that was never a log and a log someone altered all exit
  1, and nothing in the tool can tell them apart — so the name no longer
  picks one. The verdict was already `violation` and the diagnoses already
  state consistency, never intent; the exit code's name and `--help` now do
  too. `palimpsests audit verify` prints `VIOLATION: …` where it printed
  `TAMPERED: …` — the one change to output; anything that matches that word
  should read the exit code instead. `EXIT_TAMPERED` stays importable as an
  alias of `EXIT_VIOLATION`.

### Added

- **A consumer canary.** `.github/workflows/consumer-canary.yml` runs
  Auditor's own test suite against every commit and pull request of this
  package, and weekly; `scripts/consumer_canary.py` compares what fails with
  a ledger of breaks made on purpose, each with its reason, and fails the
  check on any failure the ledger does not list. It refuses to report at all
  if the suite ran against another copy of the package or ran no tests. A
  signal, not a required check.
