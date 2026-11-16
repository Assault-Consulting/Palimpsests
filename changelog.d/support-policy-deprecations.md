### Changed

- **`palimpsests.cli.EXIT_TAMPERED` emits a `DeprecationWarning`.** It was
  kept as a silent alias of `EXIT_VIOLATION` when the name changed; it now
  says it goes in 1.0. The value is the same, 1.

### Documentation

- **A support policy** in `SECURITY.md`: which versions receive fixes now
  and from 1.0, target times for acknowledging, assessing and fixing a
  reported vulnerability, what counts as critical for an audit log, when a
  report is disclosed, and that a critical problem reported by someone
  running Palimpsests comes before planned work.
- **A deprecations table** in `docs/INTEGRATION-SURFACE.md`: each name on
  its way out, since when, until when and what to use instead. A test
  holds the table to the code in both directions. Reading what earlier
  releases wrote is stated as not deprecated.
