### Added

- **An `empty_container` diagnosis** (U26) for a container with no records.
  The verdict is unchanged — §7.1 holds vacuously on zero records — but the
  diagnosis says the check passed because there was nothing to check, not
  because a log was found intact. Carried by `pala-verification-report/1`
  as any other pattern; the report still validates against its schema.

### Documentation

- **Clarification C-8**: a container with no records — the vacuous answer
  stands, and what it means is stated. Whether an empty container should
  carry a stronger verdict belongs to an implementation's report format,
  not to the frozen core.
