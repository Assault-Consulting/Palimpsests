### Documentation

- **`RELEASING.md` describes the release as it is done.** The checklist now
  covers what the last three releases learned outside it: the surface check
  before a release, gathering the changelog fragments, staging by path,
  tagging the release commit by its hash, checking the published package from
  a clean environment, patch releases, and what not to do when something is
  wrong after the tag. The fragments are gathered by
  `scripts/assemble_changelog.py`, which lived outside the repository until
  now; it refuses, and writes nothing, on a fragment it cannot place, and the
  test suite runs the same parse on every change.
