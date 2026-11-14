# Changelog fragments

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

Each pull request that changes behaviour, the public surface, a format or
the documentation a user relies on adds **one file here** instead of
editing `CHANGELOG.md`: `<short-name>.md`, holding the entry under the
heading it belongs to (`### Security`, `### Added`, `### Changed`,
`### Fixed`, `### Documentation`), written the way it will read in the
release notes.

At release the fragments are gathered into the new `## [X.Y.Z]` section
of `CHANGELOG.md`, in heading order, and deleted in the same release
pull request. Until then `## [Unreleased]` in `CHANGELOG.md` stays empty.

The gathering is `scripts/assemble_changelog.py` (see `RELEASING.md`). It
knows the five headings above and no others, and wants nothing before the
first heading; the test suite parses every fragment the same way, so one it
cannot place fails on the pull request that adds it.

Why fragments: parallel pull requests never conflict over one file, and
the changelog is written while the change is fresh rather than
reconstructed at the end of a cycle.
