### Fixed

- **The release tools' lock file could not be installed on the Python the
  release runs on.** An automated update had recompiled
  `.github/requirements/release.txt` for one interpreter and dropped the
  pins that carry a marker, `typing-extensions` among them; `pip install
  --require-hashes` then refused it on Python 3.12. The release workflow
  runs only on a tag, so nothing had run it. The file is recompiled, and a
  `release-rehearsal` job in `ci.yml` now runs the release workflow's build
  job — same Python, same lock file, same commands — on every change.
