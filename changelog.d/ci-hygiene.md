### Security

- **The tools the workflows install are hash-locked.** `build`, `twine` and
  `cyclonedx-bom` in the release workflow — the tools that produce the
  published files — and ruff, bandit, xml2rfc, atheris and the vector job's
  `cryptography` are installed with `pip install --require-hashes` from
  `.github/requirements/`. Before, they were installed at whatever version
  was newest that day. What the tests run against stays unlocked, on
  purpose; `.github/requirements/README.md` says why.
- **CodeQL analyses every pull request and every push to `main`**, for the
  Python source and for the workflows themselves, beside Bandit.

### Documentation

- The verification kit's README states the count of independent
  implementations on record: five, three of them from outside the project.
