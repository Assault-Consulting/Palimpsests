<!--
SPDX-FileCopyrightText: Assault Consulting
SPDX-License-Identifier: Apache-2.0
-->

# Locked tool requirements

The tools the workflows install — to lint, to build, to scan, to render
the specification, to cut a release — are installed from the files here
with `pip install --require-hashes`. Each `.txt` is compiled from the
`.in` beside it and names every package, direct and transitive, with the
SHA-256 of every file that may be installed for it.

| File | Used by | Holds |
|---|---|---|
| `lint.txt` | `ci.yml`, lint | ruff |
| `build.txt` | `ci.yml`, reproducible build and clean-room install | build |
| `vectors.txt` | `ci.yml`, vector regeneration | cryptography |
| `sast.txt` | `sast.yml` | bandit |
| `spec.txt` | `spec-build.yml` | xml2rfc |
| `fuzz.txt` | `fuzz.yml` | atheris |
| `release.txt` | `release.yml` | build, twine, cyclonedx-bom |

`release.txt` matters most: it is what builds the files that are signed
and published.

## To change one

Edit the `.in`, then compile it — the same command for every file:

```bash
cd .github/requirements
uv pip compile --generate-hashes --universal --python-version 3.11 \
    --no-header release.in -o release.txt
```

Dependabot proposes the updates; a changed `.txt` goes through review like
any other change.

## What is not locked, and why

- **What the tests run against** (`pip install -e ".[dev]"`). A new
  release of a dependency that breaks the package should fail here on the
  day it appears, not reach a user first.
- **The clean-room install**: it is the install a user does, a wheel and
  whatever `pip` resolves for it that day.
- **The consumer canary**: it installs the consumer's own requirements,
  which this repository does not choose.

A scanner that counts unpinned `pip install` lines counts these. They are
left as they are deliberately.
