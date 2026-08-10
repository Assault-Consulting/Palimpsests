# Reproducible build

Palimpsests' distribution artifacts — the sdist (`.tar.gz`) and the wheel
(`.whl`) — are **reproducible**: building the same commit produces the same
bytes, so any party can independently rebuild a release and confirm, by hash,
that it was built from exactly this source with nothing added.

This is the OpenSSF Gold `build_reproducible` criterion, and it pairs with the
project's signing story (Sigstore keyless signatures, PEP 740 attestations,
SLSA Build L2 provenance): signatures prove *who* built an artifact,
reproducibility proves *what* it was built from.

## What makes it deterministic

- **Backend.** The build uses `hatchling` via PEP 517 (`python -m build`),
  which writes archive members in a fixed order and does not stamp wall-clock
  build time into the output.
- **`SOURCE_DATE_EPOCH`.** Timestamps in the wheel and sdist are pinned to the
  **commit date** of the checked-out commit, not the moment of building. This
  makes the output independent of *when* you build and independent of the
  backend's default epoch, so it stays stable across `hatchling` versions.
- **Fixed locale, timezone, and umask.** `LC_ALL=C.UTF-8`, `TZ=UTC`, and
  `umask 0022` remove environment-dependent sorting and file-mode variation.

## Reproduce a build yourself

From a clean checkout of the commit (or tag) you want to verify:

```bash
python -m pip install build

export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export LC_ALL=C.UTF-8
export TZ=UTC
umask 0022

python -m build
sha256sum dist/*
```

Building a second time into a different directory yields identical hashes.
For a release, compare those hashes against the artifacts attached to the
corresponding GitHub Release / published to PyPI: they match byte-for-byte.

## How CI enforces it

The `reproducible-build` job in `.github/workflows/ci.yml` runs
`scripts/check_reproducible_build.sh` on every push and pull request. The
script builds the sdist and wheel **twice** and fails if any artifact differs
between the two builds — so a change that introduces non-determinism (a leaked
timestamp, an unsorted glob, an absolute path) cannot merge silently.

The release workflow (`.github/workflows/release.yml`) sets the same
`SOURCE_DATE_EPOCH` / locale / umask when building the artifacts it publishes,
so the released files are the reproducible ones.

## Scope

Reproducibility here covers the **Python distribution artifacts** the project
publishes. The optional `[native]` path links against a separately installed
`llama.cpp` build, which is outside these artifacts and outside this
guarantee; it is documented under the `[native]` extra and validated on
hardware, not shipped in the wheel.
