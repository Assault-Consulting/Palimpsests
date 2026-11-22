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

### Comparing with a published release

The files on the GitHub Release and on PyPI are the same bytes — one build
feeds both. Whether **your** rebuild has the same hash as theirs depends on
one more thing than the source: the compression library your Python was
built with. The wheel is a zip and the sdist a gzip, and two builds of
zlib may deflate the same input into different bytes.

Measured on 0.15.0 (2026-11-22): a rebuild from a clean clone of the tag,
with the release's own locked tools, on a different Python 3.12 build than
the release runner's, gave archives with **different SHA-256 and identical
contents** — the same 81 members in the wheel and 784 in the sdist, in the
same order, each with the same content hash, timestamp and mode. Only the
compressed sizes differed.

So compare in two steps. The archive hashes first: if they match, you are
done. If they do not, compare what is inside:

```bash
python scripts/compare_dist.py dist/<file> <the published file>
```

It prints `same bytes`, or `same contents (N members); the archives differ
in compression only`, or `DIFFERENT CONTENTS` with the members that differ,
and exits 1 in the last case.

A difference in contents is a finding; a difference in compression alone
is not. The published files' own hashes are what the release's provenance
(`RELEASING.md`) signs.

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
