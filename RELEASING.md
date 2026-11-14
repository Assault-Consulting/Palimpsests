# Releasing Palimpsests

How a release is cut, and — importantly for anyone verifying provenance —
how the published artifacts are **cryptographically signed** and how to
check that signature yourself.

## How releases are published

Releases are published to PyPI automatically by the `release.yml` GitHub
Actions workflow, triggered by pushing a version tag (`v*`). The workflow
has three jobs:

1. **build** — builds the sdist and wheel with `python -m build`, runs
   `twine check` on them, and generates a **CycloneDX SBOM** of the base
   install (see [Software Bill of Materials](#software-bill-of-materials-sbom)).
2. **publish** — uploads to PyPI using **PyPI Trusted Publishing (OIDC)**.
3. **release** — creates a **GitHub Release** for the tag and attaches the
   wheel, the sdist, and the SBOM as downloadable assets. This also makes
   the per-version release links in `CHANGELOG.md` resolve.

No API token or password is stored in the repository or its secrets. The
publish job authenticates to PyPI with a short-lived OpenID Connect token
issued by GitHub for that specific workflow run, scoped by the `pypi`
environment. This is why the workflow's default permissions are read-only
and each job additively grants only the one scope it needs — the publish
job `id-token: write`, the release job `contents: write`.

## Release signing (provenance / attestations)

**Every published artifact is signed**, and the signature is verifiable by
anyone — no key management on our side, and none required on yours.

Publishing through Trusted Publishing with
`pypa/gh-action-pypi-publish` produces **PEP 740 digital attestations**
backed by **Sigstore**. For each artifact (the wheel and the sdist), a
signed attestation bundle is generated at publish time and recorded in
Sigstore's public transparency log. The attestation binds:

- the artifact's SHA-256 digest (so it covers the exact file contents),
- the publishing workflow (`release.yml` in this repository) and the tag
  it ran from,
- the OIDC token issuer (`token.actions.githubusercontent.com`),

so a verifier can confirm that a given file was built and published by
this project's release workflow from a specific tagged commit, and has not
been altered since.

This is a **keyless** signing model: instead of a long-lived GPG/PGP key
that a maintainer must guard and users must fetch, the signature's trust
root is the OIDC identity of the release workflow plus Sigstore's public
log. There is no private key for us to leak and no public key for you to
download and trust out of band.

### How to verify a release

**On PyPI (no tools needed).** Open the file's page on PyPI — for example,
<https://pypi.org/project/palimpsests/#files> → *view details* on a file —
and scroll to the **Provenance** section. It shows the attestation
statement (in-toto `Statement/v1`, predicate `publish/v1`), the subject
digest, the Sigstore transparency-log entry, and the source repository,
tag, and publishing workflow. If the Provenance section is present and its
subject digest matches the file's SHA-256 hash (shown under *File hashes*
on the same page), the artifact is signed and verified.

**Locally, with the PyPI attestations tooling.** The published attestation
bundles can be fetched and verified against the artifact's digest using
Sigstore-aware tooling (for example, `pypi-attestations` / the `sigstore`
verification flow). The identity to expect is this repository's
`release.yml` workflow, issued by `token.actions.githubusercontent.com`.

For reference, the first signed release (v0.3.0) recorded a Sigstore
transparency entry and a `publish/v1` attestation binding the wheel's
SHA-256 to `release.yml` on `Assault-Consulting/Palimpsests` at
`refs/tags/v0.3.0` — visible in the Provenance section of that file on
PyPI.

## Software Bill of Materials (SBOM)

Each release carries a **CycloneDX SBOM** (`palimpsests.cdx.json`, spec
version 1.6, JSON), attached to its GitHub Release. It is generated during
the build job from a throwaway virtual environment holding only the freshly
built wheel and its resolved **base-install** dependency closure — so the
SBOM lists exactly the third-party packages a plain `pip install palimpsests`
pulls in (`httpx`, `pydantic`, `typer`, and their transitive dependencies),
and nothing from the build tooling.

The optional extras (`native`, `encryption`, `keyring`, `embeddings`) are
**not** in this SBOM by design: they are opt-in, and each declares its own
single dependency in `pyproject.toml`. The SBOM is generated with
`--output-reproducible`, so identical inputs produce a byte-identical file,
and `cyclonedx-bom` is version-pinned in the workflow for the same reason.

The SBOM records *what* is shipped; the Sigstore provenance above records
*that this project's workflow* shipped it. Attesting the SBOM itself —
binding it to the artifact digest via `actions/attest-sbom` — is a natural
next step and is not yet done.

## Scope of the signing (an honest boundary)

The provenance above covers the **PyPI distribution artifacts** (wheel and
sdist) — which is what "signed releases" means for a Python package, and
what a downstream installer actually consumes.

It does **not** cover the Git tags in the repository. Git tag signing
(`git tag -s`, GPG/SSH) is a separate mechanism that would additionally
let someone verify the tag object itself in Git history. It is not
currently used; the release artifacts on PyPI are signed via Sigstore
provenance instead, which is the relevant surface for release integrity.
If tag signing is added later, it will be documented here.

## SLSA Build Level

The provenance above places the release artifacts at **SLSA Build Level 2**
(v1.2 Build track): they are built on a **hosted** platform (GitHub Actions),
and that platform **generates and signs** provenance bound to this repository's
`release.yml` workflow and the tagged commit. Downstream verification checks
that signature (see [How to verify a release](#how-to-verify-a-release)).

This is **not** Build Level 3. L3 additionally requires that the material used
to sign the provenance be **inaccessible to the user-defined build steps**, so
that even a compromised build step cannot forge valid provenance. Here the build
and the OIDC signing context share one workflow job, so L3 is not claimed.
Reaching L3 would mean moving provenance generation into an **isolated builder**
(for example the `slsa-github-generator` reusable workflow), where signing
happens in a context the build cannot influence. That is future work.

As with any SLSA level, this describes the **build of this artifact** — it says
nothing about the artifact's dependencies (which carry their own provenance) or
the correctness of the code itself.

## Cutting a release (maintainer checklist)

Two people: whoever opens the release pull request does not merge it.

### Before the release pull request

1. **Everything for the release is on `main`, and CI on `main` is green —
   including the Windows jobs.** CI runs on pull requests and on pushes to
   `main` only, so a branch that is not a pull request has not been tested.
2. **A surface check from `main`**, on each platform a maintainer has, when
   anything that receives or records a client's reports has changed since the
   last one (`docs/SURFACE-CHECKER.md`):
   ```
   python scripts/check_surfaces.py --report results/
   python scripts/build_compatibility.py
   ```
   The report and the rebuilt `integrations/COMPATIBILITY.md` land in their
   own pull request. A RED or ERROR row stops the release. A SKIP is not a
   pass: the release notes say which surfaces were not checked.

### The release pull request (`release/x.y.z`)

3. **The version, in both places:**
   - `pyproject.toml` `version`
   - `src/palimpsests/__init__.py` `__version__`

   These two are separate declarations of the same fact, and they have
   drifted before: the 0.8.0 release shipped with the constant still reading
   `0.7.0`, which published exports naming the wrong verifier.
   `tests/test_smoke.py` now asserts they agree, so the drift fails CI — but
   the checklist names both files so the release path does not depend on a
   test catching a mistake that should not be made.
4. **The changelog.** Write the section's introduction — what the release is,
   and anything a user must do — to a file outside the repository, then:
   ```
   python scripts/assemble_changelog.py X.Y.Z YYYY-MM-DD ../intro.txt
   ```
   It gathers every fragment in `changelog.d/` under its heading, deletes the
   fragments and moves the link references at the foot of `CHANGELOG.md`. It
   refuses, and writes nothing, on a fragment it cannot place. Read the
   result: `## [Unreleased]` is empty, the new section sits above the previous
   one, and `git diff --stat` shows added lines only. **A change that carries
   no fragment is absent from the notes** — compare the fragments with
   `git log vPREVIOUS..main` before running it, and add what is missing.
5. **Status banners** (README, docs) for a minor release. A patch release
   leaves them alone.
6. **Check locally:**
   ```
   python -m pytest -q
   ruff check src tests scripts
   python scripts/check_links.py
   python -m pip install build twine
   python -m build && python -m twine check dist/*
   ```
   Build from a clean tree. The sdist follows the ignore rules, so an
   untracked directory they do not cover is swept into it: the sdist is a
   few megabytes, and one of tens of megabytes holds something it should not.
7. **Stage by path** — `git add pyproject.toml src/palimpsests/__init__.py
   CHANGELOG.md changelog.d` — not `git add -A`. `dist/` is not committed.

### After the merge

8. **Tag the release commit, by its hash** — not whatever `main` points at
   by then:
   ```
   git fetch origin
   git log --oneline -1 origin/main        # release: X.Y.Z (#NNN)
   git tag vX.Y.Z <that commit> -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
9. The `release.yml` workflow builds, generates the SBOM, publishes to PyPI
   via OIDC (Sigstore attestations generated automatically), and creates the
   GitHub Release with the wheel, sdist, and SBOM attached.
10. **Confirm what was published**, from outside the repository:
    - on PyPI both files show a **Provenance** section naming `release.yml`;
    - the GitHub Release exists with the `palimpsests.cdx.json` asset, and
      the CHANGELOG release link resolves;
    - a clean environment installs it and it checks itself:
      ```
      python -m venv /tmp/rel && /tmp/rel/bin/pip install "palimpsests[serve]==X.Y.Z"
      /tmp/rel/bin/python -c "import palimpsests; print(palimpsests.__version__)"
      /tmp/rel/bin/palimpsests pala selftest
      ```
      The last line of the self-test is
      `sound: this build reproduces the published expectations`.

### Patch releases

A patch release (`X.Y.Z`, `Z > 0`) is cut **from `main`**, by the same
steps, when everything on `main` since the last release is a fix or purely
additive: no format change, nothing removed, vectors byte-identical. Its
introduction says so in its first line.

There is no maintained release branch. If `main` already carries a change
that cannot ship in a patch, the choice is between releasing the next minor
version early and a branch cut from the previous tag — and the second has a
cost to know in advance: CI does not run on it until it is a pull request,
and nothing here has exercised that path.

### If something is wrong after the tag

**Do not delete the tag and do not publish again.** PyPI accepts a version
number once: a file removed from it cannot be replaced under the same
number, and a tag moved after publication no longer names what the
provenance was issued for. Stop, write down what happened, and decide
together: a bad release is yanked on PyPI and followed by the next patch
number.

### One-time setup: the trusted publisher

The `publish` job runs in the `pypi` environment, and the trusted publisher
registered on PyPI for this project should name that environment too. A
publisher registered without one accepts any job of `release.yml`, whether
or not it runs under the environment's protection rules. The Provenance
section of a published file shows which it is: beside the repository and the
workflow it names the environment, or none. For 0.14.1 it names none;
adding the environment on PyPI (*Manage project → Publishing*) is the
remaining step, and needs no change in this repository.
