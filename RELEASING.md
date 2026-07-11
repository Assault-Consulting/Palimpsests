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

## Cutting a release (maintainer checklist)

1. Land all release content on `main` via PR (CI green).
2. Update `pyproject.toml` `version`, `CHANGELOG.md`, and any status
   banners (README / docs) to the new version — via a `release/x.y.z` PR.
3. After merge, tag from `main`:
   ```
   git tag vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
4. The `release.yml` workflow builds, generates the SBOM, publishes to PyPI
   via OIDC (Sigstore attestations generated automatically), and creates the
   GitHub Release with the wheel, sdist, and SBOM attached.
5. Confirm on PyPI that the new files show a **Provenance** section, that the
   GitHub Release was created with the `palimpsests.cdx.json` asset, and that
   the CHANGELOG release link resolves.
