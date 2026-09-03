<!--
SPDX-FileCopyrightText: 2026 Assault Consulting
SPDX-License-Identifier: Apache-2.0
-->

# standards/

Publication tooling for specification documents: sources written in
kramdown-rfc markdown are rendered to RFCXML v3 and plain text by
`kdrfc` (with `xml2rfc` doing the final rendering). The CI job
(`.github/workflows/spec-build.yml`) builds every `draft-*.md` in this
directory and fails on a source that does not render — the same
gate-not-taste posture as the rest of the repo's CI.

## Sources

- `draft-sparysh-pala-audit-00.md` — *PALA-1: A Tamper-Evident Audit
  Record Format for Constrained and Disconnected Deployments*. Submitted
  to the IETF as an Internet-Draft (individual submission) on
  2026-09-02, posted 2026-09-03, expires 2027-03-07.
  <https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/>

  The document presents the frozen PALA-1 v1.0 wire format as it is; it
  does not revise it. Nothing in `docs/specs/pala-1/` changes because a
  publication document exists, and the test vectors remain the
  normative artefact for interoperability.

Local build:

```bash
pip install xml2rfc
gem install kramdown-rfc
kdrfc -3 standards/draft-<name>.md   # produces .xml and .txt alongside
```

Conventions for sources here: one document per file, named exactly as
its publication name; the rendered `.xml`/`.txt` are build outputs and
are not committed; content changes follow the repository's PR-and-
non-author-review convention like every other document.

A submitted revision is immutable — the IETF archive keeps every
revision permanently and a posted draft cannot be withdrawn. Changes to
a submitted document therefore land as a new revision, not as an edit
to the one already posted.
