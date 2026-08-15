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

There are no sources here yet; the directory carries the pipeline so
that when a publication cycle opens, the document lands into working
tooling instead of the tooling landing in a hurry.

Local build:

```bash
pip install xml2rfc
gem install kramdown-rfc
kdrfc -3 standards/draft-<name>.md   # produces .xml and .txt alongside
```

Conventions for future sources: one document per file, named exactly as
its publication name; the rendered `.xml`/`.txt` are build outputs and
are not committed; content changes follow the repository's PR-and-
non-author-review convention like every other document.
