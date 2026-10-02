<!--
SPDX-FileCopyrightText: 2026 Assault Consulting
SPDX-License-Identifier: Apache-2.0
-->

# standards/

Publication tooling for specification documents: sources written in
kramdown-rfc markdown are rendered to RFCXML v3 and plain text by
`kdrfc` (with `xml2rfc` doing the final rendering). The CI job
(`.github/workflows/spec-build.yml`) builds every `draft-*.md` in this
directory, checks that every literal block survives into the rendered
text verbatim (`check_render.py`), and fails on either — the same
gate-not-taste posture as the rest of the repo's CI. The rendered
`.xml` and `.txt` are uploaded as the `rendered-drafts` workflow
artifact.

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

- `draft-sparysh-pala-audit-01.md` — the next revision, in preparation:
  literal blocks restored, references corrected, related work on signed
  syslog (RFC 5848) and systemd journal Forward Secure Sealing, and a
  section relating PALA-1 to `draft-kuehlewind-audit-architecture`.
  Its "Changes from -00" appendix lists every change.

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

**Submit what CI rendered, nothing else.** The file uploaded to the
datatracker is the `.xml` from the `rendered-drafts` artifact of the
commit being submitted. The -00 upload was rendered outside CI, by a
kramdown-rfc version that reads a line of three backticks as an inline
code span rather than a fence: seven literal blocks, including the
verification pseudocode, were flattened into running text, and its
reference list was built from hand-written stubs. Sources use `~~~`
fences, and `check_render.py` fails a source whose blocks do not
survive.

A submitted revision is immutable — the IETF archive keeps every
revision permanently and a posted draft cannot be withdrawn. Changes to
a submitted document therefore land as a new revision, not as an edit
to the one already posted.
