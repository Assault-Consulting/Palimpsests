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

- `draft-sparysh-pala-audit-01.md` — posted 2026-10-02, expires
  2027-04-05; submitted from the `rendered-drafts` artifact
  of commit `4c7d2005`. Literal blocks restored, references corrected,
  related work on signed syslog (RFC 5848) and systemd journal Forward
  Secure Sealing, and a section relating PALA-1 to
  `draft-kuehlewind-audit-architecture`. Its "Changes from -00" appendix
  lists every change.

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
fences, a table is preceded by a blank line, and `check_render.py`
fails a source whose blocks do not survive or whose table syntax leaks
into the render.

A submitted revision is immutable — the IETF archive keeps every
revision permanently and a posted draft cannot be withdrawn. Changes to
a submitted document therefore land as a new revision, not as an edit
to the one already posted.

## Known defects in posted revisions

Posted text cannot be corrected in place; each defect below is fixed in
the next revision and, where a check can catch its class, by
`check_render.py`.

- **-00:** all seven literal blocks flattened into running text, the
  verification pseudocode included; reference list built from
  hand-written stubs (an empty co-author entry, missing months, wrong
  authors on RFC 9679). Rendered outside CI. Fixed in -01.
- **-01:** in the test-vector section, the table listing the twelve
  records of the vector chain is rendered as a paragraph with its `|`
  syntax visible: it follows a closing `~~~` with no blank line, so
  kramdown read it as paragraph text. The expected-results block and
  every hash are intact, and the vectors themselves are published
  separately. `check_render.py` now fails on leaked table syntax. Fix:
  a blank line, in the next revision.

## Queued for -02

Fixes and additions accumulated for the next revision; none is reason
enough on its own to post one.

- Test vectors: a blank line before the vector-chain table (the -01
  defect above).
- Implementation status: the Agent Action Capsule verification run
  against `draft-mih-scitt-agent-action-capsule-05`, once it is on the
  record; the reciprocal run, if it happens.
- Transparency services: the head-to-head consistency proof
  (`pala consistency`) as the way a later published head is shown to
  extend an earlier one.
- Before rendering: re-check every Internet-Draft description against
  the revision its reference now resolves to; references follow the
  latest revision, descriptions do not.
