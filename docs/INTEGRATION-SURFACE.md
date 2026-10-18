# The integration surface

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

The documented contract between this package and any consumer that
embeds its audit stack — first among them
[Auditor](https://github.com/Assault-Consulting/Auditor), whose desktop
shell drives everything below through a Python sidecar. If a behaviour
matters to a consumer and is not written here or in the linked specs,
it is not promised.

## The seven channels

| # | Channel | Surface | Stability |
|---|---------|---------|-----------|
| 1 | Reading | `palimpsests.audit.reader.AuditReader` (`open`, `verify`, `records`, `spans`, `boots`, `origin_at`, `unloaded_at`, `acknowledged_candidates`, `shredded_targets`; sparse access `record_count`, `record_at`, `record_by_seq`, `header_at` since 0.13; `Verification.manifest` since 0.13) | public (since 0.8) |
| 2 | Report | `palimpsests.audit.report.build_report`, `derive_verdict`, format `pala-verification-report/1` | public (since 0.10) |
| 3 | Proofs | `palimpsests.audit.pala.proofs.inclusion_proof`, `range_proofs` | public (since 0.10) |
| 4 | Bundle | `palimpsests.audit.pala.bundle.assemble_bundle`, format `pala-bundle/1` | public (since 0.10) |
| 5 | Health | `palimpsests.audit.timehealth`, `palimpsests.audit.bootstats` | public (since 0.10) |
| 6 | Conformance | `palimpsests.audit.pala.vectors.load`, `palimpsests.audit.pala.selftest.run_selftest`, `pala selftest` | public (since 0.10) |
| 7 | Distribution | PyPI wheel; vectors and the report schema ship inside it | — |

**Stability class "public":** breaking changes only with a minor version
bump and a CHANGELOG entry naming the break; additive changes (new
fields, new functions) may land in any release. The two named formats
(`pala-verification-report/1`, `pala-bundle/1`) change only by format-id
bump. Writer APIs remain **experimental** until 1.0, as the README
states — no consumer contract covers them.

## The report contract

- The JSON shape's machine truth is the schema shipped in the wheel at
  `palimpsests/audit/_schemas/pala-verification-report-1.schema.json`
  (source: `docs/specs/report/`). A rendering validates against it; the
  package's own CI does.
- **The verdict is produced only by `derive_verdict`.** A renderer reads
  the report's `verdict` field or calls the function; it never
  re-derives the rule. This is what keeps two renderings from disagreeing
  in the one word that matters.
- **Normalization rule for golden tests:** `checked_at` (by design) and
  the version-carrying fields `verifier.tool` / `verifier.package` are
  normalized away before comparing reports. Everything else is
  deterministic for the same inputs.
- `anchor.observed_at_ns` is `null` when the anchor source does not
  carry an observation time — today's file/manual sources do not.
- Wording discipline is part of the contract: a report is an attestation
  of a check, never "compliant", "certified", or "valid log".

## Reading a live file

A writer appends unbuffered, but a record write is not guaranteed
atomic against a concurrent reader: a file read mid-write may end in a
partial record, which parses as a malformed container (§2.4).

**Rule:** a consumer verifying a file that may be under active writing
copies it first and reads the copy (`copy-then-read`). A malformed
*tail* on a live file is "a record in flight", not evidence of
tampering; the same defect in a copied, quiescent file is a real
finding. Auditor's UI follows this rule.

## Files a verdict reads

A verdict is a verdict on the container's bytes — with one exception since
0.13. When a segment's first record declares a continuation (inference
profile r6), the diagnosis (`declared_continuation` or
`continuation_contradicts_manifest`) is decided against the
`<stem>.segments.json` manifest beside the file. `Verification.manifest`
names that file, the status it decided (`matches` / `contradicts` /
`declared_only`), and the SHA-256 of the bytes read — one read, hashed and
parsed from the same buffer, so the digest describes the manifest the
diagnosis rests on. `None` means the verdict read no second file.

A consumer that identifies what it verified by digest records both digests,
and treats a change to either file as a change of subject. The report
(`pala-verification-report/1`) does not carry the manifest's identity yet;
adding it is a format question, and the format changes only by format-id
bump.

## Size envelope

The reader holds all record headers in memory and `build_report` /
`assemble_bundle` read the source file fully (the bundle twice). This
is comfortable to the order of ~10^6 records / hundreds of MB;
multi-GB retention archives (see `docs/RETENTION.md` for the storage
math) should be segmented before interactive use. A streaming reader
is backlog, not promise.

A consumer that needs one record, a page of records or a count does not
have to pay for the whole decode: `record_count`, `record_at(index)`,
`record_by_seq(seq)` and `header_at(index)` read the index the walk built
at open and decode only the record asked for. `records()` still
materialises every record before its first item; use it for a full walk,
not for a window. `shredded_targets()` and the origin methods
(`origin_at`, `unloaded_at`, `origin_state_at`) do not materialise the
chain either: each builds what it needs once per reader from the headers
and the few bodies that matter — the `KEY_SHRED` records; the one record
that set the origin asked about — and answers from that. Measured at
1,000,002 records / 245 MB: the first origin question 2.7 s, each after it
under a millisecond, `shredded_targets()` 0.6 s, against 20.6 s and
1.99 GB peak RSS for the full decode they used to pay.

Measured at that boundary, not just estimated: a synthetic
1,000,004-record / 224 MB chain, `open()` plus `verify()` plus
`build_report()` together, was killed by the OS on a 3.9 GB machine —
`_referential_advisories()` needs every record's kind to resolve r2
references, which needs every body decoded, and `_decoded_records()`
keeps the full decoded chain in memory once that happens. A
100,000-record / 22.4 MB chain, well inside the stated envelope, ran
the same flow in 4.9 s at 460 MB peak RSS — roughly 20× the file's own
size. "Comfortable" holds well short of the 10^6 mark; nearer it, the
margin is thinner than the file size alone suggests, and depends on
how much RAM the caller's machine actually has to spare.

One redundant cost is now avoidable: `build_report()` previously
always opened its own `AuditReader`, even when the caller already had
one open — decoding the same chain a second time for no reason but
that the function had no way to be handed the first reader. It now
accepts one (`reader=`); a caller holding a reader that has already
paid this cost no longer pays it again. This does not change the
underlying decode's own cost or memory shape — that is the streaming
reader work already named above as backlog.

## Conformance for embedders

- Run `pala selftest` (or `run_selftest()`) at sidecar startup and
  surface an UNSOUND result to the user — the packaged vectors make
  this an offline check.
- The companion vector set's `semantics` block covers a subset of its
  records by design (the block grows additively); rendering-conformance
  tests should assert against the seqs present, not assume totality.
