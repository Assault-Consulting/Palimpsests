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
| 1 | Reading | `palimpsests.audit.reader.AuditReader` (`open`, `verify`, `records`, `spans`, `boots`, `origin_at`, `unloaded_at`, `acknowledged_candidates`, `shredded_targets`; sparse access `record_count`, `record_at`, `record_by_seq`, `header_at` since 0.13; `Verification.manifest` since 0.13; `container_check()`, `record_fields_at()` since 0.14; for a byte view `record_bytes_at()`, `header_tlv_spans_at()`, `body_tlv_spans_at()` since 0.14, and the fixed header's layout `HEADER_FIELDS` / `HeaderField` / `FIXED_HEADER_LEN` since 0.14.1); a segmented chain as one set: `palimpsests.audit.segment_set.verify_segment_set` (since 0.14) | public (since 0.8) |
| 2 | Report and export | `palimpsests.audit.report.build_report`, `derive_verdict`, format `pala-verification-report/2` (since 0.15; `/1` in 0.10 – 0.14, still read); the HTML page `palimpsests.audit.report_html.render_html` (since 0.14 — a rendering of the report's `.data`, its markup not a format); the record export `palimpsests.audit.export.export_jsonl`, format `pala-jsonl/1` (since 0.14.1) | public (since 0.10) |
| 3 | Proofs | `palimpsests.audit.pala.proofs.inclusion_proof`, `range_proofs`; prefix consistency `chain_root`, `consistency_proof`, `ConsistencyProof`, format `pala-consistency-proof/1` (since 0.12) | public (since 0.10) |
| 4 | Bundle | `palimpsests.audit.pala.bundle.assemble_bundle`, format `pala-bundle/1` | public (since 0.10) |
| 5 | Health | `palimpsests.audit.timehealth`, `palimpsests.audit.bootstats` | public (since 0.10) |
| 6 | Conformance | `palimpsests.audit.pala.vectors.load`, `palimpsests.audit.pala.selftest.run_selftest`, `pala selftest` | public (since 0.10) |
| 7 | Distribution | PyPI wheel; vectors and the report schema ship inside it | — |

**Stability class "public":** breaking changes only with a minor version
bump and a CHANGELOG entry naming the break; additive changes (new
fields, new functions) may land in any release. Two named formats
(`pala-bundle/1`, `pala-consistency-proof/1`) change only by format-id
bump. Two are open — `pala-verification-report/2` and `pala-jsonl/1`: a
release may add a key, and none is removed, renamed or given another
meaning without a format-id bump, so a consumer ignores a key it does not
know. The report's verdict set is closed all the same: a new verdict is a
new format id.

**Since 0.13, what a value *means* is held to the 1.0 standard already**
— the rules a consumer needs to rely on a verdict it renders:

- **`None` has one meaning per field, and that meaning is frozen.**
  Where a field could be `None` for two reasons, the contract names the
  pair that tells them apart: on a decoded record, `kind is None` means
  the record carries no kind (not an EVENT/SAFETY body, no body, or an
  encrypted one), and `kind is not None and kind_name is None` means a
  kind this build does not know. `complete_to_anchor is None` means not
  checked; `Verification.manifest is None` means no second file was read.
- **Numbers never change meaning; names may grow.** A record type, kind,
  tier, time-trust, outcome, source or disposition number is fixed by the
  specification. A name table may gain entries, so a consumer handles a
  `None` name for a value it does not know.
- **Vocabularies are open.** A release may add a diagnosis pattern, an
  advisory code or a manifest status; none is ever renamed or
  repurposed. A consumer renders an unknown one with the verifier's own
  sentence and says it has no guidance for it — never hides it, never
  maps it to a known one. The current members are listed below.
- **Machine fields are contract; sentences are not.** `pattern`, `code`,
  `at_seq` and the manifest `status` are what a consumer branches on.
  `narrative`, `detail`, `expected`, `anchor_reason` and the reason of a
  chain violation are the verifier's words: carried verbatim, never
  parsed, free to improve in any release, always English. Since 0.14 a
  chain violation also carries a code — `VerifyResult.violation_codes`,
  parallel to `violations`, and `Diagnosis.code` for `record_violation` —
  and the code is what to branch on. The verification report carries both
  since format `/2`: `chain.violation_codes`, parallel to
  `chain.violations`, and `diagnosis.code`.

The structural rules — one place to import from, no removal or rename
within a major, deprecation over one minor — take effect at 1.0. Until
then the class above holds for symbols, with every break named in the
CHANGELOG. The plan towards both is in
[CONSUMER-SURFACE.md](CONSUMER-SURFACE.md).

**Not covered by any channel:** the writer APIs (`PalaWriter`, anchor
stores, rotation) remain **experimental** until 1.0, as the README states;
they get a contract of their own before then. **SCITT statement
construction v3** (the bytes of a signed statement) is independently
reproduced — bridge run B3, `docs/specs/pala-1/INDEPENDENT-VERIFICATION.md`
§7 — and changes only by content-type bump, as v2 does. The Python functions of the
bridge (`palimpsests.audit.pala.scitt` — `verify_statement`,
`StatementCheck` and its `root_status` values) stay **experimental** until
they belong to a channel; B3 verified the construction, not that API.

## Vocabularies (open)

| Vocabulary | Members as of 0.13 |
|---|---|
| Diagnosis `pattern` | `empty_container`, `not_a_container`, `truncated_tail`, `prefix_absent`, `declared_continuation`, `continuation_contradicts_manifest`, `seq_gap`, `chain_break`, `record_violation`, `unanchored_tail`, `replaced_or_rolled_back` |
| Advisory `code` | `anchor_never_written`, `mid_boot_time_trust_change`, `mono_regression_in_boot`, `wall_regression_in_boot`, `span_unclosed`, `span_unopened`, `reference_hash_mismatch`, `reference_unresolved`, `ack_target_not_a_candidate`, `tool_target_not_a_call`, `shred_target_key_mismatch`, `shred_target_unresolved`, `continuation_malformed`, `continuation_predecessor_mismatch`, `continuation_index_not_increasing`, `continuation_index_gap`, `continuation_prior_root_mismatch` |
| Violation `code` | `prefix_absent`, `genesis_not_first`, `genesis_prev_hash_nonzero`, `header_len_mismatch`, `malformed_tlv`, `time_trust_undefined`, `time_unknown_with_wall_clock`, `empty_body_digest_nonzero`, `nonempty_body_digest_zero`, `encrypted_body_too_short` |
| `ManifestReading.status` | `matches`, `contradicts`, `declared_only` |
| `outcome_name` | `ok`, `error`, `timeout`, `cancelled`, `unobserved` |
| `source_name` | `parsed-from-wire`, `reported-by-client` |
| `disposition_name`, `kind_name`, `type_name`, tier and time-trust names | as the specification and the inference profile define them |

An advisory never changes a verdict. Each new member ships with one
CHANGELOG sentence saying what it means and whether it changes a verdict.

## The report contract

- The JSON shape's machine truth is the schema shipped in the wheel at
  `palimpsests/audit/_schemas/pala-verification-report-2.schema.json`
  (source: `docs/specs/report/`). A rendering validates against it; the
  package's own CI does. The schema states what must be present and does
  not forbid a key it does not name: the format is open to additions.
- **`/1` is no longer written and is still read.** Its schema ships beside
  the new one, `derive_verdict` answers a `/1` report by the rule it was
  written under, and `render_html` renders one. What changed, and what a
  consumer does about it: `docs/specs/report/MIGRATING-1-TO-2.md`.
- **The verdict is produced only by `derive_verdict`.** A renderer reads
  the report's `verdict` field or calls the function; it never
  re-derives the rule. This is what keeps two renderings from disagreeing
  in the one word that matters. `pala verify --json` carries the same
  word for the same file and anchor, and a test holds the two together.
- **Four verdicts, a closed set:** `sound` — everything checked, held;
  `partial` — sound as far as checked, completeness not checked; `empty` —
  the container holds no records, so nothing was checked and nothing was
  found intact; `violation` — something contradicts. An empty file that
  misses a supplied anchor is a `violation`. A consumer that gates on a
  verdict treats `empty` as it treats `partial`: not a failure, and not a
  pass.
- **Normalization rule for golden tests:** `checked_at` (by design) and
  the version-carrying fields `verifier.tool` / `verifier.package` are
  normalized away before comparing reports. Everything else is
  deterministic for the same inputs.
- `anchor.observed_at_ns` is `null` when the anchor source does not
  carry an observation time — today's file/manual sources do not.
- Wording discipline is part of the contract: a report is an attestation
  of a check, never "compliant", "certified", or "valid log".

## The export contract

`export_jsonl(data, out)` writes `pala-jsonl/1` — one line per record and a
summary line; the format is described in
[specs/export/pala-jsonl-1.md](specs/export/pala-jsonl-1.md).

- **Derived, never authoritative.** Every line names its record by `seq` and
  `record_hash`; what is concluded from a line is checked against that record.
- **It never refuses a container.** A broken chain, a body that does not match
  its digest, a container cut mid-record: what can be exported is, and the
  summary says what was found. A body that does not match is marked on its
  own line (`body_digest_mismatch`) as well as in the summary.
- **`consistent` is `pala verify`'s consistency, by the same rule** — the
  header chain, the container's form and every body's digest. The two cannot
  answer differently about one file.
- **Completeness is never claimed.** The export reads no anchor;
  `completeness_checked` is `false`.
- **A line carries what the reader decodes** — a tool's outcome, the evidence
  mark, an operator's disposition, `detail` — so a consumer of the export
  parses no TLV.
- **Codes and numbers are contract; sentences are not**: `malformed`, `note`,
  `detail` and the reasons in `violations` are carried verbatim.
- **Normalization rule:** the summary's `tool` names the package version.
  Everything else is deterministic for the same container.
- **It streams.** Records are read, written and forgotten one at a time;
  `data` is any bytes-like object, so pass a file's mapping, not a copy of
  the file. Measured on 200,002 records of tool loops (42 MB): 448 MB peak
  before 0.14.1, when every decoded record was kept; 77 MB after, 42 of them
  the file itself held as bytes.

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
carries the manifest's identity since format `/2`, in its `manifest`
block: the file's name (the manifest sits beside the subject; the report
holds no path of the machine that ran the check), the status, the digest
and the detail — `null` when the verdict read no second file.

## Size envelope

The reader holds all record headers in memory and `build_report` /
`assemble_bundle` read the source file fully (the bundle twice). This
is comfortable to the order of ~10^6 records / hundreds of MB;
multi-GB retention archives (see `docs/RETENTION.md` for the storage
math) should be segmented before interactive use. A streaming reader
is backlog, not promise.

A consumer that needs one record, a page of records or a count does not
have to pay for the whole decode. A consumer that filters by kind, evidence
mark, tool outcome or `detail` reads `record_fields_at(index)` (since 0.14):
the same values `record_at(index)` would give, read in place, nothing
decoded or kept. A consumer that shows bytes reads `record_bytes_at(index)` —
the record as the file holds it — and `header_tlv_spans_at` /
`body_tlv_spans_at` for where each TLV sits, as offsets from the record's
start; `HEADER_FIELDS` (since 0.14.1) names the sixteen fields of the 156 fixed
bytes those spans sit after, each with its offset, length and `struct` code.
`Header.decode` keeps every field and TLV, so an accepted header
re-encodes to its own bytes; the stored bytes are what there is to show for
a header it rejects, and for every body. And: `record_count`, `record_at(index)`,
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

**`verify()` on an agent's log.** The referential pass was bounded in 0.12
by the number of references — which on an agent's log is about half the
records, since every tool result references its call. Measured by Auditor on
0.13.1: one million records of tool loops, `verify()` 32.5 s and 2.47 GB,
every record decoded and kept. Since 0.14 a cold reader reads references in
place — the reference, the target's header hash and its kind — and decodes
nothing: on 200,000 records of tool loops, 5.8 s / 513 MB before, 1.7 s /
97 MB after, no record kept. A reader whose chain is already decoded keeps
the decoded path, and the two give the same advisories (tested).

Measured at that boundary in 0.10, before the referential pass was
bounded (0.12: it now decodes only the records that carry a reference
and the records they name), so the figures below are a ceiling, not
today's cost: a synthetic 1,000,004-record / 224 MB chain, `open()` plus `verify()` plus
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
