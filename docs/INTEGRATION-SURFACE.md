# The integration surface

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

The documented contract between this package and any consumer that
embeds its audit stack — first among them
[Auditor](https://github.com/Assault-Consulting/Auditor), whose desktop
shell drives everything below through a Python sidecar. If a behaviour
matters to a consumer and is not written here or in the linked specs,
it is not promised.

This is the surface for reading a chain. Writing one has its own contract
([WRITER-SURFACE.md](WRITER-SURFACE.md)), and so have the HTTP routes an
integration reports to ([SERVE-SURFACE.md](SERVE-SURFACE.md)).

## The channels

| # | Channel | Surface | Stability |
|---|---------|---------|-----------|
| 1 | Reading | `palimpsests.audit.reader.AuditReader` (`open`, `verify`, `records`, `spans`, `boots`, `origin_at`, `unloaded_at`, `acknowledged_candidates`, `shredded_targets`; sparse access `record_count`, `record_at`, `record_by_seq`, `header_at` since 0.13; `Verification.manifest` since 0.13; `container_check()`, `record_fields_at()` since 0.14; for a byte view `record_bytes_at()`, `header_tlv_spans_at()`, `body_tlv_spans_at()` since 0.14, and the fixed header's layout `HEADER_FIELDS` / `HeaderField` / `FIXED_HEADER_LEN` since 0.14.1; a KEY_SHRED's erasure note `decode_shred` / `ShredView` since 0.15; question one as one answer `AuditReader.is_consistent()`, `Diagnosis.question`, the vocabularies as data, and the header-enum names `assurance_tier_name` / `time_trust_name` — the same objects as in `palimpsests.audit.names` — since 0.15); a segmented chain as one set: `palimpsests.audit.segment_set.verify_segment_set` (since 0.14) | public (since 0.8) |
| 2 | Report and export | `palimpsests.audit.report.build_report` (`health=` since 0.15), `health_summary`, `derive_verdict`, format `pala-verification-report/2` (since 0.15; `/1` in 0.10 – 0.14, still read); the HTML page `palimpsests.audit.report_html.render_html` (since 0.14 — a rendering of the report's `.data`, its markup not a format); the record export `palimpsests.audit.export.export_jsonl`, format `pala-jsonl/1` (since 0.14.1) | public (since 0.10) |
| 3 | Proofs | `palimpsests.audit.pala.proofs.inclusion_proof`, `range_proofs`, `InclusionProof`; prefix consistency `chain_root`, `consistency_proof`, `ConsistencyProof`, format `pala-consistency-proof/1` (since 0.12) | public (since 0.10) |
| 4 | Bundle | `palimpsests.audit.pala.bundle.assemble_bundle` (`reader=` since 0.15), `BundleResult`, format `pala-bundle/1` (`docs/specs/bundle/pala-bundle-1.md`) | public (since 0.10) |
| 5 | Health | `palimpsests.audit.timehealth`, `palimpsests.audit.bootstats` | public (since 0.10) |
| 6 | Conformance | `palimpsests.audit.pala.vectors.load`, `palimpsests.audit.pala.selftest.run_selftest`, `pala selftest` | public (since 0.10) |
| 7 | Distribution | PyPI wheel; vectors and the report schema ship inside it | — |
| 8 | SCITT statements | `palimpsests.audit.pala.scitt` — `build_signed_statement`, `head_payload`, `verify_statement`, `StatementCheck`, `StatementRefused`; needs the `[scitt]` extra | public (since 0.15) |

| 9 | Live reading | `palimpsests.audit.tailing.TailingReader` (`events`, `snapshot`, `close`), `TailEvent`, `TAIL_EVENT_KINDS` | **provisional** (since 0.15) |

**Stability class "provisional":** declared, tested and meant to become
public, but not yet held to the rule below — it may change in a minor
release, and the changelog names the change. A consumer may build on it
and should pin the minor. Live reading is provisional because no consumer
has run it yet and two properties may have to change when one does: it
keeps every verified record in memory, and `snapshot()` verifies them all
again on each call. It becomes public, or says why not, before 1.0.

**Stability class "public":** breaking changes only with a minor version
bump and a CHANGELOG entry naming the break; additive changes (new
fields, new functions) may land in any release. One named format,
`pala-consistency-proof/1`, changes only by format-id bump. Three are
open — `pala-verification-report/2`, `pala-bundle/1` and `pala-jsonl/1`:
a release may add a key, and none is removed, renamed or given another
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

- **One diagnosis, three questions.** A diagnosis is about one of them,
  and `Diagnosis.question` says which: `consistency`, `completeness`, or
  `None` (`empty_container`). A finding about the anchor is not a finding
  about the chain: a chain that holds together, read against an anchor
  that does not name its head, has a diagnosis and is consistent. And a
  body altered after writing leaves the diagnosis `None` — the diagnosis
  is made from the header pass — on a file that is not consistent. So
  **question one is never `diagnosis is None`**: it is
  `AuditReader.is_consistent()`, the same rule as `consistency.ok` in
  `pala verify --json` and `consistent` in the export and the bundle.
- **The vocabularies are data too** (since 0.15): `DIAGNOSIS_PATTERNS`,
  `DIAGNOSIS_QUESTIONS`, `ADVISORY_CODES`, `VIOLATION_CODES` and
  `MANIFEST_STATUSES` in `palimpsests.audit.reader`, `VERDICTS` in
  `palimpsests.audit.report` — what the installed build can say. A
  consumer that keeps a table of its own (guidance per pattern, a
  sentence per code) tests that the table covers these, and learns of a
  new member from a failing test instead of from a user's screen.

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
bridge are channel 8 since 0.15 ("The SCITT statement contract" below);
B3 verified the construction, not that API, and the contract test is what
holds the API.

## Vocabularies (open)

| Vocabulary | Members as of 0.13 |
|---|---|
| Diagnosis `pattern` | `empty_container`, `not_a_container`, `truncated_tail`, `prefix_absent`, `declared_continuation`, `continuation_contradicts_manifest`, `seq_gap`, `chain_break`, `record_violation`, `unanchored_tail`, `replaced_or_rolled_back` |
| Advisory `code` | `anchor_never_written`, `boot_ended_without_close` (since 0.15), `reports_refused` (since 0.15), `mid_boot_time_trust_change`, `mono_regression_in_boot`, `wall_regression_in_boot`, `span_unclosed`, `span_unopened`, `reference_hash_mismatch`, `reference_unresolved`, `ack_target_not_a_candidate`, `tool_target_not_a_call`, `shred_target_key_mismatch`, `shred_target_unresolved`, `continuation_malformed`, `continuation_predecessor_mismatch`, `continuation_index_not_increasing`, `continuation_index_gap`, `continuation_prior_root_mismatch` |
| Violation `code` | `prefix_absent`, `genesis_not_first`, `genesis_prev_hash_nonzero`, `header_len_mismatch`, `malformed_tlv`, `time_trust_undefined`, `time_unknown_with_wall_clock`, `empty_body_digest_nonzero`, `nonempty_body_digest_zero`, `encrypted_body_too_short` |
| Diagnosis patterns about consistency | `not_a_container`, `truncated_tail`, `prefix_absent`, `declared_continuation`, `continuation_contradicts_manifest`, `seq_gap`, `chain_break`, `record_violation` |
| Diagnosis patterns about completeness | `unanchored_tail`, `replaced_or_rolled_back` |
| `ManifestReading.status` | `matches`, `contradicts`, `declared_only` |
| `outcome_name` | `ok`, `error`, `timeout`, `cancelled`, `unobserved` |
| `source_name` | `parsed-from-wire`, `reported-by-client`, `derived-from-telemetry` (since 0.15) |
| `ShredView.reason_name` | `unspecified`, `legal_erasure`, `retention_expiry`, `policy` |
| `StatementRefused.code` | `not_cose_sign1`, `trailing_bytes`, `protected_header_malformed`, `detached_payload`, `payload_malformed`, `repeated_key`, `indefinite_length_map`, `unprotected_header_malformed` (since 0.15), `non_deterministic_encoding` (since 0.15), `unsupported_alg`, `key_type_mismatch`, `signature_invalid`, `head_mismatch`, `format_id_mismatch`, `range_invalid`, `content_type_unknown`, `payload_keys_mismatch`, `protected_labels_mismatch`, `root_malformed`, `chain_too_short`, `root_mismatch` |
| `StatementCheck.root_status` | `absent`, `recomputed`, `carried, not recomputed` |
| `StatementCheck.payload_encoding` | `deterministic` |
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

## The SCITT statement contract

Channel 8: a chain head as a COSE_Sign1 Signed Statement, built and
verified (`docs/INTEROP-SCITT.md` for what the statement is and what a
deployment may say on the strength of it).

- **It needs the `[scitt]` extra** (`cbor2`, `cryptography`). Without it
  every function raises `ScittUnavailable`; a bare install keeps full
  verification of chains and loses only this channel.
- **A key is a `cryptography` key object**, loaded by the caller: an
  Ed25519 or P-256 private key to sign, the matching public key to
  verify. The module reads no key files and holds no keys. Which key is
  trusted is the caller's decision and the whole of the claim.
- **One verifier: `verify_statement(message, public_key, expected_head,
  reader=None)`.** It returns a `StatementCheck` — `version` (`v2` /
  `v3`), `payload`, `root`, `root_status`, `payload_encoding`,
  `statement_id` — or raises.
  `check_statement_against_head` is deprecated since 0.15 and goes at
  1.0 ([Deprecations](#deprecations)); it returned the payload alone and could not say what was
  established about a root.
- **Every statement it does not accept is a `StatementRefused`**, a
  `ValueError`, with a `code` from the vocabulary above
  (`STATEMENT_REFUSAL_CODES`). That includes bytes that are no CBOR at
  all: a verifier of someone else's bytes raises one thing. The code
  names the check that failed, never a cause — a statement for another
  chain, a corrupted download and a forgery are refused alike.
- **One encoding is accepted, and `statement_id` names the statement**
  (since 0.15). The envelope, the protected header and the payload must
  be the RFC 8949 §4.2.1 deterministic encoding; any other writing of
  the same signed content is refused (`non_deterministic_encoding`),
  though its signature is valid. The unprotected header must be a
  definite-length map with no label twice
  (`unprotected_header_malformed`) and its count in the shortest form;
  what it holds is not judged.
  `statement_id` is 32 bytes: the SHA-256 of the statement with the
  unprotected header emptied — the hash of the bytes as built, and
  unchanged when a receipt is attached. Refer to a statement by it, not
  by a hash of whatever bytes arrived. It names the signed statement,
  not its content. `payload_encoding` is therefore always
  `deterministic`; the field stays until 1.0 and is then removed.
  See [INTEROP-SCITT §11](INTEROP-SCITT.md#11-one-statement-one-encoding-one-name).
- **A root is recomputed only with the chain.** Without `reader`, a v3
  root is `carried, not recomputed`: signed, and not verified against
  anything. A consumer says which.
- **It does not verify receipts.** Whether a transparency service
  registered a statement, and when, is checked by that service's
  protocol. `verify_statement` passing says the statement is this
  construction, signed by this key, committing to this head — not that
  it was ever published.
- **Algorithms: ES256 (`-7`), EdDSA (`-8`) and Ed25519 (`-19`, RFC 9864;
  since 0.15).** Any other is refused as `unsupported_alg`. `-8` and `-19`
  both mean Ed25519 here and `-7` means P-256: a key of another type —
  Ed448, another curve, a private key — is refused as `key_type_mismatch`,
  by the builder (`ValueError`) and by the verifier, before any signature
  is checked. Statements under `-8` and `-19` reproduce byte for byte;
  ES256 ones do not. The builder's default is unchanged (`-7`).
- The *bytes* of a statement are a different contract from this API:
  they change only by content-type bump, and are what the independent
  verification covers.

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

The manifest's format, `pala-segments/1`, is specified in
`docs/specs/segments/pala-segments-1.md`: its two writers, the keys, what a
reader checks, and what it does not follow. It is open to added keys.

A consumer that identifies what it verified by digest records both digests,
and treats a change to either file as a change of subject. The report
carries the manifest's identity since format `/2`, in its `manifest`
block: the file's name (the manifest sits beside the subject; the report
holds no path of the machine that ran the check), the status, the digest
and the detail — `null` when the verdict read no second file.

## Size envelope

The reader holds all record headers in memory and `build_report` /
`assemble_bundle` read the source file fully, through the reader's mapping
and not a copy. Both take `reader=` (`assemble_bundle` since 0.15), so a
consumer that holds the chain open hands it over and the file is not
opened again. A bundle holds the records of its *selection*, and a proof
for each, in memory while the archive is written — **a bundle is for a
selection, not for a whole large chain.** Measured on a chain of 10^6
records (183 MB, checkpointed every 50,000): a selection of 1,000 records
takes 9 s and 0.4 GB, nearly all of it the verification of the whole file
that every bundle carries; 100,000 records take 14 s and 1.3 GB and make
a 239 MB archive; the whole chain does not fit in 8 GB. The archive
outgrows its source because `proofs.json` carries a path per record. To
hand over a whole chain, hand over the chain: `pala segment`, or the file
itself with its report.

The other commands on that same chain (10^6 records, 183 MB; one run each,
Python 3.13 on a 2-core x86-64 Linux VM with 8 GB, peak resident memory of the
process):

| Command | Time | Peak memory | Output |
|---|---|---|---|
| `pala verify` | 9 s | 0.5 GB | — |
| `pala export` (whole chain) | 23 s | 0.3 GB | 535 MB of JSONL |
| `pala segment` (100,000 per segment) | 7 s | 0.6 GB | 11 segments and the manifest |
| `pala bundle`, 1,000 records | 9 s | 0.4 GB | 2.4 MB |
| `pala bundle`, 100,000 records | 14 s | 1.3 GB | 239 MB |

Memory is about half a kilobyte per record for everything but a large
bundle; the export streams its output and does not grow with it. These
are measurements of one machine, not limits and not a promise.

This is comfortable to the order of ~10^6 records / hundreds of MB;
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

## Writing a chain, and chains for tests

This document is for reading. Writing a chain with this package —
`PalaWriter`, rotation, the lock, what is and is not guaranteed about
durability — has its own contract: `docs/WRITER-SURFACE.md`.

A consumer's tests need chains that do **not** verify, and the writer
cannot produce one. `palimpsests.audit.testing` makes them from a
well-formed chain, one named defect per function, and its `DAMAGE` table
states what the reader says about each — so no test needs to rewrite
bytes at offsets copied from the specification.

## Conformance for embedders

- Run `pala selftest` (or `run_selftest()`) at sidecar startup and
  surface an UNSOUND result to the user — the packaged vectors make
  this an offline check.
- The companion vector set's `semantics` block covers a subset of its
  records by design (the block grows additively); rendering-conformance
  tests should assert against the seqs present, not assume totality.

## Live reading (provisional)

`TailingReader(path, anchor=…, poll_interval=…, torn_grace=…)` follows a
container that is still being written. `events()` blocks and yields
`TailEvent(kind, seq, record, detail)` until `close()`; `snapshot()`
returns the same `Verification` `AuditReader` would give for the records
verified so far, because it is produced by the same code — a chain read
live and the same chain read afterwards give the same answers.

| `kind` | What happened |
|---|---|
| `record` | a whole record was verified; `record` is its `DecodedRecord` |
| `anchor_seen` | that record was an `ANCHOR` |
| `pending_tail` | bytes after the last whole record: a record in flight, not a defect |
| `shrunk` | the file lost bytes *within* the pending region — a writer truncating its own torn tail on resume |
| `recovered` | the writer's recovery records followed |
| `diagnosis` | a pending tail that stopped growing for `torn_grace` (`truncated_tail`), or the file shrinking below a verified record (`replaced_or_rolled_back`) — the one real alarm |

`kind` is an open vocabulary (`TAIL_EVENT_KINDS`); `detail` is a sentence,
never parsed. The reader polls with `os.stat`; it does not follow a
rotation into the next segment.

## Deprecations

A name that is going away keeps working, says so when used, and is listed
here with the release it leaves in. Nothing is removed without having
been in this table for at least one minor release; from 1.0, nothing is
removed within a major.

| Name | Deprecated | Removed | Use instead | What differs |
|---|---|---|---|---|
| `palimpsests.audit.pala.scitt.check_statement_against_head` | 0.15 | 1.0 | `verify_statement` | Returned the payload alone; `verify_statement` returns a `StatementCheck` (version, range, root). Refusals are the same `StatementRefused`. |
| `palimpsests.cli.EXIT_TAMPERED` | 0.15 | 1.0 | `EXIT_VIOLATION` | The same value, 1. The old name stated a cause the tool cannot know. |

Both emit a `DeprecationWarning` naming the replacement. Python hides
that warning outside tests by default; run a suite with
`-W error::DeprecationWarning` to find a use before the name is gone.

**Not deprecated, and not going:** reading what earlier releases wrote.
`pala-verification-report/1` has not been written since 0.15 and is still
read and rendered (`REPORT_FORMAT_1`, and its schema ships); a bundle, a
segments manifest or a statement made by any released version stays
readable. A format is retired by a format-id bump and a migration note,
never by an unreadable file.

## The report's health section

`build_report(..., health=True)` (`pala report --health`) fills the
report's `health` key with a summary of channel 5: boots, the widest gap
between anchors, wall-clock steps and drift, open spans. Without the flag
the key is `null` and nothing is computed — `null` means "not asked for",
never "healthy".

- **Advisory.** No figure is a threshold, there is no word of judgement,
  and `derive_verdict` does not read the section.
- **Of fixed size.** Counts and extremes, no series: it does not grow
  with the chain. A consumer that wants the series calls
  `step_catalog`, `drift_series` and `boot_statistics` itself.
- **Each group names its clock** in `basis`: proved order, the monotonic
  clock within one boot, or the writer's wall clock against it. A figure
  on the wall clock is the writer's claim.
- `anchors.widest_gap_ns` counts the edges (boot start to the first
  anchor, the last anchor to the boot's end): an existed-by bracket for a
  record of that boot is never narrower.
- **It costs a walk.** Measured on a chain of 10^6 records, a report with
  the section took 11 s and 0.7 GB against 9 s and 0.4 GB without it.

The schema names every key; the section is open to added ones.
`health_summary(reader)` returns the same section for a reader a consumer
already holds.

## How a break is found before a release

A consumer pins a released version, so by itself it meets a change made
here only when it lifts the pin. Two things run earlier.

- **The contract test** (`tests/test_consumer_surface.py`) holds the
  declared names, the fields of the views, the vocabularies and their
  documented members to the code on every change.
- **The consumer canary** (`.github/workflows/consumer-canary.yml`) runs a
  consumer's own test suite — Auditor's sidecar, on its `main` — against
  every commit and pull request here, and once a week. Its failures are
  compared with a ledger, `.github/consumer-canary/auditor-expected.txt`:
  the breaks made on purpose, each with its reason. A failure the ledger
  does not list fails the check. A line that passes again is reported, and
  removed. The canary is a signal and not a required check: the
  consumer's branch moves on its own, and must not be able to block a
  merge here.

A break of the surface is therefore either absent, or written down twice
before it ships: in the changelog, and in the ledger.
