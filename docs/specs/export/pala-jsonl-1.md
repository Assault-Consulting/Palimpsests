<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# `pala-jsonl/1` — the record export

The format written by `palimpsests pala export` and by
`palimpsests.audit.export.export_jsonl`: the converter PALA-1 §1.1 calls
`pala2json`. A PALA-1 log is binary; this is the view of it a person, a
script or a log pipeline can read.

**Derived, never authoritative.** The export carries no signature and enters
no hash. Every line names its record by `seq` and `record_hash`, so anything
said about a line can be taken back to the record it came from and checked
there. The binary log is what is evidence; this is a rendering of it.

## Shape

UTF-8 text, one JSON object per line, LF line endings, no blank lines:

1. one line per record, in the order the records sit in the container;
2. then exactly one **summary** line — the only line with `"summary": true`.

Compact separators, keys in a fixed order. A reader finds the summary by its
key, not by its position, and takes the last line as a cross-check.

## A record's line

Always present:

| Key | Value |
|---|---|
| `seq` | the record's sequence number |
| `record_hash` | SHA-256 of the record's header, lowercase hex — the record's identity in the chain (§1.2) |
| `record_type` | the type, as `"0x%04x"` |
| `type_name` | its name, or `null` for a type this build does not know (§7.6) |
| `kind` | `EVT_KIND` of an EVENT or SAFETY body, or `null` — the record carries no kind |
| `kind_name` | its name, or `null`: with `kind` set, a kind this build does not know |
| `body_len` | bytes of body, `0` for none |

When the header decodes — every record of a known format version:

| Key | Value |
|---|---|
| `boot_id` | hex |
| `span_id`, `parent_span_id` | hex, or `null` for "no span" |
| `assurance_tier`, `time_trust` | the numbers the specification fixes |
| `monotonic_ns`, `wall_clock_ns` | integers; `wall_clock_ns` is qualified by `time_trust` |
| `key_id` | `0` for a cleartext body |
| `header_tlvs` | `[{"tag": "0x%04x", "value_hex": "…"}, …]`, in order |

When it does not, those keys are absent and `"header_undecoded": true` is
present. The record is still listed, with its `seq`, `record_hash` and type.

Present only where the record has them — each equal to what
`AuditReader.record_at()` decodes:

| Key | On |
|---|---|
| `source`, `source_name` | a `TOOL_CALL` or `TOOL_RESULT`: `0` parsed-from-wire, `1` reported-by-client |
| `outcome`, `outcome_name` | a `TOOL_RESULT`: `ok`, `error`, `timeout`, `cancelled`, `unobserved` |
| `disposition`, `disposition_name` | an `OVERSIGHT_ACK` |
| `operator_id` | an `OVERSIGHT_ACK`: 16 bytes, hex, pseudonymous |
| `detail` | an EVENT or SAFETY body carrying `EVT_DETAIL` |

`ok` is a return, never a success; `unobserved` is a return whose failure the
recording vantage could not see (inference profile §3.1). A line with
`source: 1` is the client's report, recorded — not the runtime's observation.

The body, when `body_len` is not `0`:

| Key | Meaning |
|---|---|
| `body_tlvs` | the body's TLVs, as `header_tlvs` — a cleartext body that parses |
| `body_opaque: true` | an encrypted body, or one that does not parse: present, not shown |
| `body_digest_mismatch: true` | **the body is not the one this record's header binds** |

`record_hash` covers the header, and the header binds the body by its digest.
A body whose digest does not match is exported all the same — showing damaged
evidence is the point — but whatever the line shows of it is **not** what
`record_hash` covers, and the line says so. The key is absent when the body
matches.

## The summary line

| Key | Value |
|---|---|
| `summary` | `true` |
| `format` | `"pala-jsonl/1"` |
| `records` | records the check walked |
| `chain_head` | hash of the last of them, hex |
| `chain_ok` | the header chain of §7.1 holds: no break, no gap, no violated MUST |
| `breaks`, `gaps` | seqs |
| `violations` | `[[seq, reason], …]` — the reason is a sentence |
| `violation_codes` | `[[seq, code], …]`, parallel to `violations` — the code is what to branch on |
| `well_formed` | the walk reached the end of the file on a record boundary (§2.4) |
| `malformed` | why it did not, in the walker's words; `null` when it did |
| `bytes_parsed`, `bytes_total` | bytes of whole records walked; bytes in the file |
| `body_digest_mismatches` | seqs whose body does not match its header's digest |
| `consistent` | `chain_ok` and `well_formed` and no body mismatch |
| `completeness_checked` | `false` — see below |
| `source_sha256` | SHA-256 of the container exported, hex |
| `tool` | `"palimpsests <version>"` |
| `note` | a sentence saying the export is derived |
| `from_seq`, `to_seq` | present when the export was limited to a range |

The summary always describes the **whole container**, a range export included:
`records`, `chain_head` and every finding are about the file, not about the
lines printed.

**`consistent` is `pala verify`'s consistency, by the same rule**, so the two
tools cannot answer differently about one file. On a container with no
records it is vacuously `true`: nothing was there to contradict
(clarification C-8) — `records: 0` says the rest.

**Completeness is not checked.** The export reads no anchor.
`consistent: true` says the records present agree with each other; it says
nothing about records removed from the end, or a log replaced whole. For
that, `pala verify --anchor`.

## Damage

The export never refuses a container and never raises on one:

- a broken chain, a gap or a violated MUST: every record exported, the finding
  in the summary;
- a body that does not match its digest: exported and marked, on its line and
  in the summary;
- a container cut in the middle of a record — a writer caught mid-write, or a
  crash: every whole record exported, `well_formed: false`, `malformed` saying
  where the walk stopped;
- bytes that are not a container at all: no record lines, a summary with
  `records: 0` and `well_formed: false`.

## Rules for a consumer

- **Keys may be added; none is removed, renamed or given another meaning**
  under this format id. Ignore a key you do not know.
- **Numbers and codes are what to branch on; sentences are not.** `malformed`,
  `note`, `detail` and the reason in `violations` are carried verbatim, never
  parsed, and may be reworded in any release.
- **Name tables may grow.** Handle a `null` name beside a number you do not
  know.
- **Deterministic for one version of the tool.** The same container gives the
  same bytes; `tool` names the version, so set that field aside when
  comparing exports made by different versions.
- **It is a view.** Whatever is concluded from an export is concluded about
  the record its `record_hash` names, and is checked there.
