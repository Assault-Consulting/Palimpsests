<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The segments manifest — `pala-segments/1`

A chain kept for months is kept in **segments**: files cut strictly at
record boundaries, so that old ones can be deleted under a retention
policy and the rest still verified. The manifest is the one file that
describes the set. It is what lets a segment that does not begin with a
GENESIS be verified from its declared start, and what distinguishes *the
predecessor was deleted under retention* from *the predecessor is
missing*.

**The manifest is derived and unsigned.** The segments stay authoritative:
every claim in it about a segment that is still on disk is recomputed from
that segment's bytes. About a segment that has been deleted, the manifest
is the only evidence left, and what it says is a declaration, not a
verified fact. What gives a manifest standing is where it was kept, or an
anchor held outside it. Why this matters, and what the chain itself
carries about a cut, is in `docs/RETENTION.md` and
`docs/specs/pala-1/profiles/retention-continuation.md`.

## 1. Two writers

| | The knife | The rotating writer |
|---|---|---|
| What | `pala segment <file>`, `segment_chain()` — splits a finished file | `PalaWriter(..., rotation=RotationPolicy(...))` — cuts as it writes |
| Manifest | `segments.json` in the output directory | `<base>.segments.json` beside the chain |
| Segment files | `segment-<index>-seq<first>-<last>.pala` | `<base>` for the first, then `<base>.00001`, `<base>.00002`, … |
| Lists | every segment | **closed** segments only: the segment being written is not in the manifest until it is closed |
| Written | once | replaced atomically at every cut |

A segment written by the rotating writer after the first begins with a
`SEGMENT_CONTINUATION` record (inference profile r6): the chain itself
declares its predecessor. Segments cut by the knife do not; the knife
adds nothing to the bytes, and its segments concatenate back to the
source byte for byte.

## 2. The document

JSON, UTF-8, sorted keys, two-space indent, a final newline.

| Key | Value |
|---|---|
| `format` | `pala-segments/1` |
| `tool` | `{name, version}` — the writer |
| `source_head` | the `head` of the last listed segment, hex; 32 zero bytes when none is listed. For a rotating writer this is the last *closed* segment, not the live one |
| `segments` | the entries, in chain order |
| `records_per_segment` | the knife only: the size it cut to |
| `rotation` | the rotating writer only: the thresholds in force — any of `max_records`, `max_bytes`, `max_age_s` |

Each entry of `segments`:

| Key | Value |
|---|---|
| `file` | the segment's file name — a name, not a path: the file is beside the manifest |
| `first_seq`, `last_seq` | the seq of its first and last record |
| `records` | how many records it holds |
| `head` | the record hash (§1.2) of its last record, hex |
| `prev_head` | the head of the segment before it, hex — the value its first record's `prev_hash` must equal. 32 zero bytes for a segment that begins the chain |
| `root` | rotating writer only: the derived root (the §4.3 tree over the record hashes of every record from seq 0 through `last_seq`), hex — see `consistency-proof.md` |
| `frontier` | rotating writer only: the writer's own state for continuing that root after earlier segments are gone, hex. Opaque to a reader |

**Entry *i* is segment *i*, and the entry of a closed segment is never
removed.** Deleting a segment's file under retention leaves its entry in
place: the manifest keeps every head. A continuation record's `SEG_INDEX`
*k* is therefore checked against entry *k − 1*.

One entry can be withdrawn, and only the last: a cut interrupted after the
manifest was written and before the successor file existed. Nothing was
written after it, so the cut did not happen; a writer that resumes folds
it back — removes that entry and carries on in the same file — and logs
that it did.

## 3. What a reader does with it

**One segment, verified from its declared start.** Verify the segment's
headers with the entry's `prev_head` as the hash the first record must
link to, instead of requiring a GENESIS; check every body against its
header's digest; then compare what the file is with what the entry says —
its last record's hash is `head`, its first and last seq and its record
count are the entry's.

**The seams.** Each entry's `prev_head` equals the previous entry's
`head`. This is a statement about the manifest alone, and holds or fails
whether or not the files are there.

**The set** (`palimpsests.audit.segment_set.verify_segment_set`). Two
answers, kept apart:

- **consistent** — every seam holds, and every listed segment that is on
  disk verifies from its declared start and agrees with its entry;
- **complete** — consistent, no listed segment is absent, and the first
  entry begins the chain (`prev_head` zero, `first_seq` 0).

A segment deleted under retention makes a set incomplete, never
inconsistent. A segment that is present and damaged — a broken link, an
altered body, a file cut in the middle of a record — makes it
inconsistent, and is reported for that segment; the others are still
judged on their own.

A rotating writer's live segment is not listed. A reader finds it as the
file beside the manifest whose first record links to the last listed
`head`, and verifies it the same way.

**A manifest is input from outside.** A reader does not follow an entry
whose `file` is not a plain file name — a path into another directory, an
absolute path — and does not call a set consistent on the strength of it.
A manifest that is not JSON, not an object, or not `pala-segments/1` is
not a manifest; it confirms nothing and contradicts nothing.

**A single segment opened on its own** (`AuditReader.open` on
`<base>.<digits>`): when its first record declares a continuation, the
reader looks for `<base>.segments.json` and reports whether entry
*k − 1*'s `head` is the predecessor the record declares — `matches`,
`contradicts`, or `declared_only` when there is no usable manifest — with
the SHA-256 of the manifest bytes it read (`Verification.manifest`; the
report's `manifest` block).

## 4. What the knife refuses

`pala segment` walks its source to the end before it writes anything. A
source that is not a well-formed container — cut in the middle of a
record, or not a container — is refused and nothing is written: the cut
promises that the segments concatenate back to the source, and bytes that
are not whole records cannot be placed in a segment.

The cut is otherwise faithful, not a judgement. A chain with a broken
link or an altered body is segmented as it is; the segments carry the
same damage, the set is inconsistent, and the command says so.

## 5. Stability

The format is **open**: a writer may add a key to the document or to an
entry — the rotating writer's `root` and `frontier` are such keys — and
none is removed, renamed or given another meaning without a new format
id. A reader ignores a key it does not know. Fixed: the six entry keys of
§2 that both writers write, the rule that entry *i* is segment *i*, and
the meaning of `prev_head` and `head`.

Keep the manifest for as long as any segment it describes is kept.
