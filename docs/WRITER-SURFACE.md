<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The writer's surface

`docs/INTEGRATION-SURFACE.md` is the contract for whoever **reads** a
chain. This is the contract for whoever **writes** one with this package:
a runtime that records its own serving loop (`palimpsests serve`, the
agent hooks, an embedder), and the test suite of a consumer that needs
chains to read.

It is held to the code by `tests/test_writer_surface.py`, the same way
the reader's surface is held by `tests/test_consumer_surface.py`.

**Class: public, experimental until 1.0.** From 0.15 the names below are
declared, tested and not removed or renamed without a deprecation
release. Until 1.0 a behaviour may still change with a changelog entry;
at 1.0 this surface becomes stable with the reader's.

The writer writes the **inference profile** of PALA-1
(`docs/specs/pala-1/profiles/inference.md`). What ends up in the file is
governed by the frozen wire format and the profile, not by this document:
this one says how the Python object behaves.

## 1. What is declared

`palimpsests.audit.pala_writer.__all__`:

| Name | What |
|---|---|
| `PalaWriter` | the writer |
| `RotationPolicy` | when the writer cuts a segment on its own |
| `Durability` | when a record is on stable storage (§4) |
| `ChainLocked` | raised when another process already writes the chain |
| `FrontierUnavailable` | raised by `chain_root()` when the root cannot be stated |
| `session_span_id(session_id)` | the span id the writer uses for a session id |
| `canonical_config_digest`, `canonical_tool_args_digest`, `canonical_tool_names_digest` | the digests the profile defines over a config, a tool call's arguments, a set of tool names |

Beside it:

- `palimpsests.audit.pala.checkpoints.merkle_checkpoint(writer)` — writes
  a `MERKLE` record over the records since the previous one.
- `palimpsests.audit.anchors.AnchorStore`, `FileAnchorStore` — the write
  side of an anchor: where a deployment keeps the head it will later
  verify against. They stay in `anchors`, beside the sources that read
  what they write.
- `palimpsests.audit.testing` — damaged chains for a consumer's tests
  (§6).

Anything whose name begins with an underscore is not part of this
surface, `PalaWriter._emit` included.

## 2. A chain's life

```python
from palimpsests.audit.pala_writer import PalaWriter

with PalaWriter("audit.pala") as w:        # a new chain: the file is absent or empty
    w.genesis()                            # first, once
    w.boot()
    ...

with PalaWriter.open_existing("audit.pala") as w:   # the same chain, later
    w.boot()                                        # first after every resume
    ...
```

| Rule | What happens otherwise |
|---|---|
| `PalaWriter(path)` starts a chain; the path is absent or empty | `ValueError` on a file that holds records — a second `GENESIS` would corrupt it |
| `genesis()` is the first record and only the first | `RuntimeError` |
| `PalaWriter.open_existing(path)` resumes; the file holds records | `ValueError` on an empty file |
| `boot()` is the first record after a resume — the cross-boot link (core §4.2) | `RuntimeError` |
| one writer per chain, across processes | `ChainLocked`, before anything is read or written |
| `close()`, or leaving the `with` block, releases the file and the lock | the lock is held until the process ends |

The lock is a file beside the chain (`<path>.lock`; for a rotated chain,
one lock for all its segments). It is why two `palimpsests serve`
processes on one directory refuse instead of forking the chain.

## 3. Writing records

Every method writes **one record**, and the record is in the file — and,
under the default durability, on stable storage (§4) — when the method
returns. Each returns that record's **hash** (32 bytes) —
except `session_start`, which returns the session's **span id**
(16 bytes), the value its records and `session_end` are scoped by.

| Method | Record type | Kind |
|---|---|---|
| `genesis` | GENESIS | — |
| `boot` | BOOT | — |
| `session_start` | SPAN_START | — |
| `session_end` | SPAN_END | — |
| `model_load` | EVENT | MODEL_LOAD |
| `model_unload` | EVENT | MODEL_UNLOAD |
| `kv_save` | EVENT | KV_SAVE |
| `kv_restore` | EVENT | KV_RESTORE |
| `prefix_copy` | EVENT | PREFIX_COPY |
| `prefix_warm` | EVENT | PREFIX_WARM |
| `tool_call` | EVENT | TOOL_CALL |
| `tool_result` | EVENT | TOOL_RESULT |
| `tools_offered_no_call` | EVENT | TOOLS_OFFERED_NO_CALL |
| `recovery_truncated_tail` | EVENT | RECOVERY_TRUNCATED_TAIL |
| `guard_prefix_release` | SAFETY | GUARD_PREFIX_RELEASE |
| `guard_state_reject` | SAFETY | GUARD_STATE_REJECT |
| `guard_tool_loop_limit` | SAFETY | GUARD_TOOL_LOOP_LIMIT |
| `incident_candidate` | SAFETY | INCIDENT_CANDIDATE |
| `oversight_ack` | SAFETY | OVERSIGHT_ACK |
| `aggregate` | AGGREGATE | — |
| `shed` | SHED | — |
| `anchor` | ANCHOR | — |
| `key_shred` | KEY_SHRED | — |

- **`return_seq=True`**, on the methods a later record refers back to
  (`tool_call`, `incident_candidate` and the three guards), returns
  `(seq, record_hash)` — the seq read under the lock that wrote the
  record. Do not compute it as `writer.seq - 1` afterwards: another
  thread's record may be in between.
- **Referring back.** `tool_result(call_seq, call_hash, …)` and
  `oversight_ack(candidate_seq, candidate_hash, …)` name an earlier
  record by seq and hash. The writer does not check that the record
  exists; the reader does, and reports what does not resolve as an
  advisory.
- **Metadata only.** Bodies carry digests, counts and short `detail`
  references — never prompt or completion text. Bodies are cleartext
  (`key_id` 0); this writer has no encryption path.
- **Arguments.** Parameters after the first few are keyword-only. A
  release may add a keyword parameter with a default; it does not remove
  or reorder one, or change a default's meaning.

Reading the writer: `head` / `head_hex` (the last record's hash), `seq`
(the next seq), `path`, `boot_id`, `recovered_tail_bytes`, `durability`
(the policy in force), and
`chain_root()` — the derived root over every record from seq 0, or
`FrontierUnavailable` when the writer resumed on a later segment with no
recorded frontier and so cannot state it.

## 4. What the writer guarantees — and what it does not

**It guarantees:**

- **What it writes verifies.** A chain written only through these methods
  is consistent (`AuditReader.is_consistent()`, `pala verify`), record
  after record. The writer builds every record with the same codec an
  independent verifier reproduces from the specification; it holds no
  byte layout of its own.
- **Thread-safe within a process.** One lock guards the seq, the head and
  the file: concurrent threads cannot interleave two records or fork the
  link.
- **A record is whole or absent to the next writer.** `open_existing`
  scans the file; a torn trailing record — bytes of a record that was not
  finished — is truncated, `recovered_tail_bytes` says how many, and
  `recovery_truncated_tail()` records that it happened. Pass
  `recover_torn_tail=False` to refuse instead.
- **A record that was returned survives a loss of power** — under the
  default, `Durability.RECORD`. See below.
- **A stop that was not a close shows, once the chain goes on** (since
  0.15, inference profile r8). See "The writer's own two records".

### The writer's own two records

A writer writes two records nobody asked it for (inference profile r8,
§3.3):

- `WRITER_OPEN`, directly behind the first `GENESIS` or `BOOT` it
  writes. Its detail names the release that wrote it.
- `WRITER_CLOSE`, as its last record, in `close()`.

A chain that simply stopped used to say nothing about why. Now a boot
that opened and was followed by another boot either ends with
`WRITER_CLOSE` or was stopped without being closed — a crash, a kill, a
power cut — and a reader reports it (`boot_ended_without_close`, an
advisory: the chain is whole either way).

What follows from it:

- **Record counts and seqs move.** `genesis()` returns the hash of the
  `GENESIS` record, and the chain has grown by two records by the time it
  returns. Take a seq from `return_seq=True` or from `seq`, never by
  counting calls.
- **The head of a closed chain is the hash of `WRITER_CLOSE`.** `head`
  and `seq` stay readable on a closed writer. A head read while the
  writer ran, and anchored, is the anchor of a chain one record shorter:
  the closed file extends beyond it and is not complete against it.
  **Anchor after the close.** `palimpsests serve` prints the closing head
  when it stops.
- **`close()` is the only orderly end.** A `with` block calls it, on an
  exception too: `WRITER_CLOSE` says the writer was closed, not that the
  work succeeded.
- **The last boot of a file is never judged** — its writer may be
  writing still. A writer stopped for good and never resumed looks like
  one still running; only something outside the chain tells them apart.
- `PalaWriter(path, lifecycle=False)` writes neither record, and its
  boots are judged by nobody. It exists for a chain that must match one
  written before 0.15 record for record; a deployment has no reason to
  use it.

### Durability: when a record is on stable storage

A record handed to the operating system is in the file and not yet on
the disk; the kernel writes it out when it chooses — on Linux, by
default, within about half a minute. Until then a loss of power takes
the record with it, and what is left is a shorter chain **that
verifies**. Whoever can cut the power — by accident, or on purpose,
right after an action they would rather not have recorded — removes the
last records without a trace. `PalaWriter(path, durability=…)` decides
how long that window is:

| Policy | What a returned record has | A power loss can take |
|---|---|---|
| `Durability.RECORD` — **the default** | been synced to stable storage | nothing that was returned |
| `Durability.group(max_delay_s)` | been written; synced within `max_delay_s`, also when nothing follows | the records of the last `max_delay_s` |
| `Durability.OS` | been handed to the kernel | whatever the kernel had not written out — typically up to half a minute |

- **The cost** is one sync per record under `RECORD`: hundreds of
  microseconds to a few milliseconds, depending on the disk. Tool calls
  and safety events arrive a few per second, not thousands. A writer on a
  hot path chooses `group` or `OS` deliberately.
- **`palimpsests serve`** uses `RECORD`, and takes another policy from
  `PALIMPSESTS_AUDIT_DURABILITY` (`record`, `group`, `group:<seconds>`,
  `os`). A value it cannot read stops it: a typo does not become the
  weaker setting. A relaxed policy is announced at start-up, stated by
  `GET /v1/pala/status` (`chain.durability`) and flagged by
  `palimpsests doctor` (`serve_durability_relaxed`).
- **On the serve's own path a tool call is synced before the client is
  told of it**: the response that carries the call is built after the
  record is written. A client's *report* (hooks, events) comes after the
  fact; what is promised there is that a report answered 200 is on stable
  storage.
- **A sync that fails raises.** The record is in the file and the writer
  has moved past it — it must, or the next record would fork the chain —
  and the caller learns that durability was not confirmed.
- A cut syncs the segment it leaves, the manifest and the names of both
  before the writer moves on. `close()` syncs what is not yet synced.
- On macOS the sync is `F_FULLFSYNC`, which asks the drive to flush its
  own cache; plain `fsync` there does not.

**It does not guarantee:**

- **A disk that lies.** Some drives and virtual disks report a sync as
  done while the data is still in a volatile cache of their own. No
  software above them can tell. Know the storage the chain is on.
- **Anything against whoever can write to the file.** They need no power
  switch: they truncate it. What finds that is an anchor kept outside
  the host — the head as it was, where the host cannot rewrite it. With
  `RECORD` and an outside anchor, a cut of the power removes nothing, and
  a truncation is found.
- **That a stop was clean.** The chain does not say whether the previous
  run ended in `close()` or in a loss of power: the next `BOOT` looks the
  same. Under `RECORD` nothing returned is missing either way; under the
  other policies a reader cannot tell that records may be.
- **The record of something that was never written.** A process killed
  between an action and its record leaves no record. On the serve's own
  path the call is recorded before the client can act on it, and a call
  with no result is reported (`tool_call_unanswered`).
- **Truthful time.** `time_trust` defaults to *unsynced*: a wall-clock
  time is recorded and no claim is made for it. Pass a stronger value
  only where the deployment knows its clock is synchronized; an
  unjustified one is a verification violation (core §5).
- **Two processes.** One writer per chain. A second is refused, not
  queued.
- **`merkle_checkpoint` against a concurrent write.** Call it from the
  context that writes.

## 5. Segments

`PalaWriter(path, rotation=RotationPolicy(max_records=…, max_bytes=…,
max_age_s=…, retention_s=…))` cuts the chain into segments as it writes;
`rotate(next_path)` cuts once by hand.

- A cut falls between records, never inside one, and never inside a span
  this writer opened: a due cut waits for the span to close.
- Every segment after the first opens with a `SEGMENT_CONTINUATION`
  record, and the writer keeps `<path>.segments.json` beside the chain
  (`docs/specs/segments/pala-segments-1.md`).
- `retention_s` is a declaration written into the chain, not
  enforcement: the writer deletes nothing.
- `RotationPolicy` needs at least one threshold; an empty one is refused.

## 6. Chains for tests

A consumer's tests need two kinds of chain.

**Well-formed ones** come from the writer: the methods of §3 on a
temporary path. The published vectors
(`palimpsests.audit.pala.vectors`) are the other source, and the better
one where a fixed, known chain will do — they do not change.

**Damaged ones** the writer cannot produce, and a consumer should not
have to rewrite bytes at offsets copied from the specification.
`palimpsests.audit.testing` takes the bytes of a well-formed chain and
returns the bytes of a damaged one — one small named defect per function
— and `DAMAGE` states what the reader reports for each:

| Builder | The reader's diagnosis | Consistent |
|---|---|---|
| `alter_body` | none — the header chain still verifies; the body mismatch is in `container_check()` | no |
| `break_link` | `chain_break` | no |
| `violate_must` | `record_violation`, code `time_trust_undefined` | no |
| `remove_record` | `seq_gap` | no |
| `drop_first_records` | `prefix_absent` | no |
| `drop_last_records` | none without an anchor; `replaced_or_rolled_back` against the earlier head | yes |
| `cut_mid_record` | `truncated_tail` | no |
| `not_a_container` | `not_a_container` | no |

The expectations are part of this surface: a release that changes what
the reader says about one of these changes this table, the test that
holds it, and the changelog.

## 7. Not on this surface

- `palimpsests.audit.log.AuditLog` — the SQLite audit log of the
  inference library's own calls. A different log with a different
  format; not PALA-1.
- The server's recording paths (`palimpsests serve`'s routes, the hook
  ingest). They use this writer; their own contract is the HTTP surface.
- Encryption of bodies, key management, and `KEY_SHRED`'s effect on
  keys: the writer records that a key was destroyed; it holds no keys.
