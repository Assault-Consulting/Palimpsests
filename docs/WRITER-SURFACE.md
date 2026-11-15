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

Every method writes **one record**, and the record is in the file when
the method returns. Each returns that record's **hash** (32 bytes) —
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
(the next seq), `path`, `boot_id`, `recovered_tail_bytes`, and
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

**It does not guarantee:**

- **Durability against power loss.** A record is handed to the operating
  system before the method returns (the file is unbuffered), and the
  writer does **not** `fsync` each record. A crash of the process loses
  nothing that was returned. A power loss or a kernel crash can lose the
  last records, or leave the torn tail above. A deployment that needs
  more keeps an anchor outside the host — which is what makes a lost tail
  *detectable* — and chooses its filesystem accordingly.
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
