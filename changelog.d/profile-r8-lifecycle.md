### Security

- **A writer stopped without being closed is visible** (inference profile
  r8). A crash in the middle of a record left a torn tail, which a resumed
  writer records; a stop *between* two records — a kill, a power cut, which
  can be someone's choice — left no trace. The writer now writes
  `WRITER_OPEN` behind its first `GENESIS` or `BOOT` and `WRITER_CLOSE` as
  its last record, and the reader reports a boot that opened, was followed
  by another boot, and does not end with a close: advisory
  `boot_ended_without_close`. The chain is whole either way; the verdict
  does not change. The last boot of a file is not judged — its writer may
  be writing still.

### Added

- **Inference profile r8:** `EVENT` kinds 12 (`WRITER_CLOSE`) and 13
  (`WRITER_OPEN`), §3.3. `KIND_WRITER_CLOSE`, `KIND_WRITER_OPEN` and the
  advisory code in the reader. `WRITER_OPEN` names the release that wrote
  the boot. `inference-vectors.json` gains a second boot, opened and closed
  (27 records; every earlier record byte-identical).
- `PalaWriter(..., lifecycle=False)` writes neither record.

### Changed

- **Every chain a writer writes is two records longer per writer run**, and
  record counts and seqs move accordingly: `GENESIS` is followed by
  `WRITER_OPEN`, and `close()` appends `WRITER_CLOSE`.
- **The head of a closed chain is the hash of its `WRITER_CLOSE`.** A head
  read from a running writer — or from `GET /v1/pala/status` — and then
  anchored is the anchor of a chain one record shorter: the closed file
  extends one record beyond it and is not complete against it. Anchor after
  the close. `palimpsests serve` prints the closing head when it stops;
  `head` and `seq` stay readable on a closed writer.
- The companion vectors hold two boots.
