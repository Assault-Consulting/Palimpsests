### Security

- **A loss of power no longer removes the last records without a trace.**
  The PALA-1 writer handed each record to the operating system and never
  asked for it to be written out; the kernel does that when it chooses,
  typically within half a minute. A power loss inside that window — an
  accident, or a hand on the switch right after an action — took the
  records with it and left a shorter chain **that verified**. The writer now
  syncs every record to stable storage before the call that wrote it returns
  (`Durability.RECORD`, the default), and on `palimpsests serve` a tool call
  is on disk before the client is told of it. A cut syncs the segment it
  leaves and the segments manifest, which its crash-ordering relied on and
  did not have. On macOS the sync is `F_FULLFSYNC`.

  What it cannot cover is stated in `docs/WRITER-SURFACE.md` §4 and
  `docs/THREAT_MODEL.md` (A8): a drive that acknowledges a sync it has not
  done; whoever can write to the file, for whom an anchor outside the host
  remains the answer; and the chain still does not say that a run ended
  uncleanly.

### Changed

- **Writing a record is slower by one disk sync** — hundreds of microseconds
  to a few milliseconds, by the disk. Measured on one virtual disk, through
  the writer: 83,000 records/s with no sync, 5,100 with a sync per record,
  80,000 with `group:0.05`; a physical disk that honours the sync will be
  slower per record than this one. For a chain where that matters there are
  `Durability.group(seconds)` — a bounded window — and `Durability.OS`, the
  behaviour before 0.15.
  `palimpsests serve` takes the policy from `PALIMPSESTS_AUDIT_DURABILITY`
  (`record`, `group`, `group:<seconds>`, `os`), refuses to start on a value
  it cannot read, announces a relaxed policy at start-up, states it in
  `GET /v1/pala/status` (`chain.durability`), and `palimpsests doctor` flags
  it (`serve_durability_relaxed`).
- `PalaWriter.close()` is idempotent, and raises if its last sync fails —
  after releasing the file and the lock.
