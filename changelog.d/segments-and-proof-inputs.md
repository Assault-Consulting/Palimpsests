### Fixed

- **A damaged segment is an answer, not an exception.**
  `verify_segment_set` raised `MalformedRecord` when a segment of the set was
  cut in the middle of a record, though everything but "not a manifest" is
  meant to be an answer. It now reports that segment as not verified, says
  why, and judges the others on their own.
- **`verify_segment_set` does not follow a manifest entry that names a
  path.** An entry whose `file` is not a plain file name — a directory above,
  an absolute path — is not read, and the set is not called consistent on
  the strength of it.
- **`pala segment` looks before it cuts.** A source cut in the middle of a
  record made it fail after writing the segments before the cut — files on
  disk and no manifest. It now walks the source first and refuses, writing
  nothing (exit 3). And it printed `every segment verifies alone` whatever
  the source was; it now verifies the set it wrote and says so only when it
  holds — a chain that does not verify is still segmented faithfully, and
  the command says that the segments do not verify.
- **A consistency-proof document of the wrong shape is one error.**
  `ConsistencyProof.from_json` raised `KeyError`, `TypeError` or
  `AttributeError` depending on what was wrong, and read `2.7` as 2 and
  `true` as 1. It raises `ValueError` for anything not of the format's shape
  and coerces nothing; `pala consistency-verify` exits 3 instead of printing
  a traceback for JSON that is not an object. A well-shaped document that
  does not hold still reads and verifies `False`.

### Documentation

- **`pala-segments/1` has a specification**,
  `docs/specs/segments/pala-segments-1.md`: its two writers and how their
  manifests differ, every key, what a reader checks and what it does not
  follow. The format is declared open to added keys. `consistency-proof.md`
  now separates a document that is not of the format's shape from one that
  is and does not hold.
