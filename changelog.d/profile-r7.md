### Added

- **Inference profile r7.** Additive, and the profile's open issues closed.
  - **`EVT_SOURCE` value 2, `derived-from-telemetry`:** a tool pair written
    from an exported telemetry span. `SOURCE_DERIVED_FROM_TELEMETRY` in the
    writer and the reader; `source_name` gains the name. Value 0 is still
    written as absence, so no existing record changes by a byte.
  - **`MERKLE` records are defined for the profile** (§10): a checkpoint
    whose leaves are the record hashes since the previous checkpoint, that
    one included. This is what `merkle_checkpoint` has written since 0.10;
    the profile said until now that an inference chain should not emit one.
  - Issues 2, 3 and 5 are recorded as closed: the config-digest rule, the
    add-never-renumber rule, and `ok` as a return and not a confirmed effect.
  - `inference-vectors.json` gains three records (24 in all); every earlier
    record is byte-identical. The core vectors are untouched.

### Changed

- **A pair recorded from an OpenTelemetry span is marked
  `derived-from-telemetry`**, not `reported-by-client`. A span is exported
  after the tool returned and carries the call and its outcome together, so
  the pair's place in the chain is when the export arrived, not when the
  call was made — which a reader could not tell from the mark it had.
  Records already written keep value 1. `source_name` is an open
  vocabulary; a consumer that branches on exactly two names meets a third.
  `palimpsests doctor otel` accepts either mark, so it still passes against
  an older serve; the surface checker's `otel` probe expects the new one.
