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
  - **The digests over JSON values use RFC 8785** (JCS, §11): tool arguments
    and results (`EVT_PAYLOAD_DIGEST`) and the engine's configuration
    (`ORIGIN_CONFIG_DIGEST`). `palimpsests.audit.canonical_json` implements
    it, stdlib only, tested against the RFC's own samples.
  - Issues 3 and 5 are recorded as closed: the add-never-renumber rule, and
    `ok` as a return and not a confirmed effect.
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
- **`ORIGIN_CONFIG_DIGEST` is computed by a new rule.** It was SHA-256 over
  `key=value` lines with each value as Python's `str()` printed it —
  reproducible only from Python, and not canonical for a nested value. It is
  SHA-256 over the configuration as one RFC 8785 object. **Every
  configuration digest differs from the one 0.14 wrote for the same
  configuration**, so a chain that spans the upgrade shows a new origin at
  it. Digests written before compare among themselves, under the earlier
  rule, which the profile records.
- **`EVT_PAYLOAD_DIGEST` is pinned to RFC 8785.** It was SHA-256 over what
  `json.dumps` printed with sorted keys. For a value with no float and no
  key outside the Basic Multilingual Plane that is the same bytes, and the
  digest is unchanged. With a float it differs: `1.0` was digested as `1.0`
  and is digested as `1`, as every other JSON implementation writes it. An
  integer beyond 2^53 is digested as the double nearest to it. A value with
  NaN or an infinity is refused with `ValueError`.
