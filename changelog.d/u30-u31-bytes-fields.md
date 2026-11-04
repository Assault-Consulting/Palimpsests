### Added

- **`RecordFields.detail`** (U30): the first `EVT_DETAIL` of an EVENT or
  SAFETY body, read in place by `decode_record`'s rule — any length, so an
  empty one is `""`; UTF-8 with replacement. For a search over `detail`
  without decoding every record.
- **`AuditReader.record_bytes_at(index)` and `RecordBytes`** (U31): the
  record as the file holds it — its offset, its header (fixed part and
  TLVs) and its body, ciphertext included. `Header.decode` keeps every field
  and TLV, so an accepted header re-encodes to these bytes; for a header it
  rejects, and for every body, the stored bytes are the only view.
- **`header_tlv_spans_at(index)` and `body_tlv_spans_at(index)`** (U31):
  where each TLV sits, as `(type, value_offset, length)` from the record's
  start. `None` exactly where `header_at` is `None` (an unknown version's TLV
  area is opaque, C-4) and where `record_at(index).body_tlvs` is `None` (an
  encrypted, empty or malformed body). Requested by Auditor for its hex view.
