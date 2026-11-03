### Added

- **`AuditReader.record_fields_at(index)` and `RecordFields`** (U29): a
  record's `kind`, `source` and `outcome`, with their names, read in place —
  the values `record_at(index)` gives, without decoding the record or keeping
  anything. For consumers that filter by kind, evidence mark or tool outcome.

### Changed

- **`verify()` decodes nothing on a cold reader** (U28). On an agent's log
  every tool result references its call, so the referential pass decoded —
  and kept in the sparse cache — the whole chain: measured by Auditor at
  32.5 s and 2.47 GB on a million records. References are now read in place
  (the reference, the target's header hash and its kind). On 200,000 records
  of tool loops: 5.8 s / 513 MB before, 1.7 s / 97 MB after. The advisories
  are the same as the decoded path's, which a reader whose chain is already
  decoded still takes; a differential test holds the two together.
