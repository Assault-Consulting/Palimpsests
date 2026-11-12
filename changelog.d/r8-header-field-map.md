### Added

- **The fixed header's field map is in the reading surface.**
  `HEADER_FIELDS`, `HeaderField` and `FIXED_HEADER_LEN` are re-exported from
  `palimpsests.audit.reader` and held by the contract test. 0.14 gave a
  consumer a record's stored bytes and both TLV maps, but the map of the 156
  fixed bytes those spans sit after stayed in `pala.codec`, outside the
  surface — so a byte view could name every TLV and none of the sixteen
  header fields. The map has existed since 0.10; this declares it. A test
  holds it to the decoder on real records: each field unpacked from the
  stored bytes equals what `header_at` gives. Requested by Auditor.
