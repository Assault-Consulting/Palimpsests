### Added

- **`decode_shred(record)` and `ShredView`** in `palimpsests.audit.reader`: a
  KEY_SHRED record's erasure note as fields — `reason` and `reason_name`,
  `target_seqs`, `detail`, and the destroyed `key_id` (inference profile §8).
  The published vectors have described that body since r2 and the reader
  returned none of it. It is the note as the writer declared it; whether the
  named records exist and carried that key is still what
  `shredded_targets()` and the `shred_target_*` advisories answer.
  `DecodedRecord.detail` is unchanged — it is `EVT_DETAIL` on an EVENT or
  SAFETY body and stays `None` on a KEY_SHRED.
