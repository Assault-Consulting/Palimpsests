### Added

- **A segment check says what the manifest declares of the segment:**
  `SegmentCheck.declared_first_seq`, `declared_last_seq` and
  `declared_head`, for every listed segment, present or not. A segment
  deleted under retention was reported by file name alone; the records it
  held and its head are in the manifest, and are now passed on as declared.
- **Live reading is a declared channel, provisional:**
  `palimpsests.audit.tailing.TailingReader`, `TailEvent` and the new
  `TAIL_EVENT_KINDS` are channel 9 of `docs/INTEGRATION-SURFACE.md`, under
  the contract test. "Provisional" is a stability class introduced with it:
  the surface may change in a minor release, named in the changelog. It
  becomes public, or says why not, before 1.0.
