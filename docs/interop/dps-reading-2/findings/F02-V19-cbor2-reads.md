# F02. V19: "cbor2 reads four of them" depends on what "reads" means

For: the Standard's repository (extensions/anchoring/tests/cases.json, V19). Not filed.

**Minimised.** Of the five statements V19 lists as refused, `cbor2.loads` (cbor2 6.1.5, the pinned version) returns a value for all five. For `st_a_trailing` it returns after 329 of its 330 bytes, leaving the byte after the item unread. Counting that as read gives five, not four; counting only a decode that consumes every byte gives four.

**Where the fault is.** The case's description, which does not say how "reads" is judged. The extension's text is not involved: "bytes after the item" is refused by the check's own reader, which this reading's check does (K113).

**Effect.** V19 agrees here only under the second reading (change C05 in `out/changes.md`).

**Draft note.** "V19 says cbor2 reads four of the five refused statements. `cbor2.loads` 6.1.5 also returns for `st_a_trailing`, ignoring the trailing byte. Suggest saying that a cbor2 read counts only when it consumes the whole input (for example, decoding with `CBORDecoder` and checking the position), so that a reader reproducing V19 gets four."
