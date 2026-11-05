# F04. Anchoring's OpenTimestamps branch rests on a grammar the text does not name

For: the Standard's repository (extensions/anchoring/README.md, "An OpenTimestamps proof as a timestamp"). Not filed.

**Minimised.** The section says "The proof's bytes as the OpenTimestamps serialisation writes them (a .ots file): the magic, version 1, the file hash sha256 and its 32 bytes ... then a tree of operations leading to attestations". It names no specification for that serialisation and gives no bytes for the magic, the fork or attestation markers, or the pending tag; it cites "the reference library" three times (its result limit, that it keeps the last of a repeated operation, that it accepts a 20-byte height). The draft the vectors' real proof comes from does not specify the serialisation either (F03).

**Effect.** An implementer working from the extension's text and its references cannot write the strict reader it requires; every limit the section states (shortest varints, nine bytes, 4096, 8192, 256, no repeats, nothing after) applies to a grammar the reader must obtain elsewhere. This reading obtained it from knowledge of the format (ambiguity log A01); with it, the 32 timestamp cases T67 to T98, V24, V25 and J50 to J54 agree.

**Where the fault is.** The text (a missing normative reference), not a case or a vector.

**Draft note.** "The OpenTimestamps branch says the proof is read 'as the OpenTimestamps serialisation writes them' and cites the reference library for limits, but names no specification or pinned release for that serialisation. Suggest a normative reference to a pinned release (as draft-fassbender-scitt-time-anchor-08 §7.2.1 does for its own purposes), or a short grammar in the text: magic bytes, varint encoding, length-prefixed arguments and payloads, 0xff and 0x00 markers, and the Bitcoin and pending tags."
