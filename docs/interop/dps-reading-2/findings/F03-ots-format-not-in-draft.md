# F03. The replay of the proofs cannot be done from draft -08 (or -03) alone

For: Lemonnier's repository (interop/umarise), since it concerns the replay of the proofs there. Not filed. This reading did not read that repository's README or `SPARYSH-READINGS-2026-11.md`, so it does not know what they claim; the note states only what the draft's text gives.

**Minimised.** The first byte a reader needs that the draft does not give is byte 0 of each proof: the 31-byte magic `00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294`. After it, the draft gives the meaning of 0x08, 0xf0, 0xf1 and the Bitcoin tag (Table 4), but not the version varint, the varint encoding, the length prefix of an argument, the 0xff fork marker, the 0x00 attestation marker, the attestation's length-prefixed payload, or the pending tag. -08 says so itself (§1.3, §4.1, §7.2.1: OTS-DESERIALIZE's input format "this profile does not specify"); -03 does too (§1.4, §1.5).

**What this reading did.** It applied that grammar from knowledge of the OpenTimestamps format, without reading any implementation, and held it against D.5 and D.4: the four files equal D.5's Base64 byte for byte; each parses with nothing left over; each starts from the SHA-256 of its `.txt`; each Bitcoin branch has 82 operations (D.4), passes the nonce, leaf, node and root values of D.1 and D.2, the 89-byte prepend ending `6a20` and the append `689b0e00`, and replays to `81383c9c…43ef`, the Merkle root at bytes 36 to 67 of the supplied header for block 957289.

**Where the fault is.** Neither the proofs nor the header files: the draft's scope, which leaves the parser outside it by design.

**Draft note.** "Replaying `vectors/*.ots` from draft-fassbender-scitt-time-anchor-08 alone stops at OTS-DESERIALIZE: the draft does not specify the byte grammar (magic, varints, fork and attestation markers, pending tag). A reading that applies the OpenTimestamps grammar from elsewhere reproduces every value in Appendix D for all four files. If the interop material is meant to be replayable from the draft's text, it needs a pointer to a grammar it can cite (or the grammar itself)."
