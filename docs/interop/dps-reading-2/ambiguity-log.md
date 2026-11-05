# Ambiguity log

Every place where the text admits more than one reading, or says nothing where this reading had to choose. "Anchoring" is extensions/anchoring/README.md at `007f8c9`; "-08" and "-03" are draft-fassbender-scitt-time-anchor. "Tested" names the cases that fix the choice; "untested" means no case or vector distinguishes the readings.

## OpenTimestamps proof format

**A01. The byte grammar of a `.ots` proof.** -08 §1.3 ("the proof format is not specified in this document"), §4.1 (OTS-DESERIALIZE, "whose input format this profile does not specify"), §7.2.1 and D.7 route 2; -03 §1.4 and §1.5 say the same. -08 Table 4 gives the tags 0x08, 0xf0, 0xf1 and the Bitcoin attestation tag `0588960d73d71901`. Anchoring adds limits and "the magic, version 1, the file hash sha256 and its 32 bytes ... then a tree of operations leading to attestations". Neither states the magic's bytes, that the version and lengths are LEB128 varints, that an argument is length-prefixed, that 0xff precedes each branch but the last of a fork, that 0x00 precedes an attestation, that an attestation is an 8-byte tag and a length-prefixed payload, or the pending tag `83dfe30d2ef90c8e`.
Readings: (a) the text is not enough to parse a proof; (b) the grammar is to be taken from the OpenTimestamps release -08 pins.
Chosen: both are reported. The parser applies the grammar from this reading's knowledge of the OpenTimestamps format, without reading any implementation or the pinned release, and holds it against the bytes of -08 D.5 and the trace of D.4. Every D.4 statement checked held for all four proofs (`out/ots-replay.json`). Answer to the question under test, for this part: the text alone is not enough; findings F03 and F04.

**A02. Nesting depth.** Anchoring: "at most 256 nested timestamps". Which timestamp counts as the first is not said. Chosen: the top timestamp is level 1; a level above 256 is refused. Tested only above the limit (T81, 300 levels).

**A03. Which operations `operations` covers.** Anchoring: "It replays the operations ... any other operation ... is reported not_supported"; report schema: "Every operation on the way". -08 §4.1: a branch with another operation is unevaluated, one verified branch suffices. Readings: the whole tree, or the paths to a Bitcoin attestation. Chosen: the paths to a Bitcoin attestation; verified when at least one such path has only sha256, append and prepend; with no Bitcoin attestation, any operation in the tree. T76 agrees under both; the difference is untested.

**A04. Several Bitcoin attestations, some headers missing, none matching.** Anchoring says which block is reported when one matches, not what holds when none does. Chosen as -08 step 8: unavailable when any branch was not evaluated (header missing), failed only when every branch was evaluated and none matched. Untested.

**A05. A proof with neither a Bitcoin nor a pending attestation** (only kinds the check does not know). Chosen: `attestation` failed. Untested.

**A06. Bytes after the height in a Bitcoin attestation's payload.** Chosen: refused (attestation failed). Untested.

**A07. `subject_bytes` when the proof cannot be read.** The schema describes the check as including "the proof starts from their SHA-256". Chosen: when the proof is not read, `subject_bytes` is the naming check alone. T77 to T81, T84, T87, T94, T96, T97 expect it verified by default; they fix this choice.

**A08. -03 and -08 describe 0x08 differently.** -03 Table 4: "Implicit: SHA-256 (OTS magic byte 0x08)"; -08 Table 4: "File hash operation in the proof header: SHA-256 (0x08)". Chosen: -08's; the bytes have the magic, then the version, then 0x08 and the 32-byte digest.

**A09. D.4 prints values in which byte order.** "43 sha256 -> 3cad384e... (transaction id)": a transaction id is usually shown reversed. The value after operation 43 in internal order starts `3cad384e`; reversed, it does not. Operations 2 (`aafc3638`) and 82 (`81383c9c`) are also printed in internal order. Chosen: internal order throughout.

## The anchoring check

**A10. Precedence of statuses in one dimension.** The text says when a dimension is verified, not which of failed, unavailable, not_supported and not_checked wins. Chosen: failed, then unavailable, then not_supported, then not_checked. Fixed by K106 (signature not_supported, receipt unavailable, status unavailable), T75 and T76.

**A11. The signature check of a checkpoint not from a configured source.** "key_ref is a key in the trust policy, listed for that source": a checkpoint from a source the policy does not configure (K23) or found in the export (K10, K44) has no such source. Chosen: the rule for a checkpoint beside the export (a witness key the policy lists for a source it configures for the chain the verifier checks). K10, K23 and K44 expect the signature verified.

**A12. The scope of "one reference names one entry".** Within each list, or across lists (a `tsa_ref` equal to a `key_ref`)? Chosen: within each of `tsas`, `keys`, `checkpoint_sources` and `bitcoin_header_sources`. K57 tests sources; across lists is untested.

**A13. The scope of "one public key listed twice".** The keys list only, or also the keys of pinned TSA certificates? Chosen: the keys list. Untested (K60 uses a key no pinned certificate holds).

**A14. Strict CBOR and null.** "refuses ... a float or a simple value", but a receipt's detached payload is nil, a simple value, as RFC 9052 writes it. Chosen: null is read; every other simple value and every float is refused.

**A15. Several inclusion proofs under label 396, key -1.** The text gives one `[tree-size, leaf-index, path]`. Chosen: the first is used. Untested.

**A16. Independence when the chain cannot be read.** "configured for the checkpoint's chain_id": a source that gives nothing (K25) or a statement that cannot be read (K109 to K114, K125) has none. Chosen: the source is judged for the chain the verifier checks. Change C02.

**A17. The receipt when the statement is not read.** "The receipt is reported whatever the witness's signature says", yet K109 to K114 and K125 expect the receipt not_checked. Chosen: not_checked when the statement or its payload is not read; checked (or unavailable when none is held) otherwise, including when the payload's values are refused (K128 to K130, K132).

**A18. The receipt of a statement given by a source that is not SCITT** (K116, K117). Text silent. Chosen: not_checked, as the cases expect.

**A19. The order of the receipt's key checks.** Chosen: the key exists, is in role transparency_service, is listed for the source, is listed under Ed25519, then revocation (any reason: unavailable). K98, K99, K121, K140, K141 fix the parts they test.

**A20. Which checkpoints "the verifier holds" for a timestamp over a signature value.** Chosen: those obtained from sources and those beside the export, each counting only when its signature verifies with the key the policy lists for its key_ref (T63 to T66). A held checkpoint carrying the value but named otherwise fails the subject (T26); no holder carrying the value leaves it not checked (T25, T64).

**A21. What a pairing reader calls consistent.** "checks the counts, the digests, and that each dimension reported as verified is verified". Portable verification says a report may say less; anchoring does not. Chosen: the reader recomputes the report and compares every member but `findings`, with types (0 is not 0.0, J29 to J31); `attachment_index`, which a result "MAY also name", is compared only where the report names it (J39, J49).

**A22. A superseded key with an independent timestamp.** Chosen: the time is the earliest T, which must be before `revoked_at` (as portable verification 0.3.0 has it, G35); `not_before` is still read from the stated time. K30 tests the verified side only.

**A23. A token's algorithm labelled rsaEncryption with digest SHA-256.** Text: "RSA PKCS#1 v1.5 (RSASSA-PKCS1-v1_5) ... with SHA-256". Chosen: accepted as that. Untested (the vectors label sha256WithRSAEncryption).

**A24. The issuer's time for a chain link when one entry's time cannot be read.** Chosen: not checked. Untested.

**A25. Instant format with a fraction.** The report's instant pattern allows a fraction; its form is not fixed. Chosen: microseconds with trailing zeros removed, none when zero. Untested.

**A26. The default for an OpenTimestamps result's issuer time in the timestamp cases.** cases.json "about": "every check, the timestamp and the issuer's time are expected verified unless expected says otherwise"; for an OpenTimestamps result the schema fixes `issuer_time` to not_checked. Chosen in the harness: not_checked for OpenTimestamps results.

## The replay against draft -08

**A27. What counts as validated_chain.** -08 §4.1: "a header set whose proof-of-work the verifier has itself verified from the genesis block or from a checkpoint it holds". The header file comes with the proofs; this reader holds no checkpoint at 957288 or earlier, and verified proof of work and linkage from 957289 only. Chosen: step 7b not established, so -08's VERIFY-ANCHOR returns unverifiable for all four proofs; steps 1 to 6 and the step 8 comparison are reported separately, against the supplied header as a candidate.
