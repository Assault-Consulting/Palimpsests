# G02. D.6's first vector: "step 2" depends on a bundle value the vector does not state

For: the draft's author (draft-fassbender-scitt-time-anchor-08, Appendix D.6, Section 3.4.3). Not filed, not sent.

**Minimised.** Vector 1's artifact with byte 0 changed from 0x64 to 0x00, the original proof, and fixture-12 as `validated_chain` (declared validated for the test, not validated by this run).
- With the bundle of the unmodified pair (`claimed_hash` = `sha256:a183f624…f30b`): **invalid at step 2**. So for every single-byte substitution of every artifact: 46,920 of 46,920 (N1).
- With a bundle whose `claimed_hash` is the SHA-256 of the bytes presented, as a holder that builds the bundle from the artifact it holds would: step 2 passes, and **invalid at step 3** (`parsed.msg != computed_hash`). So for every substitution: 46,920 of 46,920 (A7).
The verdict D.6 states holds under both; the step holds under the first only.

**What the text says.** D.6: "Modified artifact ... Original proof ... Expected result: invalid (step 2: hash mismatch)", and "This vector demonstrates the binding between artifact bytes and Anchor Proof". §3.4.3 and §2.2: `claimed_hash` "is a consistency check only ... a match establishes nothing on its own, since step 3 compares the proof with the recomputed value."

**Where the fault seems to be.** The vector's statement, not the procedure: it names the proof but not the bundle, and attributes to step 2 a binding that §3.4.3 places at step 3.

**Draft note.** "D.6's first vector gives the modified artifact and the original proof but not the bundle's claimed_hash. With the original claimed_hash the result is invalid at step 2; with a claimed_hash computed from the modified bytes it is invalid at step 3, and the binding of artifact to proof is that step-3 comparison (§3.4.3). Suggest stating the bundle in the vector (claimed_hash = the D.1 hash of the unmodified artifact), or expecting 'invalid (step 2, or step 3 where claimed_hash matches the modified bytes)'. Separately: the vector's 'necessarily invalid for any other byte sequence' rests on Assumption A1; single-byte changes are what the vector exercises."
