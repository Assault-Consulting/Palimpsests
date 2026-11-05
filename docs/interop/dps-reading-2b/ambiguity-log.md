# Ambiguity log

Only places that are not in reading 2's log (A01 to A27), or that this run reads differently. "-08" is draft-fassbender-scitt-time-anchor-08. Numbered B01 onwards so as not to collide with reading 2's A-numbers. "Tested" names the runs that the choice decides; "untested" means no run here distinguishes the readings.

Reading 2's entries this run depends on are read as reading 2 read them: A01 (the `.ots` grammar, from outside the text), A09 (internal byte order; step 8 compares header bytes 36 to 67 with the replayed digest as they are) and A27 (this reader holds no validated chain). A27 is not read differently: where a run below supplies a header set as `validated_chain`, the set is a test fixture declared validated for the test, and the record says so each time.

## The Proof Bundle (-08 §2.2, §3.4.3, §4.1 Input)

**B01. Which data model the bundle is in.** §3.4.3 gives CDDL, which describes CBOR and JSON data models, and says so. `ots_proof` is `bytes`, for which JSON has no type without a further convention.
Readings: (a) CBOR; (b) JSON with an encoding of the bytes the text does not give; (c) an in-memory structure with no encoding.
Chosen: (a). The bundle is a CBOR map with text-string keys (CDDL barewords), encoded deterministically (cbor2 `canonical=True`), and decoded by the verifier before step 1. Digests of each bundle are in `out/final/bundles.json`. Untested: no run's verdict depends on the encoding.

**B02. Values the text does not fix for the vectors.** Appendix D prints no bundle.
- `claimed_hash`: D.1's printed hash of the artifact (the SHA-256 of the `.txt`, checked equal), with the `sha256:` prefix. §2.2 and §3.4.3 allow it with or without. Tested both ways: P1 and P2 with the prefix, A2 and A3 without; the verdicts are the same.
- `origin_id`: omitted. The CDDL marks it optional and §2.2 says it is not used in verification; §4.1's Input line (`ots_proof (.ots), claimed_hash, origin_id`) lists it without marking it optional. Untested.
- `bitcoin_block_height`: omitted. The CDDL marks it optional and §2.2 says it is not used; §4.1's Input line does not list it, and no step reads it. Untested; what a verifier does when it disagrees with the attested height is not said.

**B03. `claimed_hash` in D.6's first vector.** D.6 states "Modified artifact" and "Original proof" and expects invalid at step 2. It does not state the bundle's `claimed_hash`. Step 2 returns invalid only where `claimed_hash` differs from the hash of the bytes presented.
Readings: (a) the bundle of the unmodified pair (`claimed_hash` = D.1's hash): step 2 decides; (b) a bundle whose `claimed_hash` is computed from the bytes presented, as a holder that builds the bundle from the artifact it holds would: step 2 passes and step 3 decides (`parsed.msg != computed_hash`).
Chosen: (a), which D.6's "step 2" implies. Tested: N1 (46,920 runs, all invalid at step 2). Reading (b) was run apart as A7 (46,920 runs, all invalid at step 3). Finding G02.

**B04. `validated_chain` in D.6's first vector.** D.6 does not say. Chosen: fixture-12 (the twelve headers of Lemonnier's file, declared validated for the test, not validated by this run), so that a run that passed steps 2 and 3 would reach step 11 and return valid. The outcome of each run then turns on steps 2 and 3 only. With no view, a run that passed steps 2 and 3 would still end unverifiable, and the vector would not distinguish. Not run with no view: step 2 returns before `validated_chain` is read, so the verdict would be the same; that is stated from the code, not computed.

**B05. A Bitcoin attestation whose payload is not a height.** OTS-ATTESTED-HEIGHT (§4.1) returns the height; its failure is not defined. Reading 2's `bitcoin_height` refuses bytes after the height and a height above 2^53 − 1 (anchoring's limit for a report). Chosen: OTS-DESERIALIZE is taken to fail on such an attestation (it yields "the attestations that terminate its branches", and the attestation cannot be read), so step 3 returns invalid. Reading 2's limit is applied unchanged; -08 states no such limit. Untested.

**B06. Which step decided an unverifiable result reached through step 7b.** In §4.1 the RETURN is at step 8 (`unevaluated IS NOT EMPTY`); D.6 states the result as "unverifiable (Section 4.1, step 7b)" and explains "step 7b returns NULL, so step 8 leaves the branch unevaluated". Chosen: both are recorded. `return_step` is 8; `decided_by_step` is 7b (or 5, for a branch left unevaluated by step 5). Comparisons with the expected step use `decided_by_step`.

## The validated view (-08 §4.1, validated_chain, VALIDATE-HEADER-ON-CHAIN, CONFIRMATIONS-ON; D.6)

**B07. Whether "a validated header set that does not reach the attested height" covers the eleven headers 957290 to 957300.** D.6's second vector. VALIDATE-HEADER-ON-CHAIN "returns candidate where validated_chain establishes that the block header at height H is exactly those 80 bytes, and NULL in every other case, including where the view does not reach height H".
- "Reach", read with validated_chain's own definition (validated "from the genesis block or from a checkpoint it holds"), describes a view's extent from its start upwards: a view reaches H when it extends to H. The set 957290 to 957300 extends past 957289 and does not include it. The phrase does not describe it literally: it neither stops short of H nor reaches it.
- Whether the set "establishes" the header at 957289 has two readings. (a) A view establishes a header at H only by holding a header at H; this set holds none, so step 7b returns NULL and the result is unverifiable. (b) A view validated from 957290 holds, in 957290's previous-block field, the double SHA-256 of the header at 957289; a candidate whose double SHA-256 equals it is, under second-preimage resistance, "exactly those 80 bytes". Step 7b then returns the candidate, step 8 verifies, CONFIRMATIONS-ON counts 12 (or 11 if only held headers count; either is at least 6), and the result is valid.
Chosen: (a). Tested: N2b (four runs, unverifiable at step 7b). Reading (b) was run apart as A1: valid for all four, on a header set declared validated for the test and not validated by this run. Answer to the question asked: the phrase "does not reach the attested height" does not, by its words, cover this set; the verdict D.6 expects follows for this set under (a) and not under (b). Finding G01.

**B08. CONFIRMATIONS-ON over a stored header set.** "the number of blocks validated_chain establishes at height H and above, counting the block at H itself"; a verifier with a stored set "obtains it from the extent of that set". Chosen: the number of consecutive heights from H held in the set (under B07(b), the header established through H+1 is counted too). Tested: A5 (957289 to 957293, k = 5, unverifiable at step 9) and A6 (957289 to 957294, k = 6, valid), both on header sets declared validated for the test and not validated by this run.

**B09. An empty validated view.** "A validated header set that does not reach the attested height, or none at all": a view that holds nothing is a view (not "none at all") and does not reach H. Chosen: step 7b returns NULL. Tested: A4 (four runs, unverifiable at step 7b).

**B10. Where step 7a's candidates come from.** FETCH-BLOCK-HEADER-BY-HEIGHT reads "from whatever source the verifier uses", subject to the exclusion of the anchoring service. Chosen: Lemonnier's `headers-957289-957300.json`, which `headers-sources.json` attributes to two block explorers. This run has not established who produced the file beyond what it states. The fixtures are drawn from the same file, so in P2, A3, A5 and A6 step 7b compares bytes with themselves: those runs exercise the code path of steps 7b to 11, not the provenance of the header.

## The verifier's handling of inputs the text does not cover

**B11. A bundle that does not match the CDDL.** §4.3: the procedure "MUST return exactly one of valid, invalid or unverifiable"; §3.4.3 does not say what a verifier does with a bundle that does not match. Chosen: the procedure is not run, and the harness records the run as not attempted with the reason. The CDDL `.regexp` is applied to the whole string (CDDL's regular expressions are anchored; RFC 8610 applied from knowledge, not fetched), and members the CDDL does not define are refused (a CDDL map is closed unless it says otherwise). Untested: every bundle built here matches.
