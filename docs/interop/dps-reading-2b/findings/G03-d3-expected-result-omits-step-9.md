# G03. D.3's expected result omits the confirmation-depth condition of step 9

For: the draft's author (draft-fassbender-scitt-time-anchor-08, Appendix D.3). Not filed, not sent.

**Minimised.** Vector 1, unmodified, with its bundle, and as `validated_chain` the five headers 957289 to 957293 of Lemonnier's headers file, declared validated for the test (this run validated nothing). Step 7b returns the header at 957289, step 8 classifies the branch verified, step 9 finds k = 5 < MIN_CONFIRMATIONS = 6: **unverifiable at step 9**. With six headers (957289 to 957294): **valid**. The same for vectors 2 to 4 (runs A5 and A6).

**What the text says.** D.3: "Expected VERIFY-ANCHOR result: valid, for a verifier that has placed block 957289 on the validated most-work chain; otherwise unverifiable (Section 4.1)". §4.1 step 9 and its note: step 9 is required, and a verifier that cannot establish six blocks at H and above returns unverifiable.

**Where the fault seems to be.** D.3's summary sentence. §4.1 and §4.3 (Table 5) state the condition; D.3 states a verifier that places block 957289 returns valid, and the run above places it and returns unverifiable.

**Draft note.** "D.3 could read: 'valid, for a verifier that has placed block 957289 on the validated most-work chain and establishes at least MIN_CONFIRMATIONS (6) blocks at 957289 and above (Section 4.1, step 9); otherwise unverifiable.' As written, a verifier holding a validated view that ends at 957293 meets D.3's condition and, per step 9, returns unverifiable."
