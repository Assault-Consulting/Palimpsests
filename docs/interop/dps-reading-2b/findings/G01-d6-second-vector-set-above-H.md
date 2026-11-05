# G01. D.6's second vector does not settle a validated set that starts above the attested height

For: the draft's author (draft-fassbender-scitt-time-anchor-08, Appendix D.6 and Section 4.1). Not filed, not sent.

**Minimised.** Vector 1, unmodified, with its bundle (`claimed_hash` = `sha256:` + D.1's hash), and as `validated_chain` the eleven headers 957290 to 957300 of Lemonnier's headers file, declared validated for the test (this run validated nothing). Steps 1 to 7a pass; the candidate at 957289 is the file's header. Everything then turns on what VALIDATE-HEADER-ON-CHAIN(view, 957289, candidate) returns.
- Reading (a), a view establishes the header at H only by holding one at H: NULL; step 8 leaves the branch unavailable; **unverifiable**. (Runs N2b-v1 to v4.)
- Reading (b), the view holds 957290, whose previous-block hash is the double SHA-256 of the candidate, so the view establishes that the header at 957289 is exactly those 80 bytes: the candidate; step 8 verified; CONFIRMATIONS-ON 12 (11 if only held headers count); **valid**. (Runs A1-v1 to v4, computed only to show this reading.)
The same holds for vectors 2 to 4.

**What the text says.** D.6: "a validated header set that does not reach the attested height, or none at all" → unverifiable. §4.1: VALIDATE-HEADER-ON-CHAIN returns NULL "in every other case, including where the view does not reach height H". This set extends past 957289; it does not stop short of it. The words "does not reach" do not describe it, and "establishes" admits both readings.

**Where the fault seems to be.** The text: the vector's wording and the undefined sense of "establishes". §3.4 item 3 requires that "two conformant verifiers with the same view of the chain return the same output"; under the two readings, the same view gives unverifiable and valid.

**Draft note.** "In D.6's second vector, 'a validated header set that does not reach the attested height' leaves open a set that begins above it (for the vectors, headers 957290 to 957300). Such a set carries the hash of block 957289 in 957290's previous-block field. If VALIDATE-HEADER-ON-CHAIN may establish a header that way, VERIFY-ANCHOR returns valid for that set; if it must hold the header, unverifiable. Suggest saying which, in §4.1, and wording the vector as 'a validated header set that holds no header at the attested height' (or 'that ends below the attested height') accordingly."
