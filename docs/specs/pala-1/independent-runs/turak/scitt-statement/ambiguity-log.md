# Ambiguity log — SCITT-bridge Signed Statement run

Every place where the task file, the vector, or a standard admitted more
than one reading — including the ones resolved correctly, which the task
asks for explicitly. Nine entries. None blocked the run.

Three fed findings in [`RUN-RECORD.md`](RUN-RECORD.md): A5 → F3,
A7 → F2, and A8 is the context that makes F1 worth stating carefully.
The remaining six are places where the published material could say what
it means instead of leaving it to be inferred correctly.

---

## A1 — RFC 9943 is the reason for the task but is not on its reading list

**Where.** Task file, "Contamination boundary" against "Why it matters".

**What was unclear.** The task justifies itself by RFC 9943 — the
statement "is what a PALA-1 producer registers with a SCITT transparency
service (RFC 9943)" — but the MAY-read list names only RFC 9052, RFC
9597, RFC 8032 and RFC 8949. An implementer taking the list as
exhaustive would verify the statement as a bare COSE_Sign1 and never ask
whether it is a conformant *Signed Statement*.

**Choice made.** Read RFC 9943. The binding constraint in the task is the
MUST-NOT list, which covers repository material only; a published RFC is
the class of input the task says is under test. Every check derived from
it is labelled as such in the transcript.

**Consequence.** This is where F1 comes from. Had the list been read as
closed, the run would have reported a clean pass and missed a MUST
violation.

**Suggested resolution.** Add RFC 9943 to the MAY-read list — and say
whether conformance to it is in scope for the run, or only parse-and-
verify. The two produce different reports.

---

## A2 — the payload's schema exists only inside an English sentence

**Where.** Vector, `statement_inputs.payload_note`.

**What was unclear.** The payload map's structure and its format
identifier are given as prose: *attached CBOR map: {1: chain head (32
bytes), 2: first_seq, 3: last_seq, 4: 'pala-1/v1.0'}*. Task step 5 asks
for byte-for-byte reproduction, which requires the exact string
`pala-1/v1.0`. Every other input needed for reproduction —
`issuer`, `subject`, `chain_head_hex`, `first_seq`, `last_seq`,
`private_seed_hex` — is a structured field. This one is not.

**Choice made.** Extracted the last single-quoted token from the note by
regular expression, so the reproduction is driven by the vector's stated
input rather than by a constant typed in from the expected answer. Noted
in the verifier where this happens.

**Suggested resolution.** Give the format identifier its own field, e.g.
`statement_inputs.payload_format_id`, and keep the note as commentary.
A reproduction step should not have to parse English.

---

## A3 — the external AAD is never stated

**Where.** Vector, `expected`; task step 2.

**What was unclear.** The Sig_structure of RFC 9052 §4.4 has an
`external_aad` field. Neither the task nor the vector says whether
externally supplied data participates in this signature.

**Choice made.** A zero-length byte string, per RFC 9052 §4.4: *"If this
field is not supplied, it defaults to a zero-length byte string."* The
signature verifies under that reading, which confirms it.

**Suggested resolution.** One clause in the vector — "no external AAD" —
costs nothing and removes a guess from step 2. The guess happens to be
safe here only because a wrong one fails loudly.

---

## A4 — tagged or untagged

**Where.** Task step 1, "the message is small and tagged (CBOR tag 18)".

**What was unclear.** The task states the message is tagged, and it is.
RFC 9052 §2 also permits a COSE_Sign1 to travel untagged where the type
is established out of band, which is common in SCITT deployments. Should
a verifier reject an untagged statement, or accept it?

**Choice made.** Require the tag, since the task states it. Adversarial
case A3 records the untagged input and its rejection separately, so the
alternative reading is on the record rather than silently excluded.

**Suggested resolution.** Say whether the tag is mandatory for a PALA-1
Signed Statement or merely present in this vector. The two differ for an
implementer writing a receiving verifier.

---

## A5 — deterministic encoding is required for the task but never stated

**Where.** Vector, `expected.statement_hex` / `statement_sha256` /
`statement_length_bytes`; task step 5.

**What was unclear.** Byte-for-byte reproduction is only well defined if
the encoder's serialisation choices are pinned: shortest-form heads,
definite lengths, map key order. RFC 9052 §9 imposes exactly those
restrictions — but scopes them to the Sig_structure, Enc_structure and
MAC_structure, *not* to the COSE message. Nothing in the published
material says how the outer 202 bytes were serialised.

**Choice made.** Encoded the outer message in RFC 8949 §4.2.1
deterministic form. It reproduces the published bytes exactly, so the
choice was right — but it was a choice, and a different one would have
produced a "divergence" that was nobody's error.

**Consequence.** Finding **F3**. Because the outer encoding is
unconstrained, the same signature verifies over a 203-byte re-encoding
with a different SHA-256, so `statement_sha256` identifies a
serialisation rather than a statement.

**Suggested resolution.** State the encoding rule in the vector, and say
that a verifier must enforce it before treating the digest as an
identifier.

---

## A6 — the subject's provenance points at a file the reading list omits

**Where.** Vector, `subject_chain.source`.

**What was unclear.** The vector says its chain head comes from
`docs/specs/pala-1/test-vectors.json`. That file is not on the MAY-read
list, which names `PALA-1.md` for context but not the vectors. So the
vector's one checkable provenance claim points at material the task does
not obviously permit.

**Choice made.** Read it and checked the claim: `chain_head` matches, and
`verify.count = 12` matches the stated `first_seq = 0 … last_seq = 11`.
It is a published CC0 specification artifact containing no bridge
material, and the MUST-NOT list does not reach it. The check is optional
in the verifier and is skipped if the file is absent, so a run made from
the vector alone still completes.

**Suggested resolution.** Add `test-vectors.json` to the MAY-read list —
or drop the `source` field, since a claim an implementer is not allowed
to check is not doing any work.

---

## A7 — the payload's keys collide with CWT claim keys

**Where.** Vector, `statement_inputs.payload_note`; protected header
label 15.

**What was unclear.** The payload is a CBOR map keyed 1, 2, 3, 4, in a
COSE object whose protected header carries CWT claims under RFC 9597,
where keys 1 and 2 are `iss` and `sub`. Is the payload an
application-specific map, or a CWT Claims Set? Nothing on the wire says:
there is no `content type` (label 3) in the protected header.

**Choice made.** Treated it as application-specific, per the vector's
prose. Recorded the other reading as adversarial case A8, which shows the
two are contradictory: payload key 1 is a byte string where the header's
`iss` is a text string, and RFC 9597 §2 requires a verifier that reads
both as claims to compare them and reject on mismatch.

**Consequence.** Finding **F2**.

**Suggested resolution.** Declare `content type` in the protected header.
It is the parameter that exists to answer this question.

---

## A8 — RFC 9943's own CDDL does not enforce its prose

**Where.** RFC 9943 §6 prose against Figure 3 in §6.1.

**What was unclear.** §6 states that the `kid` header parameter MUST be
present when neither `x5t` nor `x5chain` is in the protected header.
Figure 3's CDDL for `Protected_Header` marks `kid`, `x5t` and `x5chain`
each optional with a leading `?`, and expresses no conditional
relationship between them. Only `CWT_Claims` is unconditional there. An
implementer validating against the CDDL alone would accept a header the
prose forbids.

**Choice made.** Followed the prose: the conditional MUST is normative
and the CDDL is a structural sketch that does not attempt to encode it.
Reported the resulting non-conformance as **F1**, and flagged in the
finding that an implementer reading only the CDDL would not see it.

**Note.** This is an observation about RFC 9943, not about this
repository. It is logged because it changes how much weight F1 should
carry before someone acts on it — which is why F1 asks for unaffiliated
confirmation.

---

## A9 — two `expected` fields assert a result rather than supply an input

**Where.** Vector, `expected.verifies_with_public_key` and
`expected.payload_commits_to_chain_head`, both `true`.

**What was unclear.** Nothing, strictly — but a verifier that read these
as inputs, or that reported them back, would be testing nothing at all.
They are the two conclusions the run exists to reach.

**Choice made.** Computed both independently and then compared against
the published booleans, so they function as expectations rather than as
answers. Both agree.

**Suggested resolution.** Harmless as published. Worth one line in the
task file noting that these are results to be reproduced, not
configuration — the same care the task already takes elsewhere with
"do not bend your reading to match our bytes".
