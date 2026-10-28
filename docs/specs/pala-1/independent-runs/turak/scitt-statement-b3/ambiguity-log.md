# Ambiguity log — bridge run B3 (statement construction v3)

Every place the task file, the vector, the draft or a standard admitted
more than one reading during this run, including the ones resolved
correctly on the first attempt. Ordered roughly by how much they cost.

Entries carried over from B1/B2 unchanged (RFC 8949 §4.2.1 ordering vs
"ascending"; the RFC 9679 required-member set; `external_aad`; the
payload's integer keys vs CWT claim keys; duplicate map keys;
`content_type` as tstr or uint; RFC 8032's `0 <= S < L` check) are not
repeated here. All of them recurred and all were re-checked; see
`verifier/scitt_verify_v3.py` sections 2 and 8.

---

## U1 — "verifies with RFC 9162 §2.1.4.2" vs the `first == second` case

**Where.** `consistency-proof.md` §2, two sentences apart: the proof
"verifies with RFC 9162 §2.1.4.2, which corrects the RFC 6962 text" and
"`first == second` has an empty proof and requires the roots to be
equal".

**The ambiguity.** Whether "verifies with §2.1.4.2" names *that
algorithm* or the document format's verification semantics generally.
It decides the equal-size case, and the two readings give opposite
answers. RFC 9162 §2.1.4.2 states its input domain as `0 < first <
second` and its **step 1** is "If `consistency_path` is an empty array,
stop and fail the proof verification." An empty proof is therefore not
something that algorithm can accept — it is the one input it rejects
before doing any work.

**How resolved.** Implemented §2.1.4.2 literally, step for step
(`merkle.verify_consistency`), and let it decide. It returns `False` for
the equal-size case both with and without my own domain guard — the
RFC's step 1 is sufficient on its own. The task says the RFC wins, so
the equal-size rule is a PALA-1 pre-check that must be settled *before*
§2.1.4.2 is entered, not a proof that algorithm accepts.

This is the run's one hard divergence; it is finding **F1** in
`RUN-RECORD.md`. It does not touch the B3 statement vector, whose proof
is `8 → 12` with a one-node path.

**Suggestion.** In §2, split the sentence: the path algorithm is RFC 9162
§2.1.4.2; `first == second` is a PALA-1 rule checked before it, and
`first == 0` is rejected before it too. Both already sit outside the
RFC's stated domain, so saying so costs nothing and removes the
contradiction.

---

## U2 — how far the generator exclusion reaches

**Where.** The contamination boundary names
`docs/interop/gen_scitt_statement_vector_v3.py` and
`docs/specs/pala-1/palaudit_ref.py`, with the rationale "the vector's
statements and roots were computed with them, so reading them would make
your agreement ours".

**The ambiguity.** Three further generators sit inside directories the
boundary otherwise opens: `docs/specs/pala-1/gen_vectors.py`,
`docs/specs/pala-1/gen_consistency_vectors.py` and
`docs/specs/pala-1/profiles/gen_inference_vectors.py`.
`consistency-proof.md` §5 says the second of those is generated "from
the reference implementation (`palaudit_ref.py`) and the RFC text
alone", so it is a caller of a named-excluded file. The boundary's list
is by filename; its rationale is by provenance, and the rationale is
wider than the list.

**How resolved.** Took the rationale as controlling and read none of the
three. Only the *data* they emit was read, which the boundary explicitly
permits.

**Suggestion.** Say "any `gen_*.py` under `docs/`" rather than naming
one, or state that the data files are in bounds and every generator is
not.

---

## U3 — `profiles/inference-vectors.json` is on neither list

**The ambiguity.** `consistency-vectors.json` is explicitly readable,
but it publishes only roots, paths and a *prose description* of its
leaves — `"record_hash of each record, seq order"` — and names its
source as `profiles/inference-vectors.json`, which appears on neither
the MAY nor the MUST NOT list. Without it the published
`roots_by_count` cannot be recomputed at all, only the paths
re-verified against the roots the file asserts.

**How resolved.** Read it, on the reasoning that the MUST NOT list is
the binding one and this is published vector data rather than code or
generator output-in-progress. Disclosed in `RUN-RECORD.md`. It carries
record headers and hashes, no roots, so it cannot transfer the answer
under test. With it, the stretch goal becomes a real check: all 18
`roots_by_count` entries reproduced from the headers.

**Suggestion.** Add it to the MAY list, or inline the 17 leaf hashes
into `consistency-vectors.json` so the file is self-contained.

---

## U4 — the root's starting point, pre-closed by the text

**Where.** The task's own framing moves between three phrasings: "the
derived root over every record up to the one the statement covers"
(intro), "the PALA-1 §4.3 tree over the record hashes of records `0 …
last_seq`" (the table), and "**It always starts at record 0, whatever
`first_seq` says.**"

**The ambiguity — and why it did not cost anything.** The intro phrase
alone would have admitted `first_seq … last_seq`, which is the obvious
wrong reading for a statement whose reported range does not start at 0,
and the single most likely way for an independent implementation to
diverge. The task closes it twice — once in prose, once by worked
example (8–11 carries the root over 0–11) — and the vector's
`root_rule` closes it a third time. Logged because the resolution came
from the text rather than from the standards: nothing in PALA-1 §4.3 or
RFC 6962 says which leaf set a *statement* should commit to.

**Suggestion.** None. This is the task text doing its job; the one
sentence in bold is load-bearing and should survive editing.

---

## U5 — nothing constrains `first_seq` against `last_seq`

**The ambiguity.** The payload table gives key 2 as "`first_seq`,
unsigned integer — the first record this publication reports" and key 3
as `last_seq`. No document states `first_seq <= last_seq`, and because
the root depends only on `last_seq`, a statement with `first_seq = 11,
last_seq = 8` is constructible, signable, and carries a root that is
correct for its `last_seq`. Nothing in the construction makes it
unreadable.

**How resolved.** My reader refuses it (`first_seq > last_seq`: the
reported range is empty or inverted) and the run records that this is my
rule, not the specification's — case A4. Finding **F4**.

**Suggestion.** State `0 <= first_seq <= last_seq` in the payload table.

---

## U6 — nothing binds the head (key 1) to the root (key 5)

**The ambiguity.** Key 1 is the record hash of record `last_seq`; key 5
is the root over `0 … last_seq`, whose last leaf is that same record
hash. The two are therefore redundant for a verifier holding the chain,
and *independent* for one that is not: both are 32-byte values under one
signature, and no stated rule relates them without the records.

**How resolved.** Demonstrated it (case A5): a statement carrying
record 7's head with the 12-record root is accepted by a chainless
verifier, and the consistency proof over it still verifies, because the
proof is a statement about roots and never looks at key 1. A
chain-holding verifier catches it only if it checks the head
*separately* — the root in that statement is the correct root for its
`last_seq`, so a root-only check passes.

The task's "What a verifier may claim about the root" is careful and
correct about the root. It says nothing about the head, and the head is
where the remaining slack is. Finding **F3**.

**Suggestion.** Extend that section: without the chain the head is
carried too, and a chainless consistency check establishes a relation
between the two *roots* only — not that either statement's head belongs
to the chain the root describes.

---

## U7 — which copy of `first`/`second` is authoritative

**The ambiguity.** Task step 4 says to take the two roots "**from the
two statements' payloads** — not from your step 1", and says nothing
about where the two tree *sizes* come from. They exist twice: as
`consistency.first` / `consistency.second` in the unsigned proof
document, and implicitly as `last_seq + 1` in each signed payload.
`consistency-proof.md` §3 forbids accepting a document "on the strength
of its own embedded roots alone when it holds roots from elsewhere" —
which covers the roots, not the sizes.

**How resolved.** Derived both sizes from the statements' own signed
`last_seq` and treated the document's `first`/`second` as a
cross-check, which they passed (8/12 both ways). The isolation is
structural rather than asserted: `chainless_consistency_check()` takes
only the two statement byte strings, the path and the public key, so the
document's size fields are not reachable from inside it.

**Suggestion.** Add the sizes to step 4's instruction, or state in
`consistency-proof.md` §3 that `first`/`second` are cross-checks against
signed data wherever signed data exists.

---

## U8 — counts, sizes and seqs

**The ambiguity.** Three vocabularies for one quantity: the task says
"from size 8 to size 12", `consistency-proof.md` §2 says "`first ≤
second` be record **counts** (seq of the last record covered, plus
one)", and PALA-1 counts records by `seq`. The conversion is
`count = last_seq + 1`, stated only in the companion document.

**How resolved.** Correctly on the first attempt, because the tamper
list names the trap directly ("a root over `last_seq` or `last_seq + 2`
records instead of `last_seq + 1`"). Logged anyway: this is where an
off-by-one would land, and the three statements of it live in three
files.

---

## U9 — `A : B` in the RFC 6962 SUBPROOF recursion

**The ambiguity.** RFC 6962 §2.1.2 writes `SUBPROOF(m, D[0:k], b) :
MTH(D[k:n])` without defining `:` in that section. Read as "the
recursion's output followed by this node" it gives leaf-ward-to-root-ward
order; the reverse reading would reverse every path.

**How resolved.** Took it as append-on-the-right, which agrees with
`consistency-proof.md` §3's "root-ward order, as `SUBPROOF` emits it",
and confirmed it by rebuilding all ten in-domain published paths from
`consistency-vectors.json` byte-for-byte, plus the B3 path
`PROOF(8, D[12])`.

---

## U10 — "exactly keys 1–5" closes the payload

**The ambiguity.** The version rule says a v3 statement carries
"exactly 1–5 with a 32-byte key 5". Read strictly this forbids an
unknown key 6, which is at odds with PALA-1 §7.6's forward-compatibility
posture elsewhere in the format.

**How resolved.** Implemented the strict reading as written. It is in
fact coherent with the design — the signed content type names the
construction, so a key 6 would come with a v4 content type rather than
inside v3 — but that reasoning is not stated, and an implementer
weighing "ignore unknown keys" against "refuse unknown keys" has only
the word *exactly* to go on.

**Suggestion.** One sentence: the payload is closed per content type;
extensions get a new content type, never a new key under an old one.

---

## U11 — the v3 media type is unregistered

**The ambiguity.** `application/vnd.palimpsests.pala1-head-v3+cbor`
uses the `vnd.` tree and the `+cbor` structured syntax suffix. Within
the boundary I cannot tell whether it is registered with IANA, and the
version is carried in the media type rather than in a parameter —
a design choice with consequences for a transparency service that
filters by type.

**How resolved.** Out of scope for byte-level verification; the string
matched exactly, which is all the vector claims. Noted for the record,
not as a defect.

---

## U12 — "carried" and "recomputed" are new vocabulary

**The ambiguity.** The task requires that "a report must not call an
unrecomputed root verified", which is clear, but no standard defines the
alternative term. Different runs will name this state differently, and
the distinction is the whole point of the section.

**How resolved.** Used three explicit states in the reader's output —
`carried`, `recomputed-ok`, `recomputed-mismatch` — and asserted in the
run (case T7) that the string "verified" never appears among them.

**Suggestion.** Fix the two words in the task text so independent runs
report the same state under the same name.
