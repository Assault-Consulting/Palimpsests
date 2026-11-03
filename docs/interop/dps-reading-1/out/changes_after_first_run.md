# Changes made to the verifier after its first run against the cases

Each change below was made after the first run showed a difference. For each: what the first
run reported, the sentence of the text the change rests on, and whether the change is to the
check or to the harness. Divergences that were *not* changed because the text supports the
first reading are under findings/.

## Action binding (binding and digest cases)
First run: 146 of 146 as expected. No change.

## Signatures (person, seal, timestamp cases)
First run: 199 of 204 as expected (out/first_run_signatures.txt).

1. N46, N48 (identity). First run: identity `not_checked` when `affirmed_digest` is not the entry's
   seal. Text: identity compares with "`affirmation_record.actor_identity` read from covered bytes
   that match the seal" — the seal is the export entry's, not the signed digest. Changed: the actor
   is read whenever the covered bytes match the entry's seal. Check fault (mine).
2. O41 (embedded_copy). First run: `not_checked` when the attachment has no UTF-8 encoding. Text:
   the copy agrees "only when every member does and the copy has exactly the members its version
   names" — a comparison of members, which needs no bytes. Changed: the harness now passes the
   document beside its bytes, and the copy is compared from the document's members. Harness fault
   (mine).
3. O06, O46 (subject). Not changed. See findings/F01.

## Action binding signature and vector cases
First run: 41 of 41 signature cases as expected. Vector cases: W09 and W10 raised KeyError in my
harness (I read the field `text`; the vectors name it `attachment_text`). Fixed in the harness;
both then as expected. W07 compared without finding texts (their wording is not fixed by the text).

## Schema cases
First run: action binding 112 of 112; signatures 110 of 110 attempted, 27 not attempted (anchoring's
trust-policy schema is not among the inputs). After the change to `copy` below, rerun: unchanged.

## Pairing cases
4. Patch op `copy` (harness). Changed before the first pairing run, from the descriptions of J03
   and J16 ("two for attachment 0, none for attachment 1"), which describe a replacement at `to`,
   not RFC 6902's insertion. Binding, schema and signature cases rerun after it: unchanged.
   First AB pairing run: 39 of 50 as expected, 11 raised (item 5).
5. `"report": "reference"` (AB K-cases, J40-J42; harness). First run raised: the cases name "the
   reference report" of their inputs, which only the reference check produces. This reading's own
   report stands in for it. Consequence: for those cases, a `consistent` expectation is checked
   against this reading's own output, which is circular; only `inconsistent` expectations test
   something.
6. Signatures pairing J47 (check and harness). First signatures pairing run: 48 of 49. J47 stopped with RecursionError on a report
   nesting 3 000 levels inside a timestamp subject's `of`. Text: "MUST give a result for every
   document valid against these schemas, and never stop on one". Changed: the recursion limit is
   raised to 20 000 and the report's timestamp subject is compared with the attachment's. A deeper
   nesting would still stop this code: limitation, not a fix in principle.

## Signatures vector cases
First run: 23 of 23 attempted as expected; V25 and V26 were marked not attempted, then implemented
from the copy rule ("verified only when every member does and the copy has exactly the members its
version names"; "an attachment of a version this check does not know is not compared"); both then
as expected.
