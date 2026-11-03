# Ambiguity log

Each entry: where, the readings, the one chosen, why. "AB" is action binding 0.3.0, "SIG" is
signatures 0.2.0. Entries marked *(cases)* are conventions of the case files rather than of the
extension text.

## Action binding

1. **AB, verifier, record statements: "a `review_log` outcome word the check does not know".**
   The text names no list of known words, and the core schema leaves `outcome` a free string.
   Readings: the extension's three outcome words; any word equal to the stage's outcome; a list in
   the Core. Chosen: `approved`, `rejected`, `escalated`, the words the extension defines.
2. **AB, `core_ref` description: a `review_log` entry's "reviewer, time and outcome".** Which stage
   time it is compared with: the review's or the outcome's. Chosen: the outcome stage's `at`, since
   the `review_log` entry backs the outcome. The fixture R1 is consistent with this; R0 is not
   compared (A0 cites `affirmation_record`).
3. **AB, verifier: "each stage comes after the stages it names".** Readings: listed after; dated
   after; both; strictly or not. Chosen: listed after **and** dated no earlier (equal instants
   allowed), each failing separately; a time that names no instant fails the comparison.
4. **AB, verifier: "the statements ... where it can read them".** Which media types are readable.
   Chosen: `application/json` only, read by the strict reader, whatever the representation kind;
   anything else `not_checked`.
5. **AB items 6 and 9: "a service named in the attachment".** Chosen: the values of `requested_by`
   and `executor_ref`. Not `authority_source_ref`, which names a permission system's snapshot.
6. **AB items 6 and 11: a specification "a reviewer in the attachment rejected or escalated".**
   Applied to changes and to requests under a standing approval, as the two items say. Not applied
   to a request resting on an approval of the same specification by another reviewer: no item says
   so.
7. **AB item 10: the bounds and the specification.** Chosen: a specification inside bounds has
   exactly the members `operation`, `target`, `policy_version`, `input_version_refs`,
   `parameters`; `operation`, `target`, `policy_version` in the bounds must be strings; an empty
   `one_of` is well-formed (nothing is inside it); `{"min": a, "max": b}` with a > b is well-formed
   (nothing is inside it). The text is silent on the last three.
8. **AB item 5: "no specification is requested more often than the largest `request_limit`".**
   Chosen: counts the requests resting on approvals and changes, not those resting on a standing
   approval of the same bytes.
9. **AB report, `executed_specifications`.** One entry per specification, in the order of its first
   attempt; `reached_by` from that first attempt. The cases S13 and L60 are consistent with this.
10. **AB, a review of bounds that names a proposal.** Reported as `differs_from_proposal` in
    `reviews` (and the binding fails, S43). No case states the `reviews` entry.
11. **AB, rationale provenance.** `contemporaneous`: `recorded_at` no later than the stage's time.
    `later_supplemented`: strictly later. The text gives the first; the second is its complement
    (L44).
12. **AB items 11 and 12: a request or recheck "after" a revocation.** Chosen: listed after, or
    dated strictly after; a time that names no instant fails.
13. **AB item 11: a specification whose bytes do not match its digest, under a standing
    approval.** Readings: not checked (like unavailable bytes) or failed. Chosen: failed. No case
    covers it.
14. **AB, the issuer signature's copy.** A copy without exactly the five members, or with other
    fixed values, fails before the bytes are built, its key state `not_checked`.
15. **AB, binding-case comparison *(cases)*.** `specification_digests` and
    `specification_statements` are one value per case; the report has one per specification.
    Aggregated as: failed, else unavailable, else not_checked, else verified.

## Signatures

16. **SIG, seal `subject` and `embedded_copy`.** See findings/F01. Chosen: `subject` is the sealed
    digest against the document only, as the text defines it; `embedded_copy` is reported apart;
    the seal's status is signature, subject and key state.
17. **SIG and anchoring, key states with a timestamp.** "Only the stated time can show that a
    signature was made after `not_before`." Chosen: `not_before` against the stated time;
    `not_after` and a superseded key's `revoked_at` against T when a verified timestamp covers the
    value, else against the stated time; a compromised key needs T < `revoked_at`.
18. **SIG, identity when the key is not a person's.** The text: the policy "binds `key_ref` to a
    person, in role `person`"; it does not say what identity reports for another role. Chosen:
    `failed`, before the rule that identity is `not_checked` when the signature is not verified.
    The cases N25, N26, N49, N102 agree.
19. **SIG, which actor identity reads.** Chosen: the `actor_ref` of the named stage only when it is
    of the kind the assertion type names (an outcome; a standing approval); otherwise none read.
20. **SIG, the status of an assertion.** Chosen precedence when not all three are verified:
    failed, then not_supported, then unavailable, then not_checked.
21. **SIG, an attachment with no UTF-8 encoding.** The copy is compared from the document's
    members (no bytes needed); the subject fails (O41).
22. **SIG, timestamp checks, restated from anchoring.** Chosen: `tsa_state` against `genTime`; an
    authority revoked as compromised fails every token; a signer identifier naming another
    certificate fails `tsa_signature`; `signer_certificate` not_checked does not stop the
    timestamp verifying, failed does; `signer_time` is reported apart and is not part of the
    timestamp's status. Anchoring's own text was not available to settle these.
23. **SIG, seal-case defaults *(cases)*.** `certificate` and `embedded_copy` are compared only when
    a case names them, though the case file says every dimension is expected verified unless
    stated: a seal with no pinned certificate or no copy cannot have them verified.

## Case conventions and pairing

24. **Patch `copy` *(cases)*.** Replaces the value at `to` (J03, J16 describe a replacement).
25. **`"report": "reference"` *(cases)*.** This reading's own report stands in for the reference
    check's.
26. **AB signature-case defaults *(cases)*.** Not stated in the case file for this section. Chosen:
    status and key state verified, time assurance not_checked, policy accepted.
27. **Pairing, "a report may say less ... it may not say more".** Chosen: any status may be
    reported `not_checked`; any other status must be the one found here; every carried value
    (counts, indexes, digests, holder, times, timestamp indexes, observed results, `reached_by`,
    editors, flags) must be the one found here; optional parts may be left out.
