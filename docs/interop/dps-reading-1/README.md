# DPS reading 1: action binding and the person approval, from the text

An outside reading of two extensions of the Decision Provenance Standard, **action binding 0.3.0**
and **signatures 0.2.0**, at the Standard's main commit
`c9043722384f784ae578ae0a64400be8a3864259`, requested by Laurent Lemonnier, the
extensions' author. The question under test: is the text alone enough to implement the checks.

Carried out by an AI assistant under the direction of Andrii Sparysh. The assistant wrote the
verifier, ran it and drafted this record. The code is in the state it ran.

## What was read (pinned)

| Repository | Commit | Files | SHA-256 check |
|---|---|---|---|
| decision-provenance-standard/standard | `c9043722384f784ae578ae0a64400be8a3864259` | 33 | all match (`inputs/standard/SHA256SUMS`) |
| Laurent-Lemonnier/dps-scitt-decision-layer | `fdc5f6352795fc713309cd25ac2669d22840e0cc` | 25 | all match (`inputs/lemonnier/SHA256SUMS`) |

`inputs/SHA256SUMS` is both lists, paths prefixed by the repository. `inputs/fetch-inputs.sh` is
the script that downloaded them.

No RFC text was fetched during the run. RFC 7493 (I-JSON), RFC 3161, RFC 8032, RFC 6979 and
WebAuthn Level 3 were applied as the texts cite them and as the assistant knows them.

Not read: any `.py` file of either repository, issues, pull requests, commit history, discussions,
any README of Lemonnier's repository, any other implementation. No web search for one.
The anchoring 0.2.0 extension's text, schemas and vectors are not among the inputs; both texts
reuse its signed-bytes rule, key states, trust policy and timestamp checks by reference. Those
parts were implemented from the restatement in the signatures README only.

### Boundary events (logged as the prompt asks)

1. `interop/aqta/approval-record/out/negatives/N1`–`N7b`: opened and read in full before
   noticing that they hold a description (`what`) and someone else's results, not documents. They
   carry no attachment, signature attachment or policy to run. The negatives below were rebuilt
   from the `what` text **after** those results had been seen: they are not an independent check.
   The cause is the reading's prompt, which listed these files among the allowed inputs before
   their contents were known. The second reading of the same extensions, `dps-reading-1b`,
   received the negatives as descriptions only.
2. `composition.json`: data, with prose members (`signed_via`, `exact_values`) describing the
   composition. Read in full; not a reading of either extension.
3. Every `summary.json` (release-decision, aqta, negatives) was opened only after
   `out/second-input-verdicts.json` had been written.

## How the run was carried out

1. The fetch script ran; all 58 digests matched.
2. The assistant read the extensions' READMEs and schemas, the case files and the vectors' structure,
   and wrote the verifier in Python 3.12 (`verifier/`). Dependencies besides the standard library:
   `cryptography` 46.0.6 (the reference pins 50.0.2), `asn1crypto` 1.5.1 (RFC 3161 tokens),
   `jsonschema` 4.26.0 (the schema cases). The prompt named the standard library plus
   `cryptography`; the other two were added for the schema cases and the time-stamp tokens.
3. Each suite was run once, the first results kept (`out/first_run_*.txt`), then differences
   examined. Every change made after a first run is in `out/changes_after_first_run.md`, with the
   sentence of the text it rests on and whether the fault was the check or the harness. The two
   remaining divergences were not changed: the text supports the first reading (findings/F01).
4. The second input was run and its verdicts written (`out/second-input-verdicts.json`), then the
   `summary.json` files were opened and compared.

To rerun, from this directory: `sh inputs/fetch-inputs.sh inputs`, then in `verifier/`:
`pip install -r requirements.txt`, `python3 run_second.py`, `python3 run_all.py`.

Wall-clock time, by the container's clock: 2026-11-02T20:46:21Z to 2026-11-02T22:08:00Z,
1 h 22 min, in two sessions of one conversation; the pause between them is included.

## Results: the published cases

`true` means the case behaved as its expected value says. The case conventions (defaults for
dimensions a case does not name, patch semantics) are in `ambiguity-log.md`.

| Suite | Cases | As expected | Not as expected | Not attempted |
|---|---|---|---|---|
| action binding, digest | 15 | 15 | 0 | 0 |
| action binding, binding | 131 | 131 | 0 | 0 |
| action binding, signature | 41 | 41 | 0 | 0 |
| action binding, vector | 10 | 9 | 0 | 1 (W08) |
| action binding, schema | 112 | 112 | 0 | 0 |
| action binding, pairing | 50 | 50 | 0 | 0 |
| signatures, person | 118 | 118 | 0 | 0 |
| signatures, seal | 45 | 43 | 2 (O06, O46) | 0 |
| signatures, timestamp | 41 | 41 | 0 | 0 |
| signatures, vector | 28 | 25 | 0 | 3 (V04, V19, V20) |
| signatures, schema | 137 | 110 | 0 | 27 |
| signatures, pairing | 49 | 49 | 0 | 0 |
| **Total** | **777** | **744** | **2** | **31** |

First runs, before any change: action binding digest and binding 146/146, signature 41/41,
vector 7/9 attempted (W09, W10 raised in the harness), schema 112/112, pairing 39/50 (11 raised
in the harness); signatures person 116/118, seal 42/45, timestamp 41/41, schema 110/110 attempted,
vector 23/23 attempted (V25, V26 were implemented after), pairing 48/49 (J47 raised). Details in `out/changes_after_first_run.md`.

Not attempted, and why:

- W08, V19: the vectors' byte-for-byte reproduction needs `generate_vectors.py`, which the reading
  may not open.
- V04: needs anchoring 0.2.0's vectors, not among the inputs.
- V20: RFC 9500's text was not fetched; the case's own printed values are not an independent check.
- 27 signatures schema cases: they validate against anchoring 0.2.0's trust-policy schema, not
  among the inputs.
- W07 (the reference report of A0 and A1) was compared structurally, finding texts excluded:
  the text does not fix their wording. Every status and value matched.
- Pairing cases whose report is `"reference"` (action binding J40–J42, K01–K08): this reading's own
  report stands in for the reference check's. For their `consistent` expectations the check is
  circular; only the `inconsistent` ones test something.

## Results: the second input

Dimension by dimension; full detail in `out/second-input-verdicts.json`.

### examples/release-decision (unsigned)

Read with its decision record and a trust policy that lists no key
(`urn:dps-reading-1:verifier-policy:no-keys`, accepted).

| Dimension | Status |
|---|---|
| structural_validity | verified |
| specifications[0].digest | verified |
| specifications[0].statements | verified |
| record_statements | verified |
| action_binding | verified |
| stage_order | verified (time basis: issuer's assertion) |
| authorisation_recheck | verified |
| observed_results | verified; attempted; x1 succeeded, target_response |
| rationale_provenance | verified |
| executed / reviews | spec 0 shown_to_reviewer / v1 as_proposed |
| issuer_signature | not_checked: the attachment carries no issuer signature |
| time_assurance | not_checked: the text verifies time only against a timestamp over a verified issuer signature |
| identity_assurance, authority_assurance | not_checked: no independent source |
| legal_signature | not_checked: none referenced |

Not checked because the attachment is unsigned: the issuer signature, its key state, holder and
certificate, and time assurance. The record's validity against the core schema was not attempted:
`decision-record.schema.json` refers to `../mode-drift/layer-4-attestation.schema.json`, which is
not among the inputs, and the record carries `mode_classification_attestation`.

### interop/aqta/approval-record/out

Action binding, read with the record, `trust-policy.json` and `signatures-attachment.json` beside:
every dimension as in the table above (all verified; issuer signature, time, identity, authority
and legal signature `not_checked`). Signatures, the one person approval (`person_approval`,
`release-manager-claims-key-1`, outcome `o1`): status verified; signature verified; subject
verified; key_state verified, on the stated time; identity verified, consistent, source
`urn:isoluce:directory:people`. Trust policy accepted.

Also computed, outside both extensions: `specification.bytes.json` is the attachment's
specification bytes; SHA-256 of `review-view.txt` is the review's `shown_view_digest`; SHA-256 of
`arguments.canonical.json` is the specification's `parameters.args_hash`; both records' seals
match the fixtures' convention (SHA-256 with the `seal_hash` value replaced by 64 zeros), which is
a convention of the action-binding cases, not a rule of either extension.

Not attempted, outside both extensions: `seal_action_record`, `policy_checks`,
`composition_args_hash_bound`.

### N1–N7b, rebuilt from their descriptions (not independent; see boundary event 1)

| Negative | Action binding: dimensions not verified | Executed | Person approval |
|---|---|---|---|
| N1 | action_binding | spec 1 unbound | all verified |
| N2 | action_binding | spec 0 shown_to_reviewer | all verified |
| N3 | none | spec 0 shown_to_reviewer | failed: signature failed, key_state not_checked, identity not_checked |
| N3b | none | spec 0 shown_to_reviewer | failed: signature failed, key_state not_checked, identity failed |
| N4, N5 | the change is to `policy.json`, which neither extension reads: same as the base | | |
| N6 | none | spec 0 shown_to_reviewer | all verified |
| N7 | none | spec 0 shown_to_reviewer | failed: subject failed; signature, key_state, identity verified |
| N7b | none | spec 0 shown_to_reviewer | all verified |

N3 and N3b were rebuilt without a signature by `someone-else-key-1` (not held): the signature
fails on the key not being listed, or on its role, before any verification. N3b's public key and
N7's other policy digest are invented values, stated in the verdicts file.

### Comparison with the summary.json files

- release-decision: every dimension the summary gives matches.
- aqta: every action-binding dimension and the person approval's five statuses match.
- negatives: the rebuilt verdicts match the summary's action-binding and person-approval statuses
  for N1–N7b. This is not an independent agreement.

## Findings

- `findings/F01-seal-subject-and-embedded-copy.md` (Standard): seal cases O06 and O46.
- `findings/F02-negatives-without-documents.md` (Lemonnier): N1–N7b publish results, not inputs.
- `findings/F03-dr-2026-0517-attestation-text.md` (Lemonnier): text in DR-2026-0517 names the
  inputs of DR-2026-0412. No check of either extension reads these fields.

## What this reading does not show

That the reference check is correct; that this verifier is correct beyond the cases run; anything
about anchoring 0.2.0's own text; the legal effect of anything; that the second input's claims are
true.

**Erratum, 5 November 2026.** An earlier version of this record gave `007f8c9` as the short form of the commit read. It is another commit of the Standard, whose text of both extensions is the same; the commit read is `c904372`.
