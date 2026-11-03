# DPS reading 1b — action binding and the person approval, from the text

An outside reading of two extensions of the Decision Provenance Standard, **action binding 0.3.0** and **signatures 0.2.0** (the person approval and the organisation seal), from their text alone. Requested by Laurent Lemonnier, the extensions' author. Carried out by an AI assistant under the direction of Andrii Sparysh.

This is a second reading. No earlier reading was looked for, opened or asked about.

## What was read (pinned)

| Input | Commit | Files |
|---|---|---|
| `decision-provenance-standard/standard` | `c9043722384f784ae578ae0a64400be8a3864259` | 39, SHA-256 verified |
| `Laurent-Lemonnier/dps-scitt-decision-layer` | `fdc5f6352795fc713309cd25ac2669d22840e0cc` | 25, SHA-256 verified; N1–N7b reduced to their descriptions by the script before reading |

- `inputs/SHA256SUMS`: the sums the script checked, identical to those embedded in `dps-reading-1b-fetch-inputs.sh` (SHA-256 of the script: `82b50660b377ff3e8cb92d175bcd9a75bcbd027d077aa426d8a893d9e9d984a9`).
- RFC 9500: not fetched (`www.rfc-editor.org` did not resolve from the run environment).
- RFCs and standards applied from knowledge, not fetched: RFC 3161, RFC 5652 §5.4, RFC 5816, RFC 7493 §2.2–2.3, RFC 8032, WebAuthn Level 3.

## How the run was carried out

- Python 3.12.3. `cryptography` 46.0.6 (the Standard pins 50.0.2; deterministic ECDSA was available, so V14 reproduced the passkey signatures), `jsonschema` 4.26.0, `referencing` 0.37.0, `asn1crypto` 1.5.1, and their dependencies: `verifier/requirements.txt`.
- Wall clock: 2026-11-03 12:27:09Z to 13:13:04Z, including a pause between two sessions.
- The check was written from the texts, run once per suite (`out/first-run/`), then changed where it or the harness was at fault (`out/changes.md`, 22 entries), and run again (`out/final/`).

## Events at the boundary

- No `.py` file of either repository was read or run. No issues, pull requests, history, Lemonnier README, other verifier or earlier reading was opened. No web search.
- Ordering rule 1: the top-level keys of every JSON file of the second input were inspected before reading; all are documents (`composition.json` included).
- Ordering rule 2: the verdicts on the second input were written to `out/second-input.verdicts-before-summary.json` at 13:11:49Z; the three `summary.json` files were opened after that (`out/boundary.log`).
- The core schema `decision-record.schema.json` refers to `../mode-drift/layer-4-attestation.schema.json`, not among the allowed inputs. Lemonnier's records carry `mode_classification_attestation`, so their core-schema validation is partial: that member's subschema was left unchecked.
- `anchoring/tests/vectors.json` was downloaded and not read (V04 left out).
- `out/first-run/` was written a second time once with unchanged, deterministic code: identical output.
- An intermediate run directory used during the work (`run2`) is not included; `out/final/` supersedes it.

## Results — the extensions' test suites (777 cases)

| Suite | Cases | First run: agree / differ / n.a. | Final: agree / differ / n.a. |
|---|---|---|---|
| action binding, schema | 112 | 112 / 0 / 0 | 112 / 0 / 0 |
| action binding, digest | 15 | 15 / 0 / 0 | 15 / 0 / 0 |
| action binding, binding | 131 | 120 / 11 / 0 | 131 / 0 / 0 |
| action binding, signature | 41 | 38 / 3 / 0 ¹ | 41 / 0 / 0 |
| action binding, vector | 10 | 7 / 2 / 1 ¹ | 9 / 0 / 1 |
| action binding, pairing | 50 | 50 / 0 / 0 | 50 / 0 / 0 |
| signatures, schema | 137 | 137 / 0 / 0 ¹ | 137 / 0 / 0 |
| signatures, vector | 28 | 19 / 1 / 8 ¹ | 20 / 0 / 8 |
| signatures, person | 118 | 116 / 2 / 0 | 118 / 0 / 0 |
| signatures, seal | 45 | 43 / 2 / 0 | 45 / 0 / 0 |
| signatures, timestamp | 41 | 39 / 2 / 0 | 41 / 0 / 0 |
| signatures, pairing | 49 | 45 / 3 / 1 | 48 / 0 / 1 |
| **Total** | **777** | **741 / 26 / 10** | **767 / 0 / 10** |

¹ The harness stopped before giving a result (`out/changes.md`, entries 1 and 18); the first complete run after the harness fix is kept as the first run.

**Not attempted (10):**

- W08 and V19: they need `generate_vectors.py`, which the boundary forbids.
- V20: RFC 9500 was not fetched.
- V06: the seed-derived keys were computed and match; the RSA key was not checked against RFC 9500.
- V04: it compares with anchoring's vectors beyond the parts reused by reference.
- V05: not implemented.
- V03, V25 and V26: computed on something other than what the case describes (`out/changes.md`, entry 22).
- J47 (signatures pairing): the deep-nesting construction was not implemented.

**Limits of what agrees:**

- In action-binding pairing J42 and K01–K08, the case's "reference" report is this reading's own report, so agreement there shows self-consistency only.
- W07 compares the reports without `findings`, whose wording the text does not fix (ambiguity A-16).

Per-case results: `out/report.json`. Per-case expected and found values, with findings: `out/final/*.json`.

**Changes after the first run (22):** 12 in the check, 8 in the harness, 1 in neither (an order), and 1 in reporting. Each names the sentence it rests on: `out/changes.md`.

## Results — second input

The verdicts were written before any `summary.json` was opened. Unsigned examples: `issuer_signature` and `time_assurance` are `not_checked` in every row, because nothing is issuer-signed and no timestamp is held. `specification_digests`, `specification_statements`, `record_statements`, `stage_order`, `authorisation_recheck`, `observed_results` and `rationale_provenance` are `verified` in every row.

| Input | action_binding | executed | Person approval: status / signature / subject / key_state / identity | Agrees with summary.json on the dimensions the texts define |
|---|---|---|---|---|
| release-decision | verified | [0, shown_to_reviewer] | — (unsigned) | yes |
| aqta | verified | [0, shown_to_reviewer] | verified / verified / verified / verified / verified | yes |
| N1 | failed | [1, unbound] | verified ×5 | yes |
| N2 | failed | [0, shown_to_reviewer] | verified ×5 | yes |
| N3 | verified | [0, shown_to_reviewer] | failed / failed / verified / not_checked / not_checked | yes |
| N3b | verified | [0, shown_to_reviewer] | failed / failed / verified / not_checked / failed | yes |
| N4 | verified | [0, shown_to_reviewer] | verified ×5 | yes |
| N5 | verified | [0, shown_to_reviewer] | verified ×5 | yes |
| N6 | verified | [0, shown_to_reviewer] | verified ×5 | yes |
| N7 | verified | [0, shown_to_reviewer] | failed / verified / failed / verified / verified | yes |
| N7b | verified | [0, shown_to_reviewer] | verified ×5 | yes |

- **release-decision (unsigned):** the dimensions the text says are then not checked are `issuer_signature` (finding: carries no signature) and so `time_assurance` and the key state. The policy named is Lemonnier's `trust-policy.json` (the release decision names none), accepted.
- **N4, N5, N6:** no dimension of the two extension texts reads an issuer policy document, a specification's own `valid_until`, or an approval's maximum age. Computed outside the texts, these agree with his `policy_checks`:
  - N4: the policy held does not hash to `policy_version`;
  - N6: the attempt is 1680 s after o1 and after `valid_until`.
- **aqta, facts outside the texts (all true):**
  - `specification.bytes.json` is the specification's bytes;
  - `review-view.txt` hashes to `shown_view_digest`;
  - `policy.json` hashes to `policy_version`;
  - `arguments.canonical.json` hashes to `args_hash`;
  - `approval.canonical.json` equals the signed assertion;
  - both records' `seal_hash` follows the 64-zeros convention of the action-binding fixtures.
- **Not checked:** `seal_action_record`, `section_8_2_properties` and `composition_args_hash_bound` are outside both texts.
- **Values chosen for the negatives** (none is fixed by the descriptions): `out/final/second-input.json`, `values_chosen`. Rebuilt attachments are compact JSON.

## Layout

| Path | What it is |
|---|---|
| `verifier/` | The code in the state it ran, with `requirements.txt` |
| `out/first-run/` | First complete run of each suite |
| `out/final/` | Final run of each suite, and `second-input.json` |
| `out/second-input.verdicts-before-summary.json` | The second-input verdicts as written before `summary.json` was opened (identical values to `out/final/second-input.json`) |
| `out/report.json` | One boolean or `not attempted` per case, with totals |
| `out/changes.md` | Every change after the first run |
| `out/boundary.log` | Timed boundary events |
| `ambiguity-log.md` | Places the text admits more than one reading |
| `findings/` | One draft issue per finding; nothing has been filed |
| `inputs/SHA256SUMS` | The inputs, pinned |

To run: fetch the inputs with the reading's script, set `DPS_INPUTS` to its `inputs/` directory, install `verifier/requirements.txt`, then from this directory:
`python verifier/run_ab.py out/final`, `python verifier/run_sig.py out/final`, `python verifier/second_input.py out/final/second-input.json`, `python verifier/make_report.py out`.

## What was not checked

- The 10 cases listed above.
- The core-schema subschema for `mode_classification_attestation`.
- Everything in Lemonnier's summaries outside the two extension texts.
- Identity and authority against any independent source; no such source was held.
