# PALA-1 v1.0 — independent verification run

Submission package for the exercise in
`docs/specs/pala-1/verification-kit/`.

- **Implementer:** Oleksii Turak — olexii.turak@gmail.com
- **Date:** 2026-08-18
- **Spec verified:** PALA-1 v1.0 at tag `pala1-v1.0` (all four input
  digests confirmed against the kit's pinned values)
- **Result:** 11/11 §8 values reproduced on first execution · 7/7 published
  demos reproduced · 13 further adversarial cases constructed · 140 checks,
  0 failures · 8 ambiguities logged · 1 specification-completeness gap
  reported

**Eligibility.** None of the disqualifying files were read; only the
four allowed inputs of kit README §1 were used, fetched at the frozen
tag and digest-checked before use. Details in `RUN-RECORD.md` →
"Eligibility".

## Contents

| Path | What it is |
|---|---|
| `RUN-RECORD.md` | The filled kit form: metadata, the eleven §8 values, the demo table, the ambiguity log, the defect report |
| `METHODOLOGY.md` | Step-by-step account of the run and the rationale for every non-obvious decision |
| `verifier/PALA1.pm` | The verifier core (337 lines): §2.1 decode, §2.2 TLV, §2.4 container, §7.1 chain, §7.2 completeness, §4.3 Merkle in both constructions |
| `verifier/AESGCM.pm` | AES-256-GCM from FIPS-197 / NIST SP 800-38D (245 lines), for the optional §4.4 extra — no crypto library was available |
| `verifier/build-container.pl` | Builds the §2.4 container from `test-vectors.json` |
| `verifier/run-suite.pl` | The eleven §8 pass-bar values |
| `verifier/demos.pl` | The seven published demos + thirteen constructed cases |
| `verifier/body-check.pl` | §7.5 digests, §4.4 decryption and AAD binding |
| `verifier/narrative-check.pl` | The §8 prose table checked against the actual bytes |
| `verifier/run-all.sh` | Runs everything |
| `output/full-run.log` | Full transcript of the run |

Two things are deliberately **not** committed here, because both are
byte-for-byte reproducible and neither should be trusted from this
directory in preference to its source: the sealed input package
(`pala1-package/`, which is just the four allowed inputs at
`pala1-v1.0` — fetch them with the kit's own script and check the
digests yourself), and the built container `chain.pala` (2315 bytes,
regenerated deterministically by `build-container.pl`; its SHA-256 is
recorded in `output/full-run.log` §1 if you want to confirm the run
used the same bytes).

## Reproducing

```bash
sh ../../verification-kit/fetch-inputs.sh && sh verifier/run-all.sh
```

Perl 5 with core modules only (`Digest::SHA`, `JSON::PP`). No
third-party dependencies. Verified to run from this directory inside a
checkout, and standalone outside one.

## The one finding

Not a wire defect, and it contradicts no §8 value. §3.1 promises that
"a crash must leave a visibly unclosed span, because that is the
evidence", but §7 defines no span-pairing check anywhere — while §7.4
explicitly justifies its one other deliberate omission
(`MERKLE_LEAF_COUNT`). The committed vectors contain a span
(`2222…`, referenced by seq 3 and seq 6) with neither a `SPAN_START` nor
a `SPAN_END`, and no §7 check flags it. Two conformant verifiers will
therefore differ on whether a user ever sees an unpaired span. Details
and two suggested text-only resolutions in `RUN-RECORD.md` → Defects and
`METHODOLOGY.md` §10.
