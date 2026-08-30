# SCITT-bridge Signed Statement — independent verification run

Submission for the task in
[`docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md`](../../../../interop/SCITT-STATEMENT-VERIFICATION-TASK.md).
It is a separate axis from this implementer's wire-format run in the
parent directory: that one reproduced the PALA-1 §8 hashes, this one
verifies and reproduces the COSE_Sign1 Signed Statement built over the
resulting chain head.

- **Implementer:** Oleksii Turak — olexii.turak@gmail.com (maintainer;
  **not** an unaffiliated external run — see `RUN-RECORD.md`)
- **Date:** 2026-08-30
- **Vector tested:** `docs/interop/scitt-statement-vector.json` at commit
  `296f331`, SHA-256 `bf810261…54bf9491`
- **Result:** all 7 task steps completed · statement **reproduced
  byte-for-byte** (202/202) · 45 checks, 0 pass-bar failures · 3/3 tamper
  expectations held · 11 adversarial cases constructed · **4 findings**,
  one of them a violation of a normative MUST in RFC 9943 §6 ·
  9 ambiguities logged

## Contents

| Path | What it is |
|---|---|
| `RUN-RECORD.md` | The run report: metadata, what was done in what order, the step-by-step results, the four findings, the tamper and adversarial tables, and the contamination-boundary disclosure |
| `ambiguity-log.md` | Nine places where the task, the vector or a standard admitted more than one reading, with the choice made for each |
| `verifier/cbor.py` | A strict CBOR codec written from RFC 8949 (240 lines) — definite-length decode that reports non-deterministic encodings, plus a §4.2.1 deterministic encoder |
| `verifier/ed25519.py` | PureEdDSA over edwards25519 written from RFC 8032 §5.1 (168 lines) — sign, verify, and the `0 ≤ S < L` range check |
| `verifier/scitt_verify.py` | The run itself (619 lines): COSE_Sign1 parse, RFC 9052 §4.4 Sig_structure, the seven task steps, tamper and adversarial cases |
| `output/full-run.log` | Full transcript of the run |
| `output/results.json` | The same, machine-readable: every check with its section, outcome and detail, plus the findings |

No COSE library, no CBOR library and no cryptographic library is used
anywhere. `ed25519.py` is self-checked against RFC 8032 §7.1 TEST 1
before it is trusted with the statement — and since the vector's key
*is* that test key, the same check confirms the vector's stated key
provenance.

## Reproducing

```bash
python verifier/scitt_verify.py
```

Python 3.9 or later, standard library only. The vector is located
relative to this directory; pass a path to test a different one:

```bash
python verifier/scitt_verify.py /path/to/scitt-statement-vector.json
```

Exit status is 0 when every pass-bar check holds. The two checks that
report `FAIL` in the transcript are the RFC 9943 conformance findings
(F1, F2) — they are findings about the published statement, which is
what the task asked for, and they deliberately do not set the exit
status.

## The four findings, in one line each

| # | Severity | Finding |
|---|---|---|
| **F1** | conformance | The protected header has no `kid`, `x5t` or `x5chain`, which RFC 9943 §6 makes a MUST violation — a transparency service cannot resolve the issuer's key in band |
| **F2** | ambiguity | With no `content type` declared, a payload keyed 1..4 is indistinguishable from a CWT Claims Set, which RFC 9597 §2 would then require a verifier to reject |
| **F3** | malleability | RFC 9052 §9 constrains only the *signed* structures, so a re-encoded 203-byte variant carries the same valid signature — `statement_sha256` identifies a serialisation, not a statement |
| **F4** | design | `sub` truncates the chain head to 8 bytes, so two different chains collide in the SCITT subject at a 64-bit birthday bound |

F1 turns on one sentence of RFC 9943 prose that the same RFC's CDDL does
not enforce (ambiguity A8), so it is worth an unaffiliated confirmation
before it is acted on.
