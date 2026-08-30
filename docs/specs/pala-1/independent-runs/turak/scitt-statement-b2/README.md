# SCITT-bridge Signed Statement — verification run B2 (vector v2)

Submission for the task in
[`docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md`](../../../../interop/SCITT-STATEMENT-VERIFICATION-TASK.md),
run against **vector v2** — the reissue that resolves run
[B1](../scitt-statement/)'s findings F1, F2 and F4 and rescopes F3.

B1 tested the 202-byte v1 statement and found the `kid` absent, the
content type undeclared and the CWT subject truncated. This run tests
whether the 331-byte v2 statement that replaced it holds up when a fresh
implementation, written from the RFCs alone, is pointed at it.

- **Implementer:** Oleksii Turak — olexii.turak@gmail.com (maintainer;
  **not** an unaffiliated external run — see `RUN-RECORD.md` for the
  boundary disclosure, which differs from B1's in one material respect)
- **Date:** 2026-08-30
- **Vector tested:** `docs/interop/scitt-statement-vector.json` at commit
  `d84be55a`, SHA-256 `e51575d0…d1570ec7`
- **Result:** all 7 task steps completed · statement **reproduced
  byte-for-byte** (331/331, stable across three runs) · **61/61 checks,
  0 failures** · 5/5 tamper expectations held · 11 adversarial cases
  constructed · **4 findings**, none contradicting the published bytes ·
  10 ambiguities logged

## What this run adds over B1

B1's F1, F2 and F4 are **confirmed fixed** in v2, and F3's rescoping is
confirmed correct — this run reproduces the F3/A1 mechanism directly.
The four new findings are refinements to the vector's prose and its
tamper list rather than defects in the bytes; the two that matter:

- **F-2** — the tamper list misses Ed25519 signature malleability.
  `S + L` yields a *second* valid 64-byte signature over the identical
  Sig_structure, accepted by any verifier that omits RFC 8032 §5.1.7's
  `0 <= S < L` range check. A signature-uniqueness failure, not a
  forgery, and it matters for a transparency service that deduplicates
  or indexes registrations by signature bytes.
- **F-1** — moving `kid` to the unprotected bucket is exactly
  **length-neutral** for this statement (−35 protected, +35 unprotected,
  331 B either way), so `statement_length_bytes` does not detect the
  move that `byte_stability.2` describes. Only the sha256 does.

## Contents

| Path | What it is |
|---|---|
| `RUN-RECORD.md` | The run report: metadata, the contamination-boundary disclosure, what was done in what order, the four findings with measurements, and the verdict |
| `ambiguity-log.md` | Ten places where a standard or the published material admitted more than one reading, including those resolved correctly on the first attempt |
| `verifier/cbor.py` | RFC 8949 decoder and deterministic encoder (211 lines). Strict by default: rejects non-minimal length heads, indefinite lengths and trailing data; preserves map order and raw encoded key bytes so §4.2.1 ordering is *checked*, not assumed |
| `verifier/ed25519.py` | RFC 8032 Ed25519 (183 lines), extended-coordinate point arithmetic, with the `0 <= S < L` range check switchable so both behaviours can be demonstrated. Anchored on §7.1 TEST 1 and TEST 2 |
| `verifier/scitt_verify.py` | The run itself (443 lines): COSE_Sign1 parse, RFC 9052 §4.4 Sig_structure, RFC 9679 thumbprint recomputation, the seven task steps, five tamper cases and eleven adversarial cases |
| `output/full-run.log` | Full transcript of the run |
| `output/results.json` | The 61 checks, machine-readable |

## Reproducing

Standard library only, no dependencies:

```bash
cd verifier && python scitt_verify.py ../../../../../../interop/scitt-statement-vector.json
```

Exits 0 with `61/61 checks passed, 0 failed`. The verifier itself runs in
0.08 s; `ed25519.py` self-tests against RFC 8032 §7.1 before anything
else is trusted.
