# SCITT-bridge Signed Statement — verification run B3 (construction v3)

Submission for the task in
[`docs/interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md`](../../../../../interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md),
run against **`scitt-statement-vector-v3.json`** — the two-statement
vector that adds the derived root (payload key 5) and the
prefix-consistency proof between the two roots.

B1 tested the 202-byte v1 statement and found the `kid` absent, the
content type undeclared and the CWT subject truncated.
[B2](../scitt-statement-b2/) confirmed the 331-byte v2 statement that
replaced it. This run tests the thing v2 could not do: whether two
registered statements of one chain can be connected **without the
chain**, by a consistency proof between the roots their signatures
cover.

- **Implementer:** Oleksii Turak — olexii.turak@gmail.com (maintainer;
  **not** an unaffiliated external run — see `RUN-RECORD.md` for the
  boundary disclosure, which has six parts this time)
- **Date:** 2026-10-28
- **Vector tested:** `docs/interop/scitt-statement-vector-v3.json` at
  commit `a39f4fd0`, SHA-256 `86a474ff…a8a96657`
- **Result:** all 8 task steps completed, both stretch goals done ·
  both statements **reproduced byte-for-byte** (369/369, stable across
  three runs) · **155/155 checks, 0 failures** · 7/7 tamper
  expectations held · nine adversarial cases of my own (13 checks) ·
  **4 findings, 1 of them a hard divergence** · 12 ambiguities logged
- **AI assistance:** yes — see `RUN-RECORD.md` § Affiliation

## The headline

**The main step works.** Given the two statements, the proof path and
the public key — and *nothing else* — prefix consistency verifies: the
12-record state extends the 8-record state. The isolation is structural
rather than promised: the check runs inside
`chainless_consistency_check(raw_earlier, raw_later, path, pub)`, and
there is no argument through which the chain, the record hashes or the
vector's `root_hex` fields could reach it. Both tree sizes come from
each statement's own signed `last_seq`.

**One hard divergence, and it is not in the statements.** A faithful
RFC 9162 §2.1.4.2 — fetched and implemented step for step — **cannot
verify** the `first == second` proof that `consistency-vectors.json`
publishes among its positive cases. The RFC's stated domain is
`0 < first < second` and its step 1 fails an empty `consistency_path`
outright. `consistency-proof.md` §2 asserts both that the format
"verifies with RFC 9162 §2.1.4.2" and that `first == second` "has an
empty proof and requires the roots to be equal"; both cannot hold.
That is finding **F1**, and it is why the step-1 omission in a
remembered version of the algorithm mattered: the RFC text had to be
read, not recalled.

**The near miss worth knowing about (F2).** The vector's own tamper
case — a root computed over `first_seq..last_seq` (8–11) instead of the
prefix — produces
`b81fb7fb…09217f76`, which is **byte-identical to the consistency
proof's only path node**. Because `first_seq = 8` is a power of two,
the wrong reading yields a real node of the published tree rather than
a random value, so an implementer who makes that mistake finds their
answer apparently corroborated by the proof document they are holding.

## Contents

| Path | What it is |
|---|---|
| `RUN-RECORD.md` | The run report: metadata, the six-part contamination-boundary disclosure, the AI-assistance disclosure, what was done in what order, the four findings, what did **not** diverge, and the verdict |
| `ambiguity-log.md` | Twelve places the task, the vector, the draft or a standard admitted more than one reading, including those resolved correctly on the first attempt |
| `verifier/merkle.py` | **New (207 lines).** PALA-1 §4.3 tree in both the iterative promote-not-duplicate form and RFC 6962's recursive `MTH`; RFC 6962 §2.1.2 `PROOF`/`SUBPROOF`; RFC 9162 §2.1.4.2 verification step for step, returning `(ok, reason)` rather than raising. Self-test: the two constructions checked equal for n = 0…24, and 276 build/verify round trips |
| `verifier/scitt_verify_v3.py` | **New (942 lines).** The run itself: COSE_Sign1 parse, RFC 9052 §4.4 Sig_structure, RFC 9679 thumbprint, the v2/v3 version rule, the eight task steps, 7 tamper expectations, nine adversarial cases |
| `verifier/cbor.py` | RFC 8949 decoder and deterministic encoder — **byte-identical to B2's** (`diff` is empty), reused as the task permits |
| `verifier/ed25519.py` | RFC 8032 Ed25519 — **byte-identical to B2's**, likewise |
| `verifier/run-all.sh` | Reproduces the whole run from a checkout |
| `output/full-run.log` | Full transcript |
| `output/results.json` | The 155 checks and the divergence, machine-readable |

## Reproducing

Standard library only, no dependencies:

```bash
cd verifier && sh run-all.sh
```

It finds the repo root from its own location, or takes it as an
argument. Exits 0 with `155/155 checks passed, 0 failed` and one
divergence printed as `[DIVERGENCE F1]`, and rewrites
`output/full-run.log` and `output/results.json`. The verifier runs in
0.27 s; `ed25519.py` self-tests against RFC 8032 §7.1 and `merkle.py`
runs its 276 proof round trips before anything else is trusted.

To run the verifier directly, pass the five inputs it reads and where to
put the results:

```bash
cd verifier && python scitt_verify_v3.py ../../../../../../interop/scitt-statement-vector-v3.json ../../../../../../interop/scitt-statement-vector.json ../../../../test-vectors.json ../../../../consistency-vectors.json ../../../../profiles/inference-vectors.json ../output/results.json
```
