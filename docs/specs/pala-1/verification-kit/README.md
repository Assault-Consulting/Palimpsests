# PALA-1 verification kit — verify the frozen format yourself

PALA-1 is frozen at v1.0 on the strength of one sentence:

> **An independent party must be able to write a verifier from the
> specification alone, without our code.**

Four independent implementations — two of them by external, unaffiliated
implementers — have passed that test (`../INDEPENDENT-VERIFICATION.md`).
This kit exists so that **anyone** can run the same exercise, on the same
terms, at any time. Every submitted run becomes part of the permanent
verification record.

No permission is needed. No contact with the maintainers is needed until
you submit. Expect roughly 1.5–4 hours.

## 1. The boundary — read this first

The exercise tests the *document*, not a conversation and not our code.
It is only meaningful if you work from the allowed inputs alone:

- **Do not clone the repository.** It contains the reference
  implementation, the production verifier, the tests, and earlier runs'
  verifiers — reading any of them disqualifies a fresh run.
- **Fetch only the allowed inputs**, using `fetch-inputs.sh` (below) or
  by downloading exactly these four files at the `pala1-v1.0` tag:
  `PALA-1.md`, `profiles/robotics.md`, `profiles/inference.md`,
  `test-vectors.json`.
- **Questions are logged, not asked.** If the text is ambiguous, record
  the ambiguity, make a documented choice, and continue. Every logged
  ambiguity is a specification defect by the spec's own standard — your
  log is a deliverable, not an inconvenience.
- Public external references the spec itself cites (RFC 2119, RFC 6962,
  RFC 3161, AES-GCM) are allowed.
- **AI assistance is allowed with disclosure** (the template has a line
  for it), provided the agent, too, works only from the allowed inputs.

```sh
sh fetch-inputs.sh        # builds ./pala1-package/ and checks digests
```

Expected SHA-256 of the inputs at the freeze (also enforced by the
script):

```
b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5  PALA-1.md
20093ccd12075aef2062603b5282df83e70ce3a59944173d930183ca6e36fe56  profiles/robotics.md
3ef8feb3017bd24ca117710c7983641ee5a3803272b6dea82937d60735449a0f  profiles/inference.md
476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193  test-vectors.json
```

## 2. The task

In any language, with no code from this repository:

1. Build the §2.4 file container from `test-vectors.json` (concatenate
   each record's `header_hex` and, where present, `body_hex`).
2. Implement §7.1 header-only chain verification and §7.2 completeness
   against an anchor.
3. Implement the §4.3 Merkle tree (either construction; both agree).
4. Reproduce, from that container, **every value in the §8 "Expected
   results" block** — the chain head, the verification triple, the
   completeness answer, the anchor head, the tree hash recomputed from
   the published leaves, the leaf count, and a verifying inclusion
   proof for leaf 7 of length 5.

That block is the pass bar: **an implementation that disagrees with any
of these is wrong, or the specification is** — the spec's own words, and
runs #1–#4 exercised both directions of that sentence.

Reproducing the §8 mutation demos (bit-flip, truncation, gap, stale
anchor, missing genesis, …) is a SHOULD: each one demonstrates a
diagnosis the format promises. The strongest prior finding came from a
demo constructed *more aggressively* than the published one — building
your own discriminating inputs is encouraged.

## 3. What to submit

Three things, per the protocol (`../INDEPENDENT-VERIFICATION.md` §6):

1. **Your verifier source** — any language; nothing about your method
   has to resemble anything of ours.
2. **The filled run record** — `RUN-RECORD-TEMPLATE.md` alongside this
   file, including the eligibility attestation.
3. **Your ambiguity log** — part of the template. "None" is a valid and
   valuable answer.

Submit by opening an issue on the repository titled
`PALA-1 verification run` with the three items attached, or by email to
the security contact in `SECURITY.md`. Every submission is answered;
runs that meet the eligibility condition are recorded in
`INDEPENDENT-VERIFICATION.md` §5 and archived byte-exact under
`independent-runs/<name>/`, where they become off-limits inputs for the
next fresh run.

## 4. What a divergence means

The wire is frozen: if your value disagrees with §8, either your
implementation is wrong or the *frozen* specification is — and the
second outcome is exactly what this process exists to catch. A confirmed
text defect is fixed as an erratum with the vectors byte-identical (this
has happened; see spec defect #4 in the §5 record); a confirmed **wire**
defect would be handled as a new format version, never as an edit to
v1.0. Minimize a divergence to the first differing byte before
submitting — it makes adjudication fast in both directions.
