<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# AAC verification run 1 — an independent Class-1 verifier from the draft text

| | |
|---|---|
| **Subject** | `draft-mih-scitt-agent-action-capsule-02` (posted 2026-07-06; latest revision on the datatracker as of this run) |
| **Vectors** | `action-state-group/agent-action-capsule` @ `bb648e15` (2026-08-30), `test-vectors/` — 69 cases; `vectors.json` SHA-256 `688955bd…3830`; `SHA256SUMS` re-verified, 138/138 OK |
| **Verifier** | `aac_verify_ref.py`, standard library only (SHA-256 in `SHA256SUMS` beside it) — written from the -02 text; the reference implementation's source was **not** read |
| **Scope** | Class 1 (§6, §7): payload-layer checks. COSE_Sign1 / Receipt verification is "by reference" (§6) and out of scope by the draft's own split |
| **Date / by** | 2026-09-04, Assault Consulting (Palimpsests project) |
| **Conformance criterion** | the vectors' README: agreement on `ok`, the §6 check numbers + severities, the derived modes, and `capsule_id` |

## Result

**55 / 69 cases agree.** Of the 14 that do not, 12 exercise material that is not in the posted -02 text, 1 is a genuine ambiguity in the text, and 1 is a severity the text leaves open. No case disagrees on a rule the -02 text actually states.

| Group | Cases | Agree | Note |
|---|---|---|---|
| JSON-DIGEST construction (§2): normalize + JCS | 24 `canonical-*` | **24 / 24** | byte-identical digests on the first run, including the UTF-16 key-order, NFC/NFD, non-BMP, control-char and integer-range edges; exceptions raised where expected |
| Format-2 single-capsule positive | 18 | 17 / 18 | the one miss is `approver: counterparty` (below) |
| Format-2 negative / honesty | 12 | 11 / 12 | the one miss is `neg-v2-canonicalization-declared` (below) |
| Store-level (ledger) | 3 | 1 / 3 | concurrent-supersedes severity; missing-parent ledger_mode (below) |
| Cross-party | 4 | 0 / 4 | not in -02 |
| Format 3 / 4, `canonicalization_id` | 7 | 1 / 7 | not in -02 |
| Format 1 rejected | 1 | 1 / 1 | |

`capsule_id` recomputed identically on **every** format-2 capsule (37/37) and every canonical case — the canonical-form definition in §5.1 plus §2 is sufficient to reproduce the content address from the text alone.

## Findings

### F1 — The frozen vectors are pinned to a revision that is not published

`test-vectors/vectors.json` declares `"spec": "draft-mih-scitt-agent-action-capsule-04"` and `"format_versions": ["2", "4"]`. The datatracker holds -00, -01, -02; -02 says `format_version` is `"2"` and defines no other. A third party building from the public text therefore cannot reproduce 12 of 69 cases by construction:

- **Format 3/4 and `canonicalization_id`** (7 cases): `pos-v4-jcs-chain-committed`, `neg-v3-format-version-unsupported`, `neg-v4-chain-tampered`, `neg-v4-canonicalization-{missing,jcs-n,unknown,non-string}`, `neg-v2-canonicalization-declared`. The -02 text has no `canonicalization_id` member, no format 4, and no rule for format 2 rejecting such a member. A -02 verifier fails them at check 1 as an unknown `format_version` (this run's choice — see I3), which happens to agree with the expected `ok=false` on the negatives and to disagree on the one positive.
- **`cross_party` / `assurance.cross_party_rung`** (4 cases): a fourth derived mode the -02 text does not define; the "bilateral" material is referenced only as a companion draft (§11).
- **`disposition.approver: "counterparty"`** (1 case, `pos-disposition-approver-counterparty`, expected `ok=true`). This one is not merely absent from -02 — it **contradicts** it: §5.5 says approver is "a closed enum, exactly `human` or `policy` … an unknown approver value is not a conforming Capsule", and §6 repeats that the closed enum is structural. A -02 verifier must fail this capsule at check 1, and does.

Suggested resolution: either post -03/-04 so the vectors and the public text agree, or split the corpus so a -02 verifier can be scored against the -02 subset. The README's stated conformance criterion assumes the reader has the same spec the generator had.

### F2 — `ledger_mode` derivation when the chain parent is missing (ambiguity)

`neg-chain-missing-parent`: the reference derives `ledger_mode: "chained"` and reports only the check-6 error. §5.4 defines "chained" as "a Capsule whose hash-chain linkage to a predecessor is present **and intact**" and asks the verifier to rederive it "from the bytes it can check". With the parent absent from the store the linkage is present but not intact, so the text-faithful derivation is `standalone`, and the declared `chained` is then an overclaim (check 7) in addition to the check-6 error. Both readings are defensible; the text should say which — specifically, whether parent existence is part of "intact" or exclusively check 6's concern.

### F3 — `effect_mode` derivation when `confirmed` lacks its binding (text gap, resolved by §5.4)

`neg-confirmed-without-response` and `neg-never-dispatch-confirmed-no-response`: `effect.status: "confirmed"` with no `response_digest`. §5.3 only says this is a check-3 failure; it does not say what `effect_mode` a verifier *derives*. A literal derivation from `status` gives `confirmed`; the reference derives `dispatched_unconfirmed`. Reading §5.4 ("rederived from the evidence present") and §5.3 ("confirmed is an observed result, never a promise") supports the reference — the evidence present is a dispatch without a bound result — and this verifier now does the same and agrees. Recommend stating the derivation rule explicitly in §5.3, next to the invariant.

### F4 — Severity of the concurrent-supersedes finding (open)

§5.5.4: a later supersedes "is structurally valid but MUST surface as a verification finding". The reference uses `info`; this verifier chose `warning` (a valid-but-suspicious condition). The text does not say. Minor, but the README's criterion counts severities, so it should.

### F5 — Assurance under-claims

§5.4 asks verifiers to report *overclaims*. A capsule declaring a weaker mode than derived (e.g. `dispatched_unconfirmed` where the bytes support `confirmed`) is not addressed. This verifier reports it as `info`; the reference is silent. Worth one sentence.

## Interpretations made (where the text is silent)

| # | Question | Choice | Confirmed by vectors? |
|---|---|---|---|
| I1 | "minus capsule_id and chain-linkage fields" — top-level only? | Top-level `capsule_id` and `chain`; nested members of those names are data | Yes (`canonical-nested-member-named-*`) |
| I2 | Integer range | JCS numbers are IEEE doubles (RFC 8785 → I-JSON); beyond ±(2⁵³−1) is a check-1 failure | Yes (`canonical-integer-*`, `neg-unsafe-integer-*`) — but the rule comes from RFC 8785, not the draft |
| I3 | Unknown `format_version` | Check-1 failure; -02 defines one value and no forward-compat rule | Yes for "1"; the "3"/"4" cases are F1 |
| I4 | `effect_mode` for an unrecognised `effect.status` | `not_applicable` (no dispatch evidenced) | Not exercised |
| I5 | `ledger_mode` when a chain block is present but no store is supplied | `chained` (linkage present; existence is a store-level check) | Yes (`neg-v3`, single-capsule expected `chained`) |

## What this run does not claim

It does not verify COSE envelopes or Receipts, does not touch Class 2, and says nothing about the producer library (`capsule-emit`) — only about whether a verifier can be built from the posted text and agree with the frozen expectations. It can, for everything -02 defines.

## Reproduce

```
git clone https://github.com/action-state-group/agent-action-capsule && cd agent-action-capsule && git checkout bb648e15
cd test-vectors && sha256sum -c SHA256SUMS
python3 <palimpsests>/docs/interop/aac-verification-run-1/aac_verify_ref.py <case>/input.json
python3 <palimpsests>/docs/interop/aac-verification-run-1/run_vectors.py .   # whole corpus, per-case agreement
```
