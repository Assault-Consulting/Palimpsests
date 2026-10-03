<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# AAC verification run 2 — Class 1, from the `-05` text

Status: ran · 2026-10-03 · reproducible from this directory.

> The verifier was written from the text before any expected value was read; every number below is printed by the runner in this directory.

**Legend**

| Term | Meaning |
|------|---------|
| `spec-derived` | expected result hand-derived by the authors from the draft and RFC 8785 |
| `reference-derived` | expected result frozen from the authors' reference verifier |
| `unlabelled` | case carries no `provenance` label |
| `out_of_scope` | expected result depends on material `-05` does not define |
| `text_ambiguity` | `-05` admits more than one reading; the sentence is quoted |
| `text_vs_vectors` | `-05` states a rule; the vector expects otherwise; the sentence is quoted |
| `verifier_defect` | this verifier was wrong; fixed and reported |

---

## Pins

| Item | Value |
|---|---|
| Run kind | independent implementation from the text, checked against author-supplied vectors (not "with independent vectors") |
| Subject | `draft-mih-scitt-agent-action-capsule-05` (posted 2026-09-26) · `.txt` from the IETF archive · SHA-256 `c2a498fa561e6ee226fbdfca00415dfb7dfc108715ce345adaf21ba2a50c008e` |
| Also read, text only | `draft-mih-sokolov-scitt-payload-binding-05` (typed digest references, §8) · `.txt` from the IETF archive · SHA-256 `938073e7ce4f4289ca6d45bebac0b319f2a701804eac5c32203124e65f2fb4fa` · RFC 8785, not re-fetched for this run |
| Vectors | `action-state-group/agent-action-capsule` · tag `v0.6.0` → commit `13a1f4534c31369e927db73af6298e8b9ffdc36a` · `vectors/capsule/` (94 cases) · `provenance-mode-vectors/` (24 cases, separate corpus) |
| `SHA256SUMS` | `vectors/SHA256SUMS`: 190/190 `capsule/` lines OK, `README.md` and `manifest.json` OK · `provenance-mode-vectors/SHA256SUMS`: 48/48 OK · `LICENSE` (in neither list) `abfc9b0b…36eb9bc` |
| Corpus | `vectors/capsule/vectors.json` SHA-256 `b478fd599d736a76966f457a6ae7dd6e130d9813d8e92c11d9d58d090b15276a` · declares `"spec": "draft-mih-scitt-agent-action-capsule-05"`, `"format_versions": ["4"]` · 94 cases: 61 spec-derived, 5 reference-derived, 28 unlabelled |
| Environment | Python 3.12.3 · Ubuntu 24 (Linux 6.18, x86_64) · standard library only |
| By | Andrii Sparysh (Assault Consulting, Palimpsests project), with AI assistance — see Disclosure |
| Criterion | corpus README: `ok`, §6 check numbers + severities, derived modes, `capsule_id` · plus the count of `info` findings, as in run 1 |

- **Pin.** `main` had moved past `v0.6.0` at the time of the run; the run targets the release, by choice.
- **Boundary.** Verifier written from the `-05` text alone, with CPB-05 read for typed digest references. From the authors' repository, only the files `fetch_corpus.sh` fetches: `vectors/SHA256SUMS`, `vectors/manifest.json`, `vectors/README.md`, the `capsule/` corpus, `provenance-mode-vectors/`, `LICENSE` — one file at a time, from the pinned commit. No source code, specification sources, registries, issues, pull requests or commit messages.
- **Scope.** Class 1 (§6, §7). COSE Producer Envelope and Receipt verification are "by reference" (§6) and not implemented · Class 2 (§8.2) not implemented.

---

## Result

Numbers as printed by `run_vectors.py` — `results-headline.txt`, per case in `results-headline.json`. Nothing outside that run, except where marked *sensitivity*.

| Check | Result |
|---|---|
| `capsule_id`, `canonical-*` group (JSON-DIGEST) | **11 / 11** byte-identical |
| `capsule_id`, all `capsule` cases | **94 / 94** identical — where a case fails closed, both sides report no digest |
| `capsule_id`, `provenance-mode-vectors` | 24 / 24 identical |
| RFC 8785 `canonical_preimages` | 47 / 47 reproduced byte-for-byte |
| `ok` | **91 / 94** cases · 94 / 97 per Capsule (3 store cases contribute 6 member results, all agreeing) · misses: `reference-bad-capsule-id`, `reference-same-hex-other-type`, `reference-unregistered-capsule-token` |
| Rule stated in `-05`, contradicted by a vector | **2** `text_vs_vectors`, both unlabelled — below · run 1's "0 disagreements" does **not** carry over |

Strict is the run-1 criterion and is reported as such. 29 of its 39 non-agreements are one `info` finding `-05` does not define.

| | strict (run-1 criterion) | secondary (findings as a set; `info` count ignored) |
|---|---|---|
| `vectors/capsule`, all | **55 / 94** | 84 / 94 |
| — spec-derived | 53 / 61 | 54 / 61 |
| — reference-derived | 2 / 5 | 5 / 5 |
| — unlabelled | 0 / 28 | 25 / 28 |
| `provenance-mode-vectors` (never merged with the above) | 16 / 24 (all unlabelled) | 22 / 24 |

The secondary column is not the headline. Unfavourable numbers are not rounded.

### What the strict number measures

Of 39 strict non-agreements in `capsule`:

- **29** — the expected result carries one extra `info` finding, check 6: "chain parent-existence and concurrent-supersedes are store-level checks; not run without a store". `-05` defines no such finding; §6 check 6 is "(store-level)" and names no diagnostic for a missing store. 25 unlabelled · 3 reference-derived · 1 spec-derived.
- **10** — differ in substance (below).

*Sensitivity* — run after the expected values were seen · not part of the result · `--alt` in `run_vectors.py` · each reading one the text neither requires nor forbids. Store `info` finding alone: 84/94. All six alternative readings: 91/94 (spec-derived 61/61, reference-derived 5/5, unlabelled 25/28); provenance corpus 20/24 strict, 24/24 secondary. Remaining three misses: the two `text_vs_vectors` cases and `reference-bad-capsule-id`.

---

## Verifier defects

| # | Defect | Origin | Fix · text |
|---|---|---|---|
| D1 | `disposition` block required on every Capsule | carried over from run 1 | §5.1: `action_type` `"fyi"` is informational, `"decide"` is "a disposition was required"; §5.5's REQUIRED members are required *within* the block · block required only for `decide` |
| D2 | `references: null` treated as absent | first reading | §5.5.5: a Capsule "MAY carry a digested references array"; §2: null "participate[s] when present" · a present non-array `references` is a check-1 failure |

- **How they were found.** From the first corpus run's disagreements, not from re-reading the text. The fixes cite text; the discovery was prompted by a vector.
- **Effect.** First run, before D1/D2: also 55/94 strict — kept as `results-first-run-before-fixes.txt`. The fixes changed which cases disagree, not the count.
- **Added after the first run.** `--alt` sensitivity switches and the secondary column. Headline behaviour unchanged: `ALT` is empty in every headline run.

---

## Interpretations

Where the text is silent or open. The Corpus column says only what the vectors show; a reading that agrees is not thereby correct.

| # | Question | Section | Reading | Corpus |
|---|---|---|---|---|
| J1 | Members removed before the identity digest | §5.1, §6 check 2 | top-level `capsule_id`, `signature`, `key_id` only (the "local-only" envelope fields); nested members of those names are data · `chain`, `references`, `canonicalization_id` stay | agrees (`canonical-nested-member-named-*`) |
| J2 | Absent-field normalization | §2 | none: "null, empty arrays, and empty objects participate when present" (run 1's `normalize` step removed) | agrees (`spec-derived-v4-null-empty-members`) |
| J3 | Integer range | §2, RFC 8785 | outside ±(2⁵³−1) is a check-1 failure; floats likewise | agrees |
| J4 | What "fail closed" stops | §2, §5.1, §6 check 1 | stop at the declaration check: no digest, no mode derivation, no later check | **disagrees** — 6 cases, `text_ambiguity` |
| J5 | One check-1 finding, or one per bad declaration | §6 check 1 | one per failed declaration | **disagrees** — 2 cases |
| J6 | `ledger_mode` | §5.4 | `chained` from the Capsule's own well-formed `chain` block (parent id 64 lowercase hex, `relation` string) alone; parent resolution affects only check 6 | agrees (`neg-chain-missing-parent`) |
| J7 | `effect_mode`, `confirmed` without `response_digest` | §5.3 | `dispatched_unconfirmed` (now stated in the text) | agrees |
| J8 | `effect_mode`, unknown `effect.status` | §5.3 | `not_applicable` plus a check-1 error (Table 3, "one of five values") | not exercised |
| J9 | Severity, concurrent supersedes | §5.5.4 | `warning` ("MUST surface as a verification finding"; no severity given) | **disagrees** — expected `info` |
| J10 | Severity, assurance overclaims | §6 checks 7, 9 | `attestation_mode`, `ledger_mode`, `cross_party_rung` → `info` (check 9: "the informational overclaim treatment"); `effect_mode` stays `error` (not named there) | agrees |
| J11 | Under-claims | §5.4 | `info`, as in run 1 | agrees |
| J12 | Well-formed `counterparty_ref`, `correlator` | §5.4.1 | `counterparty_ref` = 64 lowercase hex · `correlator` = non-empty string · rung from the block's bytes alone · no block → `unilateral_fallback` | agrees (4/4 cross-party) |
| J13 | Well-formed typed digest reference | §5.5.5, CPB-05 §8 | object with non-empty string `type`, `digest_alg`, `digest`; representation not interpreted (no digest context resolved at Class 1) | agrees, except the AAC-type case |
| J14 | "Same target", §5.5.5 boundary rule | §5.5.5 | `digest_alg == "SHA-256"` and equal `digest`; `type` ignored ("keyed on {digest_alg, digest} alone") | **disagrees** — 2 cases, `text_vs_vectors` |
| J15 | Check number for `provenance_mode` problems | §6 check 9 | every `provenance_mode` malformation under check 9 | agrees on numbers |
| J16 | Check-9 findings per missing backfill member | §6 check 9 | one finding listing the members | **disagrees** — 2 cases |
| J17 | Backfill-only members under `contemporaneous` | §5.4.3 Table 7 | not an error: the table makes them REQUIRED for `backfilled` and requires `time_rung` absent otherwise | **disagrees** — 2 cases |
| J18 | Witnessed support for `provenance_mode.time_rung` | §5.4.3, check 9 | a well-formed `references[]` entry with `citation_purpose: "corroborates_source_time"` | agrees |
| J19 | `references.log_coordinates` | §5.5.6 | `{log_id: string, leaf_index: non-negative JSON integer, inclusion_proof present}`; proof not verified | agrees |
| J20 | `retention` | §5.5.6 | `declarant` non-empty string · at least one of `retained_until` / `not_retained_after`, each RFC 3339 · reported as carried | agrees |
| J21 | Registry values | §12.1 | seven registries, incl. `host_served_observed`, `inference_completion`, `follows`, `duplicates`, six `citation_purpose` values · unknown → `info`, never reject | agrees |
| J22 | Unknown `spec_version` | §5.1 | `info` under check 8; `-04` and `-05` accepted silently | not exercised |
| J23 | `human_disposed` honesty | §6, closing paragraphs | non-numbered `warning` when `human_disposed` is true with a non-human approver, as in run 1 | agrees (`honesty-dishonest-human-disposed`) |

---

## Non-agreements by class

Strict criterion. Every case: Appendix A.

| Class | `capsule` (39) | `provenance-mode` (8) | Here |
|---|---|---|---|
| `out_of_scope` | 30 | 4 | 29 + 4: an `info` diagnostic `-05` does not define (store-level note; `duplicate_collapsed` / `duplicate_parent_not_contemporaneous`) · 1: `reference-bad-capsule-id` expects validation as an "AAC Capsule ID for agent-action-capsule/SHA-256"; `-05` defines no such artifact-type token (type names are deferred to the CPB registry) |
| `text_ambiguity` | 7 | 4 | fail-closed scope (6) · concurrent-supersedes severity (1) · provenance corpus: finding multiplicity (2), contemporaneous orphan members (2) |
| `text_vs_vectors` | 2 | 0 | below |
| `verifier_defect` | 0 | 0 | D1, D2 fixed before the headline run |

> Case names beginning `reference-` exercise the §5.5.5 `references[]` member — the prefix is not the `provenance` label. All 26 such cases are unlabelled, as are `pos-v4-jcs-chain-committed` and `neg-v4-chain-tampered` (28 in all).

### `text_vs_vectors` — 2 cases, both unlabelled

`reference-same-hex-other-type` · `reference-unregistered-capsule-token`

- **Vectors.** `ok: true` — a references entry with a different `type` but the same `{digest_alg, digest}` as `chain.parent_capsule_id` is *not* a duplicate of the chain parent ("same digest under another artifact type is not the chain parent").
- **Text, §5.5.5.** "A references entry's target is identified solely by the {digest_alg, digest} pair" · "Comparison, deduplication, and cross-record correlation over references entries therefore key on {digest_alg, digest} alone" · a references entry "MUST NOT name the same target as chain.parent_capsule_id".
- **Reading.** `type` is not part of identity; the verifier reports check 6. The text could be amended if `type` is meant to participate.
- **Provenance.** Neither case is labelled, so the corpus does not say whether the expected results follow the text or the reference implementation.

### `text_ambiguity`

- **Fail-closed scope** — 6 spec-derived cases. §2: "MUST fail closed" · §6 check 1: "Any other format or canonicalization declaration fails closed." The vectors expect a Capsule declaring format 3, or a missing / `jcs-n` / non-string `canonicalization_id`, still to get `ledger_mode: chained` (and in `neg-v2-canonicalization-*`, `effect_mode: confirmed`) with one check-1 finding: modes derived from the bytes, digest withheld. The text does not say whether derived fields are reported after a fail-closed declaration.
- **Concurrent supersedes.** §5.5.4: "structurally valid but MUST surface as a verification finding" — no severity. Expected `info`; this verifier emits `warning` (F4, run 1 — unchanged).
- **Contemporaneous orphan members** — `neg-provenance-mode-contemporaneous-orphaned-fields*`. §5.4.3 Table 7 requires `source_ref`, `source_asserted_at`, `import_batch`, `imported_at` "when mode is backfilled", and `time_rung` absent unless backfilled; nothing about the other four under `contemporaneous`. Expected `ok: false`.

---

## Delta against run 1

Run 1: 55/69 · 14 non-agreeing: 7 format-3/4 + `canonicalization_id`, 4 cross-party, 1 `approver: counterparty`, 2 store-level. Case names changed between corpora (`test-vectors/` → `vectors/capsule/`; e.g. `neg-v2-canonicalization-declared` is gone, the v2 negatives are now `-absent` / `-null`) — mapped by category.

| Run-1 non-agreement | Run 2 (strict) | `-05` |
|---|---|---|
| `pos-disposition-approver-counterparty` (F1) | **agrees** | §5.5 (three-member closed enum) |
| 4 cross-party cases (F1) | **4/4 agree** | §5.4.1 |
| `neg-chain-missing-parent` (F2) | **agrees** | §5.4 ("never downgrades ledger_mode") |
| `pos-concurrent-supersedes` (F4) | disagrees (severity) | §5.5.4 gives none |
| `pos-v4-jcs-chain-committed`, `neg-v4-chain-tampered` | agree on `ok`, checks, modes, `capsule_id` · strict miss is the store-note `info` only | §2, §5.1, §6 checks 1–2 |
| `neg-v3-format-version-unsupported`, `neg-v4-canonicalization-{missing,jcs-n,non-string}` | disagree (`ledger_mode` after fail-closed) | §2, §6 check 1 |
| `neg-v2-canonicalization-declared` | not in corpus · successors `neg-v2-canonicalization-{absent,null}` disagree | §2, §6 check 1 |

**Run-1 findings:** F1 (vectors pinned to an unpublished revision) resolved at this pin — vectors declare `-05`, text is public · F2 resolved (§5.4) · F3 resolved (§5.3) · F4 open · F5 (under-claims) unaddressed by the text; this verifier reports `info`.

**New in run 2:** 2 `text_vs_vectors` · no defined diagnostic for "store not supplied" · no AAC artifact-type token · no stated rule for what a fail-closed Capsule still reports.

---

## Boundary incidents

None that break the boundary stated above. Everything seen outside the text of `-05` / CPB-05:

- `vectors/SHA256SUMS` (allowed): path names of out-of-scope corpora (`cross-language/`, `disclosure-envelope/`, `interop/`, `producer-envelope/`) · names only, none fetched.
- `vectors/README.md` (allowed) names generator scripts under `python/scripts/` · not opened.
- Before the verifier was written: key names (not values) of `expected.json` across `capsule` cases · first 600 characters of two `canonical-*` `input.json` files · one provenance case's `expected.json` key names · all allowed files.
- After the first run: expected findings and descriptions of specific disagreeing cases in `vectors.json` and `expected.json` · allowed files, used for diagnosis (see Verifier defects).
- Palimpsests (own repository): run-1 files, `CONTRIBUTING.md`, `pyproject.toml` (ruff settings) · one unauthenticated GitHub API call rate-limited.
- Authors' side otherwise untouched: no clone, archive, tree browse, issue, PR, commit message or release note · `capsule-emit`, `scitt-cose`, `capsule-anchor` not touched.

---

## Reproduce

```
bash fetch_corpus.sh corpus            # allowed files only, from the pinned commit; verifies SHA256SUMS
python3 run_vectors.py corpus/vectors/capsule corpus/provenance-mode-vectors
python3 run_vectors.py corpus/vectors/capsule corpus/provenance-mode-vectors --alt store_info   # sensitivity only
```

---

## Disclosure

The run is by Andrii Sparysh, performed with an AI assistant under the boundary stated above; the `-05` and CPB-05 texts were taken from the IETF archive. Every number above was produced by the verifier and runner in this directory; the results files are their unedited outputs.

---

## Appendix A — every strict non-agreement, one class each

Ours / expected.

| case | provenance | class | difference |
|---|---|---|---|
| `pos-v4-jcs-chain-committed` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `neg-v3-format-version-unsupported` | spec-derived | text_ambiguity (fail-closed scope) | derived.ledger_mode standalone/chained; info-count 0/1 |
| `neg-v4-chain-tampered` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `neg-v4-canonicalization-missing` | spec-derived | text_ambiguity (fail-closed scope) | derived.ledger_mode standalone/chained; info-count 0/1 |
| `neg-v4-canonicalization-jcs-n` | spec-derived | text_ambiguity (fail-closed scope) | derived.ledger_mode standalone/chained; info-count 0/1 |
| `neg-v4-canonicalization-non-string` | spec-derived | text_ambiguity (fail-closed scope) | derived.ledger_mode standalone/chained; info-count 0/1 |
| `neg-v2-canonicalization-absent` | spec-derived | text_ambiguity (fail-closed scope) | derived.effect_mode not_applicable/confirmed; findings [(1, 'error'), (1, 'error')]/[(1, 'error')] |
| `neg-v2-canonicalization-null` | spec-derived | text_ambiguity (fail-closed scope) | derived.effect_mode not_applicable/confirmed; findings [(1, 'error'), (1, 'error')]/[(1, 'error')] |
| `pos-concurrent-supersedes` | spec-derived | text_ambiguity (severity) | findings [(6, 'warning')]/[]; info-count 0/1 |
| `reference-absent` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-bad-capsule-id` | unlabelled | out_of_scope (no AAC artifact-type token in -05) | ok True/False; findings []/[(1, 'error')]; info-count 0/1 |
| `reference-boolean-digest` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-duplicate-parent` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-empty` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-empty-algorithm` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-empty-digest` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-external-capsule` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-future-extension` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-future-purpose` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 1/2 |
| `reference-local-only-envelope-fields` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-missing-type` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-mixed-checks` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 1/2 |
| `reference-nonobject-reference` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-nonstring-purpose` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-null-coordinates` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-null-digest` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-null-references` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-object-references` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-opaque-proof` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-partial-coordinates` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-same-hex-other-algorithm` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-same-hex-other-type` | unlabelled | text_vs_vectors | ok False/True; findings [(6, 'error')]/[]; info-count 0/1 |
| `reference-tampered-after-seal` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-unknown-type-algorithm` | unlabelled | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `reference-unregistered-capsule-token` | unlabelled | text_vs_vectors | ok False/True; findings [(6, 'error')]/[]; info-count 0/1 |
| `spec-derived-v4-chain` | spec-derived | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `pos-v05-spec-version-chain-committed` | reference-derived | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `pos-v05-chain-follows` | reference-derived | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| `pos-v05-reference-counterparty-half` | reference-derived | out_of_scope (undefined store-level info finding) | info-count 0/1 |
| pm/`neg-provenance-mode-backfilled-missing-fields` | unlabelled | text_ambiguity (finding multiplicity) | findings [(9, 'error')]/[(9, 'error'), (9, 'error'), (9, 'error'), (9, 'error')] |
| pm/`neg-provenance-mode-backfilled-missing-fields-v05` | unlabelled | text_ambiguity (finding multiplicity) | findings [(9, 'error')]/[(9, 'error'), (9, 'error'), (9, 'error'), (9, 'error')] |
| pm/`neg-provenance-mode-contemporaneous-orphaned-fields` | unlabelled | text_ambiguity (contemporaneous orphan members) | ok True/False; findings []/[(9, 'error')] |
| pm/`neg-provenance-mode-contemporaneous-orphaned-fields-v05` | unlabelled | text_ambiguity (contemporaneous orphan members) | ok True/False; findings []/[(9, 'error')] |
| pm/`pos-chain-duplicates-collapsed-once` | unlabelled | out_of_scope (undefined info diagnostic) | info-count 0/1 |
| pm/`pos-chain-duplicates-collapsed-once-v05` | unlabelled | out_of_scope (undefined info diagnostic) | info-count 0/1 |
| pm/`pos-chain-duplicates-parent-backfilled` | unlabelled | out_of_scope (undefined info diagnostic) | info-count 0/2 |
| pm/`pos-chain-duplicates-parent-backfilled-v05` | unlabelled | out_of_scope (undefined info diagnostic) | info-count 0/2 |
