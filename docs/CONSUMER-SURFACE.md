# Consumer public surface — towards 1.0

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

**Status:** proposal r2, agreed as the plan for the reading surface from 0.13 to 1.0. The contract in force today is [INTEGRATION-SURFACE.md](INTEGRATION-SURFACE.md); this document is how it becomes the 1.0 contract.

Oct 17, 2026 · @Andriy Sparysh · **r2, Oct 18, 2026:** Palimpsests-side review folded in — five gaps added, the six open questions decided, a work plan added. Changes from r1 are marked **(r2)**.

## Purpose and scope

Palimpsests 1.0 is gated on a stable public API. Palimpsests already documents a consumer contract: `docs/INTEGRATION-SURFACE.md`, seven channels with a "public" stability class, Auditor named as first consumer. This proposes its 1.0 revision for reader-side consumers, drawn from what Auditor actually uses, and lists what must change before the 0.13 tag.

- **In scope:** tools that open a PALA-1 container, ask the three questions, browse records and resolve anchors. Auditor today; any third-party verifier tomorrow.
- **Out of scope:** the writer and runtime API, `serve` and its HTTP surface, CLI flags, the encrypted `AuditLog`. Each deserves its own contract; mixing them would freeze the wrong things.
- **Not narrowed (r2):** channels 2–6 of `INTEGRATION-SURFACE.md` — report, proofs, bundle, health, conformance — are public since 0.10 and stay public under their own module names. This document defines the *reading* surface; it does not demote the others. Where a symbol is re-exported into `reader` for convenience, both import paths are covered by the contract test and neither is deprecated.
- **Why before 0.13:** 0.13 adds new verdict output — three diagnosis patterns (two for continuations, and `not_a_container` from U22), six advisory codes, tool outcome names, a manifest read beside the file. Whatever ships as a field in 0.13 is what 1.0 must keep. Shaping it now is cheaper than deprecating it later.
- **Evidence base:** Palimpsests `main` at `84c6051` (after #294 and #295); Auditor `main` at `d53d56b`. Auditor's full sidecar suite passes against Palimpsests `main` and against both open 0.13 branches, #296 and #297: 324 passed, 6 skipped (PKCS#11 not installed). Nothing is broken today; the work below is about what gets promised. **(r2)** Every claim of r1 was re-checked against `84c6051`; all hold. One precision: `pala.incremental` does declare `__all__` — it is simply not a consumer module.

## What "stable" means

Stable means a consumer written against 1.0 keeps working, and keeps meaning the same thing, until 2.0. Eight rules make that checkable.

1. **One place to import from.** A symbol is public only if it appears in the `__all__` of a consumer module listed in the next section, or of a public channel module (channels 2–6). Anything reached by another path is internal, even if it is importable. `INTEGRATION-SURFACE.md` names the same set by channel; the two lists must agree, and the contract test (U20) checks that they do.
2. **No removal, rename or signature change within a major.** New keyword-only parameters with defaults are allowed.
3. **Additive fields are allowed.** Result types are frozen dataclasses; a minor may add fields with defaults. Consumers must not rely on positional construction or field order.
4. **`None` semantics are part of the contract.** Where a field documents what `None` means, that meaning is frozen. Changing what `None` stands for is a breaking change even if the type is unchanged. **(r2)** Where `None` carries two meanings, the contract fixes the pair that tells them apart. `kind_name` is the case today: `kind is None` means the record carries no kind (not an EVENT/SAFETY body, no body, or an encrypted one); `kind is not None and kind_name is None` means a kind this build does not know. `complete_to_anchor is None` means not checked.
5. **Numeric values are frozen by the spec; names may grow.** A record type, kind, tier or outcome number never changes meaning. A name table may gain entries; consumers must handle a `None` name for a value they do not know.
6. **Pattern and code vocabularies are open.** A minor may add a diagnosis pattern, an advisory code or a violation code. Consumers must render an unknown one rather than fail. Existing ones are never renamed or repurposed.
7. **Machine fields are stable; sentences are not.** `pattern`, `code`, `at_seq` and the violation codes (U24) are contract. `narrative`, `detail`, `anchor_reason` and every violation *reason* are the verifier's words: carried verbatim, never parsed. **(r2)** `Diagnosis.expected` moves to the sentence side: for `record_violation` it is the violation's reason, which can embed an exception's text (`malformed TLV: …`). Anything a consumer needs to branch on must be a field, never only a sentence.
8. **Deprecation takes one minor.** A deprecated symbol keeps working for at least one minor release and emits `DeprecationWarning`, with the replacement named in the warning text.

**When the rules apply (r2).** The "public" class in `INTEGRATION-SURFACE.md` today allows a breaking change with a minor bump and a changelog entry — the pre-1.0 regime. The eight rules are the 1.0 regime, phased in:

- **Rules 4–7 (semantics and vocabularies) apply from 0.13.** 0.13 is the release that ships new patterns, codes and names; a consumer pinned to 0.13 must be able to rely on what they mean.
- **Rules 1–3 and 8 (structure and deprecation) apply from 1.0.** Until then the pre-1.0 class holds for symbols, with every break named in the changelog.

## Evidence: what Auditor uses today

Auditor touches Palimpsests from one file, `pala_seam.py` (its ADR-0001). It imports from nine modules; only four of them declare `__all__`, but `INTEGRATION-SURFACE.md` declares three more public by channel (`bootstats`, `timehealth`, `report`). Two imports reach undeclared paths: `pala.codec` and `pala_writer`.

| What Auditor uses | Imported from | Declared public today | Used for |
| --- | --- | --- | --- |
| `AuditReader` (`open`, `close`, `verify`, `records`, `boots`, `spans`, `origin_at`, `unloaded_at`, `acknowledged_candidates`, `shredded_targets`) | `audit.reader` | Yes | Everything below the verdict |
| `DecodedRecord` fields | via `records()` | Yes | Record card, filters, lists |
| `Header` fields (`record.header.*`) | type in `audit.pala` | In `pala.__all__`, not in `reader.__all__` | Boot, span, predecessor, clocks, tier, trust, key id, body length |
| `VerifyResult` (`verification.chain`) | `audit.pala.verify` | In `pala.__all__` only | Question one: links, gaps, breaks, violations |
| `Advisory`, `AdvisoryItem` | `audit.pala.incremental` | Not in a consumer module | Advisory lane |
| `ManualAnchor`, `FileAnchor`, `ChainedAnchorSource`, `AnchorReading`, `AnchorSourceError`, `AnchorAttempt` | `audit.anchors` | Yes | Anchor profiles and provenance |
| `Pkcs11Anchor`, `Pkcs11Unavailable`, `DEFAULT_OBJECT_LABEL` | `audit.anchors_pkcs11` | Yes | Hardware anchors |
| `assurance_tier_name`, `time_trust_name` | `audit.names` | Yes | Names beside raw values |
| `boot_statistics` | `audit.bootstats` | Yes — channel 5; no `__all__` | Uptime, anchor cadence, span stats |
| `step_catalog` | `audit.timehealth` | Yes — channel 5; no `__all__` | Clock steps on the date rail and in `/nearest` |
| `build_report(...).data["container"]` | `audit.report` | Yes — channel 2 | The body-digest walk (question one, second half) |
| `FORMAT_VERSION`, `RT_SAFETY`, `ZERO16`, `ZERO32` | `audit.pala.codec` | No `__all__` | Wire version label; SAFETY filter; "no span" and "no predecessor" sentinels |
| `KIND_INCIDENT_CANDIDATE` | `audit.pala_writer` | No `__all__` | Scoping `acknowledged` to candidates |

The real problems, not the missing `__all__` lines:

- **A reader-side consumer imports the writer module** to get a kind constant. The reader does the same by design — its docstring names the writer's kind table as the single source for kind names — so the fix is to move that table into a module both import, not to call the import a mistake.
- **The body-digest walk is reachable only by building a report.** The report and its schema are public (channel 2), but half of question one has no typed call of its own.
- **`ZERO16` and `ZERO32` are wire-level sentinels.** Every consumer must know that sixteen zero bytes mean "no span" to avoid printing a span called `0000…`. That knowledge belongs in the reader, not in each consumer.
- **(r2) The verifier branches on its own sentences.** Core violations are `(seq, reason)` pairs, and the reader derives `prefix_absent` by testing `(0, "chain does not start with a GENESIS record") in chain.violations`. The same reasons go into the report's `violations` list. A consumer that wants to react to a specific violation has nothing to branch on but the sentence — which rule 7 says it must never parse. See U24.

## The proposed stable surface

Two consumer modules for reading: `palimpsests.audit.reader` for everything about reading and verifying, `palimpsests.audit.anchors` (with `anchors_pkcs11`) for where trusted heads come from. Channels 2–6 stay public beside them (r2). Most of the surface already exists. The work is re-exporting it from one place, typing one more answer, adding one vocabulary, and bringing `INTEGRATION-SURFACE.md` up to date.

**Status:** *Exists* = already in a consumer `__all__`. *Export* = exists, add to `reader.__all__` (a re-export, no move). *New* = to be written.

| Area | Symbols | Status |
| --- | --- | --- |
| Open and close | `AuditReader.open(path, *, anchor=None)`, `AuditReader.from_bytes(data, *, anchor=None)`, `close()`, context manager | Exists |
| Not a container | Diagnosis `not_a_container` when byte 0 is not the record magic; `open` and `from_bytes` do not raise on such a file | Exists — 0.13 (U22, #297) |
| Empty container (r2) | Diagnosis `empty_container` for a file with no bytes | New (U26) — after 0.13 |
| Question one: links | `verify() -> Verification`; `Verification.chain: VerifyResult` (`chain_ok`, `count`, `head`, `breaks`, `gaps`, `violations`, `uninterpretable`) | Exists — 0.14 (U19) |
| Violation codes (r2) | `VerifyResult.violation_codes: list[tuple[int, str]]`, parallel to `violations`; `Diagnosis.code` for `record_violation` | New (U24) — after 0.13, before 1.0 |
| Question one: bodies | `container_check() -> ContainerCheck` (`well_formed`, `malformed`, `bytes_parsed`, `bytes_total`, `body_digest_mismatches`) | New (U21) — after 0.13 |
| Question two | `Verification.complete_to_anchor`, `anchor_lag`, `anchor`, `anchor_attempts`; `VerifyResult.anchor_reason` (a sentence) | Exists |
| Diagnosis | `Diagnosis` (`pattern`, `at_seq` — contract; `expected`, `narrative` — sentences) | Exists |
| Companion files | `Verification.manifest: ManifestReading \| None` (`path`, `status`, `sha256`, `detail`) | Exists — 0.13 (U17, #296) |
| Advisory | `Advisory`, `AdvisoryItem` (`code`, `at_seq`, `boot_id`, `detail`) | Exists — 0.14 (U19) |
| Records | `records()`, `safety_records()`, `head()`, `DecodedRecord`, `Header` | Exists; export `Header` |
| Random access | `record_at(index)`, `record_by_seq(seq) -> DecodedRecord \| None`, `header_at(index) -> Header \| None`, `record_count` | Exists — 0.13 (U16, #294) |
| Structure | `boots()`, `spans()`, `structure()`, `BootView`, `SpanView` | Exists |
| Boot statistics | `boot_statistics(reader)`, `BootStats`, `AnchorCadence`, `SpanStats` | Exists — 0.14 (U19); channel 5 path kept |
| Resolutions | `acknowledged_candidates()`, `shredded_targets()`, `origin_state_at(seq) -> OriginState`, `OriginView` | Exists; bounded since 0.13 (U23, #295) |
| Clock health | `step_catalog(reader)`, `TimeStep` | Exists — 0.14 (U19); channel 5 path kept |
| Segments | `ContinuationView`, `decode_continuation` | Exists |
| Constants | `RT_*`, `KIND_*`, `OUTCOME_*`, `SOURCE_*`, `DISP_*`, `TIER_*`, `TIME_*`, `FORMAT_VERSION`, `NO_SPAN`, `NO_PREDECESSOR` | Exists — 0.14 (U19); the profile's numbers live in `audit.profiles.inference`, the last two are aliases of `ZERO16`, `ZERO32` |
| Names | `assurance_tier_name`, `time_trust_name` | Exists |
| Anchors | `AnchorSource`, `AnchorReading`, `AnchorSourceError`, `AnchorAttempt`, `ManualAnchor`, `FileAnchor`, `ChainedAnchorSource` (incl. `last_attempts`), `Pkcs11Anchor`, `Pkcs11Unavailable`, `DEFAULT_OBJECT_LABEL` | Exists |

Shape decisions behind the table:

- **`container_check()` is a method, not a field of `Verification`.** The body walk costs a second pass; a consumer that only browses should not pay it. `build_report` keeps calling it internally.
- **`record_by_seq` returns `None`, never raises,** for a seq the file does not hold. A segment covering 400–900 has no record 12; that is an answer, not an error.
- **`origin_at` and `unloaded_at` stay, superseded.** `origin_state_at` answers both in one call; the two older methods are deprecated in the minor after 1.0, not before.
- **The package root stays light.** `palimpsests.audit` keeps re-exporting `AuditReader` only; a consumer that needs more imports from `reader`.
- **(r2) Violation codes are additive, not a reshape.** `violations` keeps its `(seq, reason)` pairs — consumers and the report schema already carry them. `violation_codes` is a parallel list of `(seq, code)`, same order, one entry per violation. The reader's own `prefix_absent` derivation moves to the code.

## Vocabularies

Two kinds of vocabulary cross the surface, and they get different promises. Numbers are frozen by the spec and never repurposed. Names, diagnosis patterns, advisory codes and violation codes are open: a minor may add members, never rename or repurpose one.

| Vocabulary | Members | Kind |
| --- | --- | --- |
| Diagnosis `pattern` (10 once #297 lands; 11 with U26) | `not_a_container` (U22), `empty_container` (U26), `truncated_tail`, `prefix_absent`, `seq_gap`, `chain_break`, `record_violation`, `unanchored_tail`, `replaced_or_rolled_back`, `declared_continuation`, `continuation_contradicts_manifest` | Open |
| Advisory `code` (17) | `anchor_never_written`, `mid_boot_time_trust_change`, `mono_regression_in_boot`, `wall_regression_in_boot`, `span_unclosed`, `span_unopened`, `reference_hash_mismatch`, `reference_unresolved`, `ack_target_not_a_candidate`, `tool_target_not_a_call`, `shred_target_key_mismatch`, `shred_target_unresolved`, `continuation_malformed`, `continuation_predecessor_mismatch`, `continuation_index_not_increasing`, `continuation_index_gap`, `continuation_prior_root_mismatch` | Open |
| **(r2)** Violation `code` (10, U24) | `prefix_absent`, `genesis_not_first`, `genesis_prev_hash_nonzero`, `header_len_mismatch`, `malformed_tlv`, `time_trust_undefined`, `time_unknown_with_wall_clock`, `empty_body_digest_nonzero`, `nonempty_body_digest_zero`, `encrypted_body_too_short` — one per reason the verifier emits today | Open |
| `outcome_name` | `ok`, `error`, `timeout`, `cancelled`, `unobserved` | Open names over frozen numbers |
| `source_name` | `parsed-from-wire`, `reported-by-client` | Open names over frozen numbers |
| `disposition_name`, `kind_name`, `type_name`, tier and time-trust names | As in the spec | Open names over frozen numbers |
| `ManifestReading.status` | `matches`, `contradicts`, `declared_only` | Open |

What each side owes:

- **Palimpsests:** a contract test lists every member above. Adding one makes that test fail until it is updated, so every addition is a deliberate, changelog-visible act — not a side effect of a feature PR.
- **Palimpsests:** each new pattern or code ships with one sentence in the changelog saying what it means and whether it changes a verdict. Advisory codes never do; that rule is already in the spec and stays.
- **Consumers:** render an unknown pattern or code with the verifier's own sentence and say plainly that this build has no guidance for it. Never hide it, never map it to a known one.

The 0.13 additions show why the last rule matters. `declared_continuation` is the *explained* case — a prefix removed under a declared policy. `continuation_contradicts_manifest` is among the most serious diagnoses the verifier can produce. A consumer that treats both as "unknown failure" is wrong in opposite directions, which is why Auditor ships guidance for both before it moves its pin to 0.13.

## Gaps to close, in order

Twelve changes turn today's code into the surface above. Two are 0.13 release blockers (U17, U22); one more is documentation and should go in before the tag because it is cheap and states what 0.13 promises (U25).

| ID | Change | Why | When |
| --- | --- | --- | --- |
| U17 | `Verification.manifest`: the path read, `matches` / `contradicts` / `declared_only`, and the SHA-256 of the bytes read | The 0.13 diagnosis depends on a second file; a consumer must be able to name, hash and re-check it | Done (#296) |
| U22 | A `not_a_container` diagnosis when byte 0 is not the record magic | `verify()` diagnosed a non-chain as `truncated_tail` — a false sentence in a published verdict | Done (#297) |
| **U25 (r2)** | `INTEGRATION-SURFACE.md` refresh: rules 4–7 apply from 0.13; the `kind_name` pair; channel 3 names the consistency proofs (`chain_root`, `consistency_proof`, `ConsistencyProof`, since 0.12); the SCITT bridge listed as **experimental** until bridge run B3 reproduces construction v3 | The document already lags the code; what 0.13 promises must be written down when 0.13 ships | Before the 0.13 tag — docs only; this document lands with it |
| U16 | `record_at`, `record_by_seq`, `header_at`, `record_count` | One record cost a full decode: 16.9 s and 1.9 GB at 1M records | Done (#294) |
| U23 | Bounded `shredded_targets()` and origin methods | A record card asked for both and paid a full decode | Done (#295) |
| U19 | Re-exports into `reader.__all__` (`VerifyResult`, `Header`, `Advisory`, `AdvisoryItem`, `boot_statistics`, `step_catalog`, the constants); `NO_SPAN`, `NO_PREDECESSOR`; inference-profile constants moved to `audit/profiles/inference.py` (see decision 2) | No reader-side consumer should need the writer, the codec or an undeclared module | Done (0.14) |
| U20 | Contract test `tests/test_consumer_surface.py`: every symbol, field and vocabulary member in this document, both import paths for re-exports, asserted by name | Makes "stable" checkable in CI | Done (0.14) |
| **U24 (r2)** | Violation codes: `VerifyResult.violation_codes` parallel to `violations`; `Diagnosis.code` for `record_violation`; the reader's `prefix_absent` test moves from the sentence to the code; the report gains the codes additively, within `pala-verification-report/1` | Rule 7 cannot hold while the verifier itself branches on a sentence and consumers have nothing else | After 0.13; **required before 1.0** |
| U21 | `container_check() -> ContainerCheck` | Half of question one is reachable only through a report | After 0.13 (additive) |
| **U26 (r2)** | `empty_container` diagnosis; the verdict question raised as core clarification **C-8** (see below) | An empty file verifies `chain_ok` with no diagnosis and the report says `partial`, which means "intact, unanchored" — there is nothing intact | Diagnosis after 0.13; C-8 by decision |
| U18 | `verify_segment_set(manifest_path)` — a function, not a reader method (decision 6) | With rotation, a single segment reports a violation by design (D1); only the set can be called whole | 0.14 |
| **U27 (r2)** | `docs/WRITER-SURFACE.md`: the writer's own contract for runtime integrators (serve, hooks, embedders) | The writer is experimental until 1.0 and has two audiences — runtime integrators and consumers' test suites (decision 5) | Before 1.0 |

### The empty file — core clarification C-8 (r2)

Today an empty file gives `chain_ok = True`, `count = 0`, no diagnosis, and a report verdict of `partial`. `partial` means the chain is intact and was not checked against an anchor; an empty file has no chain to be intact. §4.2 says a chain's first record MUST be a GENESIS; with zero records the rule is vacuous, so the text does not decide it.

- **U26 adds the `empty_container` diagnosis** without changing the verdict — vocabularies are open, so this is safe in any minor.
- **The verdict is a question for the core**, raised as clarification C-8, the path C-7 took: "a container with zero records is not a chain". Palimpsests' position: verdict `violation`. Changing a verdict silently in code, without the clarification, would move the core's meaning outside its text.

## Outside the surface

These stay importable but carry no promise to consumers. Naming them explicitly is what lets Palimpsests change them freely.

- **Wire internals:** `pala.codec`, `pala.incremental`, `pala.verify` as modules; byte offsets, TLV tag numbers, `_HeaderSeq`, `_LazyRecords`. A consumer reaches these facts through `reader` or not at all.
- **Anything with a leading underscore,** including `_record_at`, `_decoded_records`, `_structure_pass`. The cache lock added in 0.12 is an implementation detail, not a thread-safety promise for every method.
- **Parsing a rendered report.** `build_report` and `pala-verification-report/1` stay public as channel 2. What is outside is reading a verdict or a fact out of a rendered report instead of its fields or `derive_verdict`.
- **The writer** — until its own contract exists (U27). `PalaWriter`, `AnchorStore`, `FileAnchorStore`, `Pkcs11AnchorStore`, segment cutting, locks.
- **The SCITT bridge (r2)** — `scitt.verify_statement`, `StatementCheck` and its `root_status` vocabulary are **experimental** until bridge run B3 reproduces construction v3 independently. Then they join a channel of their own.
- **Sentence text:** `narrative`, `detail`, `expected`, `anchor_reason`, violation reasons, error messages. Carried verbatim by consumers, never parsed, free to improve.

## Decisions (r2 — the six open questions of r1)

| # | Question | Decision | Why |
| --- | --- | --- | --- |
| 1 | Module for the surface | **`reader` plus `anchors`**, no new `api` module | Two import paths for one symbol during a transition cost more than the freedom buys; `reader` reorganises behind its `__all__` anyway |
| 2 | Where `KIND_*` live | **`palimpsests/audit/profiles/inference.py`** — named for the profile, not "neutral" | Kinds, EVT tags, outcomes, sources and dispositions are allocations of the *inference profile*, not of the core; a second profile (robotics) gets its own module beside it. Writer and reader both import it; the writer re-exports for compatibility |
| 3 | What U17 hashes | **The SHA-256 of the bytes actually read**, in the same read the status is judged from | Hashing in a second open would describe whatever the file had become. #296 already does this — checked |
| 4 | Is `narrative` language-stable? | **Always English; wording free to change, including in patch releases.** Localisation, if it ever comes, is a second field | A sentence that may change is honest only if the promise says so |
| 5 | Writer as test support | **Not promised as test support.** The writer gets its own contract before 1.0 (U27), which consumers' fixtures can rely on then; until then writer changes are listed in their own changelog block. Many of Auditor's fixtures can move to the **published vectors**, which are already stable artefacts | A test-only promise would be a third contract for one module; the writer needs a real one anyway |
| 6 | U18 scope | **A separate function, `verify_segment_set(manifest_path)`, in 0.14** — not a reader method | Its input is a set of files, not one; it composes existing parts (each segment already verifies alone, seeded from the manifest's `prev_head`). For 0.13, `Verification.manifest` is enough |

One question is deliberately not here: whether 1.0 needs an independent audit first. That is a funding question and does not block defining the surface.

## Work plan (r2)

Ordered by what each step unblocks. "PR" means one reviewable pull request.

**Before the 0.13 tag**

1. U17 (#296) and U22 (#297) — merged.
2. U25 — `INTEGRATION-SURFACE.md` refresh, with this document beside it.
3. Family B (OTel adapter) — already in 0.13 scope; independent of this track.

**0.13 → 0.14 (the U track proper)**

4. U19 + U20 together — one PR: the re-exports, `profiles/inference.py`, the contract test. The contract test lands with the exports so nothing is exported untested. **Done (0.14).** Two things it settled: the channel-5 names are re-exported lazily (`bootstats` and `timehealth` import the reader, so an eager import is circular); and `anchors.__all__` also lists the writer-side stores (`AnchorStore`, `FileAnchorStore`) — outside the reading surface, left in place until the writer's contract (U27) decides where they belong.
5. U24 — violation codes; touches `incremental`, `verify`, `reader`, `report`. One PR with its own vectors check: the report schema stays `/1`, the codes are additive.
6. U26 — `empty_container`; C-8 drafted beside it for the maintainers' decision.
7. U21 — `container_check()`.
8. U18 — `verify_segment_set` (0.14).

**Before 1.0**

9. U27 — the writer's contract.
10. Rules 1–3 and 8 take effect; the stability class in `INTEGRATION-SURFACE.md` changes from the pre-1.0 "public" to the 1.0 rules.

**Auditor side** (unchanged from r1): C-13 (guidance for the new patterns and codes, continuation fields, `origin_state_at`) and C-14 (tool outcome on the result card), after U19 lands; then the import rule in `check_no_wire_parsing.sh` and the canary against Palimpsests `main`.

## What Auditor commits to

A stable surface is only useful if its first consumer stays inside it. Auditor commits to five things once this proposal is agreed.

- **Only the declared surface.** After U19 lands, `pala_seam.py` imports nothing outside the consumer `__all__`. Its own CI check (`check_no_wire_parsing.sh`) gains a rule that fails on any other `palimpsests` import path.
- **A canary against `main`.** Auditor supplies a CI job that runs its sidecar suite against Palimpsests `main`; Palimpsests decides whether it runs on every PR, non-blocking at first. Today that run is 324 passed; a drop is a signal before a tag, not after.
- **Pins one minor wide.** `>=0.13,<0.14`, moved only after Auditor renders every new pattern, code and name the new minor introduces.
- **No re-derivation.** Where the surface lacks something (the manifest's identity today, a segment set tomorrow), Auditor asks for it upstream rather than rebuilding it from the bytes.
- **Unknowns stay visible.** An unknown pattern, code or name is shown with the verifier's own sentence and the plain statement that this build has no guidance for it. **(r2)** This now includes violation codes once U24 lands; until then a violation is shown by its reason sentence, carried verbatim.
