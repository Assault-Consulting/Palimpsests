# PALA-1 Profile Extension — Retention Continuation

<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

| | |
|---|---|
| **Status** | **Design — for review.** No writer or reader code implements this document; nothing here is emitted by any release. Adoption is a profile revision (additive) plus a reader advisory; the core text and `test-vectors.json` are not touched. |
| **Applies to** | Any PALA-1 profile that adopts it by allocating one `EVENT` kind and the tags below in its own namespaces. The inference profile is the intended first adopter. |
| **Companion to** | `docs/RETENTION.md` §3 (archival and pruning), `docs/compliance/24970-MAPPING.md` (bounded storage, 5.2 / 6.4 d), core §2.4, §4.2, §7.2 |

## Why

Bounded storage is done by deleting whole segments once they leave the
retention window (`RETENTION.md` §3). After such a deletion, a verifier
that is handed only the surviving files sees a chain whose first record
is not a `GENESIS`. The core is right to call that a violation (§4.2):
"no predecessor" and "predecessor removed" must stay distinguishable,
and a bare `prev_hash` cannot say which one it is. Today the manifest
(`pala-segments/1`) is the only thing that can — and the manifest lives
outside the chain.

This extension moves the declaration *into* the chain, at the moment
it is true and cheap to state: when a segment opens, its first record
says what it continues from and under what retention policy. A reader
of the survivors then finds a **declared continuation** at position 0,
not an unexplained start. The deletion is still visible — nothing here
hides it — but it is now explained by the log itself, prospectively,
by the writer that made the cut.

What this extension does **not** do: it does not make overwrite
acceptable, it does not let a verifier *prove* that the deleted prefix
was the one declared (that needs the prefix, or a consistency proof
over it — see §6), and it does not change any verdict the core
mandates.

## 1. The continuation record

The first record of every segment the writer opens after a cut is a
`SEGMENT_CONTINUATION` event. It is written **before any other record
of the segment**, under the writer's lock, as part of the cut itself —
so there is never a segment file without one, and a reader can rely on
"first record of a writer-made segment" meaning exactly this record.

Segments produced by the offline knife (`pala segment` over an existing
chain) carry no continuation record: the knife cannot insert records
without breaking the chain, and it does not try. For knife-made
segments the manifest remains the witness. A deployer who wants
in-chain declarations uses `RotationPolicy` from the start.

The record is an ordinary `EVENT` (core §3): it is chained, hashed and
counted like any other, and a verifier that does not know the kind
reports it as uninterpretable and moves on (core §7.6). It is **never**
a `GENESIS`: a `GENESIS` claims "no predecessor", which is precisely
the claim this record must not make.

The body MUST be cleartext (`key_id = 0`), for the same reason the
`KEY_SHRED` note is (inference profile §8): the declaration must remain
readable after every key that ever protected the deleted prefix is
gone. It carries no content and no personal data — heads, counts and
policy numbers only.

## 2. Body

Tags live in the adopting profile's `EVENT` tag namespace; the numbers
below are the proposal for the inference profile (next free after
0x0011). Kind number likewise (next free after 10).

| Type (proposed) | Name | Value |
|---|---|---|
| 0x0001 | `EVT_KIND` | u16 — `SEGMENT_CONTINUATION` (proposed 11). MUST be present, first (profile rule). |
| 0x0012 | `SEG_PREDECESSOR_HEAD` | 32 bytes — `record_hash` of the last record of the previous segment. MUST equal this record's own `prev_hash`; a mismatch is a semantic violation (§4). Stated explicitly so the claim is self-contained and checkable against the header, not merely implied by it. |
| 0x0013 | `SEG_INDEX` | u32 — ordinal of the segment this record opens, counting from 0 for the segment that holds `GENESIS`. Equals the segment's index in the manifest. |
| 0x0014 | `SEG_RETENTION_S` | u64 — the retention floor in force at the cut, in seconds: the writer declares that no predecessor segment is eligible for deletion until at least this long after its close. 0 means "no floor declared". Policy, not a promise the chain can enforce — but a deletion earlier than the declared floor is then contradicted by the log. |
| 0x0015 | `SEG_PRIOR_ROOT` | 32 bytes — **optional.** A commitment to the *entire* prefix `[0, seq)` — always from record 0, never a window — so that one value in the newest survivor covers everything ever deleted before it, however many deletions occurred. Its tree definition is deliberately not fixed here (§6, open issue 1). Absent until it is. |
| 0x0004 | `EVT_DETAIL` | UTF-8, ≤ 200 bytes — optional; the policy that made the cut in the writer's own words (e.g. `max_bytes=134217728`). Metadata only. |

`seq` of the record is itself the count of records that precede it;
no separate count tag is needed and none is defined.

Tag order in the body follows the profile rule (`EVT_KIND` first); the
rest in ascending type order, so the encoding is deterministic and can
be pinned by companion vectors when a revision adopts this.

## 3. What a reader does with it

Verification is profile-independent (core §3.4); everything below is
**reader-side, advisory**, layered on the core verdict exactly as the
referential checks of inference r2 are.

**Case A — full chain present.** Continuation records are ordinary
events. A reader that knows the kind MAY check §4 semantics and MAY
list segment boundaries from them; the core verdict is unaffected.

**Case B — prefix absent, position 0 is a continuation record.** The
core still reports the §4.2 violation (first record is not a
`GENESIS`) and the existing `prefix_absent` diagnosis still applies.
The profile-aware reader adds a named row:

    origin: declared continuation — segment <SEG_INDEX>, continues from
    head <SEG_PREDECESSOR_HEAD>, <seq> records precede, retention floor
    <SEG_RETENTION_S> s

and, when a manifest or an anchor for the predecessor is available, one
of:

| Evidence at hand | Row |
|---|---|
| Manifest names a segment `SEG_INDEX − 1` whose `head` equals `SEG_PREDECESSOR_HEAD` | `predecessor: matches manifest` |
| Manifest present, no such entry or a different head | `predecessor: contradicts manifest` — a finding, not an advisory |
| No manifest, no anchor | `predecessor: unverified (declared only)` |

**Case C — prefix absent, position 0 is not a continuation record.**
Unchanged from today: `prefix_absent`, no explanation in the chain. The
absence of a declaration is itself informative once a deployment has
adopted this extension — it means the cut was not made by the writer.

## 4. Semantic checks (reader advisory, profile-aware)

On a `SEGMENT_CONTINUATION` record with known kind:

1. `SEG_PREDECESSOR_HEAD` MUST equal the record's `prev_hash`.
2. It MUST be the first record of its file (a continuation record in
   the middle of a segment is a writer error, reported as such).
3. `SEG_INDEX` MUST be strictly greater than the previous continuation
   record's `SEG_INDEX` in the same chain, and consecutive when the
   full chain is present.
4. `key_id` MUST be 0.

Failures are reported by name and never reject the chain — the core
verdict stands on its own.

## 5. Decisions taken in this design

| # | Decision | Answer |
|---|---|---|
| D1 | **Exit policy of a profile-aware verifier** when position 0 is a declared continuation | The core verdict is not changed — `pala verify` keeps reporting the §4.2 violation, because the frozen text mandates it and a verifier that "forgives" a missing genesis on the strength of an in-chain claim has quietly moved trust into the log. The *report* (`build_report` / Auditor path) carries the continuation as a named row with the predecessor status above; `predecessor: contradicts manifest` is surfaced with finding weight. No new exit code. |
| D2 | **Where the numbers come from** | Body tags in the adopting profile's `EVT` namespace, kind in its kind space — no core TLV allocation, no core text change. The extension defines semantics and reserves nothing itself. Vendor use is a profile-level question and is not opened here. |
| D3 | **Which record declares** | The successor's first record, prospectively, at the cut. Not a trailer on the predecessor: a trailer is exactly what gets deleted, and a declaration that disappears with the thing it describes explains nothing. |
| D4 | **What is deleted** | Whole segments, from the front, at or after the declared retention floor. Never a partial segment; never from the middle. The newest surviving continuation record then describes all of it at once (`seq` = everything before; `SEG_PRIOR_ROOT`, once defined, commits to all of it). |
| D5 | **Relation to `SHED`** | None. `SHED` records drops under saturation (core §3.3); this extension records planned deletion under policy. A storage-boundary `SHED` class is a separate, additive profile allocation (24970 mapping, 6.4 d rows). |

## 6. Open issues

| # | Issue |
|---|---|
| 1 | **`SEG_PRIOR_ROOT` tree definition.** The inference profile has no `MERKLE` leaf source (its open issue 1), so the core §4.3 tree is not available to it. A root over `record_hash` leaves — a derived tree, computed by any verifier from headers alone — is the obvious candidate and is the same object a prefix-consistency proof needs. The definition belongs with that proof format, not here; until it exists the tag is absent and the declaration rests on `SEG_PREDECESSOR_HEAD` + `seq`. |
| 2 | **Manifest as the anchor for a deleted predecessor.** Case B's "matches manifest" depends on the manifest being trustworthy independently of the chain. It is a plain JSON file today. Whether it should be anchored (its digest in an `ANCHOR` record, or in the next continuation record) is a design question shared with core open issue 5. |
| 3 | **Resume after crash mid-cut.** If the writer dies between closing the predecessor and writing the continuation record, the successor file exists without one. `open_existing` must either finish the cut (write the record first) or fold the empty file back. Writer-side detail, but the "first record of a writer-made segment" guarantee in §1 depends on it. |
| 4 | **Vectors.** When a profile revision adopts this, companion vectors pin the body encoding as every prior revision's did; no byte of `test-vectors.json` changes. |

## 7. Adoption path

1. This document reviewed (ADR-class, non-author).
2. Inference profile revision: kind 11, tags 0x0012–0x0015, §1–§4 by
   reference; companion vectors.
3. Writer: emit at the cut; resolve open issue 3.
4. Reader: Case B rows; §4 checks.
5. `RETENTION.md` §3 and the 24970 mapping rows move from Planned to
   Shipped with the release that carries steps 2–4.

None of steps 2–5 are in scope for 0.12.
