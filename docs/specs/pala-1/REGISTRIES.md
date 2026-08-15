# PALA-1 registries — allocations and allocation policy

The single index of every number space PALA-1 and its profiles allocate
from, with the policy that governs additions. Anyone allocating a value
edits the owning document **and this file in the same pull request**; a
value that appears in one and not the other is a defect of that PR.

This document is non-normative: the owning documents (`PALA-1.md`, the
profile documents) define each value's meaning. What this file adds is
the one thing scattered tables cannot give — a place where a collision
or a renumbering is visible at review time.

| | |
|---|---|
| **Covers** | PALA-1 core v1.0 (frozen) and its profiles (robotics r1, inference r2) |
| **Licence** | CC0-1.0, like the core specification. |

## The two rules above all others

1. **Additive only, forever.** A number, once allocated, is never
   renumbered and never reused — including numbers whose feature is
   later retired. Retirement is documented; the number stays burned.
2. **A value exists when its full kit exists.** An allocation lands
   only together with: its normative text in the owning document, an
   emit path (or an explicit not-yet-emitted note), tests, companion
   test vectors, and reader recognition. Half-allocated values — text
   without vectors, vectors without text — do not merge.

## Closed registries (core, frozen at v1.0)

Changing any of these is a new `format_version` negotiated per core
§11 — never an edit to v1.

### Record types (core §3) — u16, closed

`0x0001 GENESIS`, `0x0002 BOOT`, `0x0010 SPAN_START`, `0x0011 SPAN_END`,
`0x0012 EVENT`, `0x0020 MERKLE`, `0x0021 AGGREGATE`, `0x0030 SHED`,
`0x0040 SAFETY`, `0x0050 ANCHOR`, `0x0051 WITNESS`, `0x0060 KEY_SHRED`.

Shed classes are part of the allocation: `GENESIS`, `BOOT`, `SHED`,
`SAFETY`, `ANCHOR`, `WITNESS`, `KEY_SHRED` are **never-shed**; `MERKLE`
and `AGGREGATE` are sheddable; the rest are normal. The class rule for
any future version: evidence of safety events, oversight, shedding and
erasure is never-shed — dropping it under load is the one shed no
deployment may configure (core §3.3).

### Header TLV types (core §2.2) — u16, closed

`0x0001–0x0003` origin triple; `0x0011–0x0012` Merkle;
`0x0020–0x0022` shed; `0x0030–0x0033` witness; `0x0040` shred key;
`0x0050` anchor head. Record-type numbers and TLV-type numbers are
**separate namespaces** (core §2.2) — do not read one table with the
other's numbers.

### Core value vocabularies — closed

- `time_trust`: 0–3 (core §5). Values above 3 undefined in version 1.
- `WITNESS_KIND`: 1 transparency log, 2 RFC 3161 TSA (core §2.2).
- `assurance_tier`: 0 (A), 1 (B), 2 (B+) (core §6); tier C is
  deliberately not a header value.

### `AGGREGATE` body tags, core portion (core §3.2) — closed at 0x0001–0x0002

`0x0001 AGG_WINDOW_NS`, `0x0002 AGG_SAMPLE_COUNT`. Everything from
`0x0003` upward is delegated to profiles, one profile per chain, so
profile allocations cannot collide within a chain.

## Open registries (profiles — additive in profile revisions)

Additions never renumber, never touch an envelope byte, and follow the
unknown-value reader rule: a reader meeting a value it does not know
reports it and moves on — rejection is forbidden (core §7.6; inference
profile §3).

### Inference profile (`profiles/inference.md`, r2)

**`EVENT`/`SAFETY` body tags** — u16, own namespace. Allocated:
`0x0001–0x000B` (r1: 0x0001–0x0004; r2 added 0x0005–0x000B).
**Next free: `0x000C`.**

**`EVT_KIND`** — u16, with a range convention this registry makes
explicit:

| Range | Purpose | Allocated | Next free |
|---|---|---|---|
| 1–99 | Serving operations (`EVENT` records) | 1–7 | 8 |
| 100–199 | Safety and oversight (`SAFETY` records) | 100–103 | 104 |
| 200–65535 | Unallocated; a future block is claimed here first | — | — |

**`EVT_CATEGORY`** (incident categories, kind 102): 1–3 allocated;
next free 4. **`EVT_SEVERITY`**: 1–3, closed by meaning (low/medium/
high). **`EVT_DISPOSITION`**: 0–2 allocated; next free 3.

**`AGGREGATE` tags (profile portion)**: `0x0003–0x0007` allocated;
next free `0x0008`.

**`KEY_SHRED` body tags** — own namespace (inference profile §8):
`0x0001–0x0003` allocated; next free `0x0004`. **`SHRED_REASON`**:
0–3 allocated; next free 4.

### Robotics profile (`profiles/robotics.md`, r1)

**`AGGREGATE` tags (profile portion)**: `0x0003–0x0005` allocated
(optical-flow statistics); next free `0x0006`. Other robotics
namespaces are owned by that document; additions register here the
same way.

## Registration procedure

One pull request, non-author review, containing all of:

1. The normative addition in the owning document, with the profile's
   revision history updated (additive revision, e.g. r2 → r3).
2. The updated allocation row(s) **and next-free pointer(s)** in this
   file.
3. The full kit of rule 2 above: emit path, tests, companion vectors
   regenerated with the frozen sets byte-identical.

A PR that allocates from a closed registry is rejected by policy, not
by taste: that change is a format-version decision (core §11) and
starts there.
