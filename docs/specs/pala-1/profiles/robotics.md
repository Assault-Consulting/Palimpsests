# PALA-1 robotics profile

The first PALA-1 profile: record-body semantics and vocabularies for a
robot emitting PALA-1 — high-rate sensor loops, a tiered perception
cascade, a safety path. This document is a companion to the core
specification (`../PALA-1.md`, §3.4) and defines nothing about the
envelope, the chain, or verification: those are the core's, and they hold
here unchanged. A verifier needs nothing from this document to answer the
core's three questions.

| | |
|---|---|
| **Profile of** | PALA-1, version 1 |
| **Status** | **Draft.** Frozen together with the core at spec v1.0; do not implement against it before then. |
| **Date** | 2026-08-03 |
| **Licence** | CC0-1.0, like the core specification and its test vectors. |

**History.** The content of this profile sat inside the core draft dated
2026-08-02 and was split out unchanged: the tag values, units and
semantics below are the original ones, so vectors generated against the
pre-split draft remain valid against this profile byte-for-byte.

---

## 1. `ORIGIN_ROLE` vocabulary

UTF-8 values for the core's `ORIGIN_ROLE` TLV (core §2.2), naming the
emitting component. The vocabulary is open — a deployment may add roles —
but the following names are established and used by the committed test
vectors:

| Role | Component |
|---|---|
| `eyes.tier1` | First perception tier — the fast, always-on visual path |
| `perception_health` | The monitor that compares perception tiers and raises divergence |
| `brain` | The planner; the span the test vectors open |

A model update is a different origin: the core's
`(ORIGIN_ROLE, ORIGIN_MODEL_DIGEST, ORIGIN_CONFIG_DIGEST)` triple is what
answers *"which weights said that?"* after an incident, and this profile
adds only the role names.

## 2. `EVENT` bodies — `c'` writes

`EVENT` records carry **`c'` writes**: enriched context produced by the
perception cascade about the scene (what is ahead, what is moving, what
changed). A `c'` body SHOULD be encrypted (`key_id ≠ 0`): scene
descriptions are personal data whenever people are in the scene, and
crypto-shredding (core §4.4) is the erasure path for them.

## 3. `MERKLE` leaves — frames and audio, per second

The core defines the tree (RFC 6962, promotion of unpaired nodes — core
§4.3); this profile defines the leaves: **digests of captured frame and
audio buffers, aggregated per second into one `MERKLE` record.** At a
30 Hz sensor rate that is 30 leaves per record — 30 Hz of digests becomes
1 record/s, which is what removes the high-rate pressure from the chain
(core, open issue 2).

Selective disclosure then reads naturally: prove one *frame* with
~log₂(n) hashes without revealing the other 29 — *"show me this moment"*
without *"show me everything"*.

The exact capture point of the digested buffer (sensor output vs
post-codec bytes) is an open issue of this profile — see §6.

## 4. `AGGREGATE` body — optical-flow statistics

The core fixes the window framing (`AGG_WINDOW_NS`, `AGG_SAMPLE_COUNT`,
tags 0x0001–0x0002) and reserves 0x0003 upward for profiles (core §3.2).
This profile allocates:

| Type | Name | Value |
|---|---|---|
| 0x0003 | `AGG_FLOW_MIN_MILLI` | u32 — milli-pixels per frame |
| 0x0004 | `AGG_FLOW_MAX_MILLI` | u32 — milli-pixels per frame |
| 0x0005 | `AGG_FLOW_MEAN_MILLI` | u32 — milli-pixels per frame |

Optical-flow magnitude is the Tier 0 post-market-monitoring statistic:
how much the scene moved, per window, with no scene content. Milli-units
per the core's fixed-point constraint — a float here would reintroduce
the cross-implementation disagreement the core rejects JSON for, in the
one record whose purpose is being comparable across vendors.

Per core §3.2, an `AGGREGATE` body with these statistics SHOULD be
cleartext (`key_id = 0`): flow magnitudes are not personal data, and
encrypting them would make the PMM export useless to the party entitled
to read it.

## 5. Rates and the nonce argument

The core derives the AES-GCM nonce from `seq` rather than randomness
because a sustained high-rate writer approaches the ~2³² safety bound of
random 96-bit nonces within the format's ten-year horizon (core §4.4).
This profile is the motivating case: a 30 Hz emitter crosses 2³² in under
five years of continuous operation, and multi-sensor platforms get there
sooner.

## 6. Open issues (profile)

| # | Issue |
|---|---|
| 1 | **Merkle leaf capture point.** Whether a frame digest covers the raw sensor buffer or the post-codec bytes changes what a disclosed frame proves. Undefined in the pre-split draft; must be fixed before v1.0. |
| 2 | **Role vocabulary scope.** Whether `ORIGIN_ROLE` names beyond §1 need registration or stay free-form per deployment. |

---

## 7. Test vectors

The committed test vectors (`../test-vectors.json`) follow this profile:
the narrative is a robot's ten seconds (a `c'` write about a pedestrian,
a second of frame digests, a flow `AGGREGATE`, a perception divergence),
and the `AGGREGATE` body uses the tags of §4. The properties those
vectors demonstrate are envelope properties (core §8) — the profile
supplies the story, the core supplies the guarantees.
