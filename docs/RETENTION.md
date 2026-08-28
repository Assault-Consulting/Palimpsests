# Retention, archival, and pruning

Operational guidance for keeping a PALA-1 audit log over the retention
period a deployment is subject to — how much it costs to store, how to
archive and prune without losing verifiability, and where raw-payload
retention is a deployer policy rather than a property of the log.

**Claim form.** Palimpsests writes and verifies the log; the *retention
period* and *raw-payload policy* are the deployer's, set by the
obligations the deployed system is under (e.g. the six-month minimum of
EU AI Act Article 26(6)). This is operational guidance, not legal
advice.

**Provenance.** Storage and resume figures are measured, not estimated —
from `results/audit-overhead-footprint-v0.7.0.md` (v0.7.0, `7940dc3`,
Arc iGPU). Verify against your own deployment's kind mix.

---

## 1. Storage cost (measured)

The log is small. Footprint is deterministic per record kind (measured
from the encoder), so storage is a function of the *kind mix*, not a
single average:

| Kind | bytes/record |
|---|---|
| GENESIS / BOOT / SPAN_END | 156 (fixed header only) |
| MODEL_UNLOAD | 179 |
| SPAN_START | 173 |
| PREFIX_WARM / PREFIX_COPY | 183 |
| SAFETY (guard) | 186 |
| ANCHOR | 192 |
| KV_SAVE / KV_RESTORE | 210 |
| EVENT + origin (MODEL_LOAD) | 251 |

For a realistic agentic session the **weighted mean is ≈ 181 B/record**,
about **8.5 KB per full session** (~47 records: model load, 8 sub-sessions
with spans and KV operations, a guard refusal, an anchor). Cross-checked
against the on-disk session file: 182.6 B/record, agreeing to ~1 %.

**Sizing rule.** `storage ≈ records × (your weighted B/record)`. Use the
per-kind table against your own mix rather than the flat 181 B — a chain
that emits many `KV_*` or `AGGREGATE` records, or large `EVT_DETAIL`
strings, runs heavier; a mostly-lifecycle chain runs lighter.

**Illustrative scenarios** (181 B/record; your mix will differ):

| Sessions/day | Records/day | Per day | Per 6 months |
|---|---|---|---|
| 1 000 | ~47 k | ~8.5 MB | ~1.5 GB |
| 10 000 | ~470 k | ~85 MB | ~15 GB |
| 100 000 | ~4.7 M | ~850 MB | ~155 GB |

At any realistic scale the six-month retention duty is **not a storage
problem** — it is a chain-management problem (§3, §4).

## 2. Six-month retention (Article 26(6))

The log is append-only and its segments are self-verifying, so meeting a
minimum retention period is a matter of *not deleting* the archived
segments, not of special machinery. Storage is modest (§1); the real
questions are archival granularity (§3) and how large a single live
chain is allowed to grow before resume cost bites (§4).

## 3. Archival and pruning

Segment boundaries are invisible to the chain (spec §2.4): a `BOOT`
record links to the previous boot's head, so a log is a sequence of
segments that verify as one chain. This gives clean archival units.

- **Whole-segment archival preserves verifiability.** Verification
  consumes the file sequence; an archived segment verifies on its own
  and, with the next segment's `BOOT` back-link, as part of the whole.
- **Prefix-absent verification is honest, not silent.** Verifying a
  chain whose prefix has been archived away — e.g. the genesis segment
  moved to cold storage — reports **exactly one explicit violation at
  position 0** (missing genesis) and verifies the remainder as sound.
  The loss is visible, never silent. (A truncated *tail* is a different
  case: it is invisible to the §7.1 chain check and is caught by the
  **anchor**, not by a position-0 violation — see the reader docs.)
- **Pruning below the retention floor is a deployer action**, outside
  the log. Formal prefix-consistency (Merkle) proofs across pruned
  prefixes are roadmap (post-0.8); until then, prune at segment
  boundaries and keep the anchor for the retained head.

### Rotation in production (writer-side, 0.11)

`pala segment` is the offline knife for a chain that already grew;
`RotationPolicy` on `PalaWriter` makes the same cut at write time, so
a chain that lives for months never needs the knife. Thresholds —
`max_records`, `max_bytes`, `max_age_s` — are checked after each
record under the writer's lock: the cut falls strictly between
records, a record that crosses a threshold stays in its segment, and
a due cut is deferred to the span boundary (a cut never severs a
span). Closed segments land in an atomically-updated
`pala-segments/1` manifest whose `prev_head` seeds let every segment
verify **alone** (`start_prev`), exactly as the offline knife's does.

**Choosing triggers for the six-month duty.** Segment size is your
pruning granularity: once the duty window passes, expired segments are
deleted whole and the manifest keeps every head, so the survivors
still name the history they continue (§3 above). At the measured
≈ 181 B/record (§1):

    max_bytes ≈ records_per_day × 181 B × days_per_segment

| Load | Volume | Weekly segments | 6-month window |
|---|---|---|---|
| ~10 k records/day | ≈ 1.8 MB/day | `max_bytes=16 MiB` | ≈ 330 MB, ~26 segments |
| ~100 k records/day | ≈ 18 MB/day | `max_bytes=128 MiB` | ≈ 3.3 GB, ~26 segments |

Prefer `max_bytes` (or its `max_records` equivalent, ≈ `max_bytes`/181)
as the primary trigger: both are deterministic and carry exactly
across a resume. `max_age_s` runs on the process's monotonic clock and
restarts at zero when a segment is adopted by `open_existing` — use it
as a backstop for near-idle writers, not as the primary cut. Segments
of ≤ 128 MiB also keep cross-boot resume of the live segment well
under a second (§4: ≈ 4 s/GB).

## 4. Resume cost of large chains

Cross-boot resume (`open_existing`) walks the file once to adopt the
tail head and sequence — **linear in file size, ≈ 4 s/GB** (measured:
slope 3.99 s/GB, residuals ±0.02 s; ~6 M records/GB). A 1 GB chain
resumes in ~4 s.

This is fine for a boot-time path, but it is the argument for **chain
rotation and an anchoring cadence rather than one unbounded log**: a
deployment that lets a single chain grow to tens of GB pays tens of
seconds per resume. Rotate at a segment/anchor cadence sized so the live
chain stays in the low-GB range; archived segments (§3) carry no resume
cost. (Resume is a *structural* walk; cryptographic link and body
integrity are the separate `pala verify` path — resume and verification
are deliberately distinct.)

## 5. Payload retention — a design position

PALA-1 is **hash-by-default**. In the inference profile the bodies are
metadata-only; `body_digest` is always present, and raw payloads (prompts,
completions, KV blobs) are **never written to the log by default**. Two
consequences for retention:

- **Retaining raw payloads, where an obligation requires it, is a
  deployer policy applied *outside* the log** — the log carries the
  tamper-evident record that an event occurred and the digest that binds
  its content, not the content itself. This keeps the log small (§1) and
  keeps personal data out of it by construction.
- **Where a deployment does choose to carry payloads in the log**, an
  encrypted-payload profile supports **cryptographic erasure** (spec
  §4.4): destroying a per-record key erases the payload while every hash
  in the chain and Merkle tree still verifies — reconciling a retention
  duty with a GDPR Art. 17 erasure duty.

## 6. References

- Measured footprint and resume figures: `results/audit-overhead-footprint-v0.7.0.md`.
- Segment boundaries, chain, verification: `docs/specs/pala-1/PALA-1.md` (§2.4, §7.1); `docs/audit/`.
- Cryptographic erasure: PALA-1 §4.4.
- Regulatory context: `docs/compliance/EU-AI-ACT-MAPPING.md` (Articles 19(1), 26(6)); `docs/compliance/24970-MAPPING.md` (security/privacy/retention).
