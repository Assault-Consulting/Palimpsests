<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The evidence bundle — `pala-bundle/1`

`pala bundle <file>` and `palimpsests.audit.pala.bundle.assemble_bundle`
put a range of a chain's records, the proofs that bind them, the verdict
on the whole chain and their time claims into one tar archive: a file to
attach, open and re-verify.

**The bundle is derived and unsigned.** The chain stays authoritative.
Everything in a bundle is either the chain's own bytes or a statement
that can be recomputed from them with the specification alone — and a
reader of a bundle recomputes; it does not take `verification.json` on
trust. The archive's integrity statement is `MANIFEST.json`, which is
itself unsigned: what gives a bundle provenance is how it was handed
over, or an anchor held outside it.

## 1. The archive

A plain (uncompressed) tar with five members, in this order:

| Member | What it is |
|---|---|
| `records.pala` | The records of the range: exact source bytes, header and body, concatenated as a file container (§2.4). |
| `proofs.json` | For each record in the range, its inclusion proof against a chain-carried `MERKLE` root, or `null`. |
| `verification.json` | The verdict on the **whole** source chain at assembly time. |
| `time-claims.json` | Every time assertion in the range, with its trust level by name. |
| `MANIFEST.json` | The format, the tool, the source chain's head, the range, and the SHA-256 of each member above. |

Tar metadata is fixed (`mtime` 0, uid and gid 0, empty owner names) and
the JSON members are written with sorted keys, two-space indent and a
final newline. Same source bytes, same range, same anchor answer, same
tool version: the same archive, byte for byte.

## 2. `MANIFEST.json`

| Key | Value |
|---|---|
| `format` | `pala-bundle/1` |
| `tool` | `{name, version}` — the assembler |
| `source_head` | the head of the whole source chain, hex |
| `range` | `{from_seq, to_seq, records}` — the seqs of the first and last record bundled, `null` when none were |
| `members` | `{<member name>: {sha256}}` for the four members above it |

## 3. `verification.json`

What the assembler saw when it verified the whole source file — not the
range alone.

| Key | Value |
|---|---|
| `consistent` | **The answer to "does this log hold together":** `chain_ok`, and the container well-formed, and no body-digest mismatch. Since 0.15. |
| `chain_ok` | The header chain alone (§7.1): links, no gaps, no violated MUST. **A body altered after writing does not show here** — the header that binds it is intact. |
| `records`, `head` | the number of records verified, and the chain head, hex |
| `breaks`, `gaps`, `uninterpretable` | seqs |
| `violations` | `[[seq, reason], …]` — the reason is a sentence |
| `violation_codes` | `[[seq, code], …]`, parallel to `violations` — the code is what to branch on. Since 0.15. |
| `container` | `{well_formed, malformed, bytes_parsed, bytes_total, body_digest_mismatches}` — the container walk (§2.4) and the check of every body against the digest its header binds. The same object as the verification report's `container` section. Since 0.15. |
| `completeness` | `{checked, ok, anchor_lag}` — `checked` is `false` when no anchor was supplied; `ok` is then `null`, and never to be read as passed |
| `anchor` | `null`, or `{head, source_kind, source_detail}` |
| `anchor_attempts` | `[{source_kind, source_detail, outcome, error}, …]` |
| `advisory` | `[{code, at_seq, detail}, …]` — signals, never a verdict |

**A bundle written by 0.10 – 0.14 has no `consistent`, `container` or
`violation_codes`.** Its `chain_ok` covered the headers only. To know
whether the bodies in such a bundle match their headers, check
`records.pala` itself: `pala verify` on the extracted member does.

## 4. `proofs.json`

`{"proofs": {"<seq>": <proof or null>, …}}`. A proof is
`{leaf, path, root, root_seq}`: the record's hash (§1.2), the sibling path
as `[[side, hash], …]`, the root it lands on, and the seq of the `MERKLE`
record that carries that root. `null` means no `MERKLE` checkpoint in the
chain covers that record yet — *not yet aggregated* is not *not
included*. A proof binds a record's header hash; the body is bound by the
header's digest, which `container.body_digest_mismatches` reports on.

## 5. `time-claims.json`

`{"claims": [{seq, monotonic_ns, wall_clock_ns, time_trust,
time_trust_name}, …]}`, restating each bundled record's header. Wall-clock
time is advisory and only as good as its `time_trust` says; ordering
authority is `monotonic_ns` and `seq` (core §5).

## 6. Damaged sources

A damaged chain bundles too; packaging broken evidence for inspection is
half the point.

| The source | The bundle |
|---|---|
| a broken link, a gap, a violated MUST | all records; `chain_ok` and `consistent` are `false` |
| a body altered after writing | all records, the altered body as it is; `chain_ok` `true`, its seq in `container.body_digest_mismatches`, `consistent` `false` |
| cut in the middle of a record | the whole records before the cut; `container.well_formed` `false`, `malformed` says where the walk stopped |
| not a container at all | no records; `container.well_formed` `false` |
| no records | no records; `consistent` `true` — nothing was there to contradict, which is not a log found intact (clarification C-8) |

## 7. Stability

The format is **open**: a release may add a key to a JSON member; no key
is removed, renamed or given another meaning without a new format id. A
reader ignores a key it does not know. The five members, their order, the
determinism rules of §1 and the meaning of every key above are fixed.

## 8. Re-verifying a bundle

With no code from the assembler:

1. each member's SHA-256 equals its entry in `MANIFEST.json`;
2. `records.pala` walks as a container, every body matches its header's
   digest, and — when the range starts at seq 0 — the header chain
   verifies and ends on `source_head` if the range reaches the last
   record;
3. every non-null proof verifies from `leaf` — which is the hash of that
   record's header in `records.pala` — along `path` to `root` (core §4.3),
   and `root` is the root carried by the `MERKLE` record at
   `root_seq` when that record is in the range;
4. each time claim equals the fields of its record's header.

`tests/test_bundle.py` does this with the specification-level functions
only.
