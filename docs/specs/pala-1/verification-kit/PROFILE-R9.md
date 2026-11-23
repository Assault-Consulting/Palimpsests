# The profile track — read the inference profile at r9 yourself

The core track of this kit (`README.md` §2) tests the frozen format. This
track tests what sits on top of it: the **inference profile at revision
r9**, the latest revision and the one Palimpsests 1.0 implements
(`profiles/inference.md` §9.1). The profile says what the bodies of
records mean — tool calls and their results, incidents, a human's
acknowledgement, a declared cut of the log, a writer's opening and
closing, reports a server refused — and how the digest of a JSON value
is computed.

The profile itself says that no independent reading of it as a whole is
on record. This track is how one is made.

The boundary, the rules on questions and on AI assistance, and how to
submit are those of `README.md` §1 and §3; they are not repeated here.
Expect roughly 4–8 hours.

## P0. What this track tests, and what it does not

- **It tests r9 as published at the Git tag `v0.15.0`**, the first
  release that carries it. The profile's own rule is that r1–r9 are not
  edited in place after that release, so the text and the vectors you
  fetch are the ones every later release means by "r9".
- **It is one revision.** r9 contains r1–r8: a revision only adds. When
  a later revision is published it gets a track file of its own; this
  one keeps testing r9.
- **It needs a core verifier, and does not re-test the core.** You need
  the chain checks of `PALA-1.md` §7.1 and §7.2 and the tree of §4.3. Use
  your own from a core run, or write them during this one. The core's
  own pass bar is the other track.
- **It tests a reader, not a writer.** Nothing here asks you to produce
  records the way the Palimpsests writer does.
- **Not covered by the vectors, and so not by the pass bar:** the
  `MERKLE` checkpoint of profile §10 (the vector chain holds none), the
  `ORIGIN`, session and `AGGREGATE` bodies of §1–§3 and §5, and how the
  digests at `seq` 8–22 were computed (their inputs are not published).
  Reading those sections and logging what is unclear in them is still
  part of the run.

## P1. Inputs

```sh
sh fetch-inputs.sh profile     # builds ./pala1-profile-r9-package/ and checks digests
```

Six files at the tag `v0.15.0`. By hand, from
`https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/v0.15.0/docs/specs/pala-1/`
followed by each path below, keeping the `profiles/` folder. The digests
must be these; if one differs, stop.

```
b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5  PALA-1.md
476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193  test-vectors.json
6c93362144065af796481af4a669fd6c5a6d2987924e9314dbb37a8764258186  profiles/inference.md
4fb17b23c4be5292240c4b99b3debfae31d31311cf0692380bc5b84d56442005  profiles/inference-vectors.json
9cb9c337e3cc67a0b0c15fb13afa9e5e450ef21b61eba37e6c7e40154a3dc859  profiles/payload-digest-vectors.json
73f88321939f9d52df70fd3448fafa6b4f844b1e19d01e7922c3f37750073fb9  profiles/retention-continuation.md
```

| File | What it is for |
|---|---|
| `PALA-1.md`, `test-vectors.json` | the core the profile rests on; the same bytes as in the core track |
| `profiles/inference.md` | **the document under test**, at r9 |
| `profiles/inference-vectors.json` | a chain of 32 records over three boots, with the expected meaning of its bodies |
| `profiles/payload-digest-vectors.json` | 37 JSON values: 22 with a digest, 15 with none |
| `profiles/retention-continuation.md` | the design behind profile §3.2; the profile says its own §3.2 is the normative part |

Besides the standards of `README.md` §1.1, this track allows the ones
the profile cites: **RFC 8785** (JSON canonicalization) and **RFC 7493**
(I-JSON). A general-purpose JSON parser is allowed; a library that
implements RFC 8785 for you is not, because §11 is one of the things
being read.

## P2. The task

In any language, with no code from this repository:

1. Build the container from `inference-vectors.json` as in the core
   track: each record's `header_hex`, then its `body_hex` where present.
2. Check the chain with your core verifier.
3. Decode every body by the profile's text.
4. Compute the digests of `payload-digest-vectors.json` by profile §11.

### The pass bar

Eight items, numbered as in the run record. Section numbers are those of
`profiles/inference.md` unless "core" is written.

| # | What you reproduce | Expected |
|---|---|---|
| P1 | The core's answers for the profile chain (core §7.1, §7.2) | `chain_ok` true, 32 records, no breaks, gaps or violations; `chain_head` as published; complete against the top-level `anchor_head` |
| P2 | Every record's hash and, for the 22 records with a body, the body digest in its header | all 32 `record_hash` values as published; all 22 body digests match their bodies |
| P3 | The boots of the chain | three: they begin at `seq` 0, 24 and 27 |
| P4 | Every numbered entry of `semantics`, field by field, **from the body bytes** | 18 entries — `seq` 4, 5, 6, 8, 9, 10, 12, 14, 15, 17, 18, 19, 21, 22, 25, 26, 29, 30. A field that is a name (`kind_name`, `outcome_name`, `source_name`) is the profile's name for the number you decoded |
| P5 | Every reference: where an entry has `ref_seq` and `ref_hash`, the record at that `seq` has that hash | all hold |
| P6 | The continuation at `seq` 19 (§3.2): its predecessor head equals its own `prev_hash`; its prior root recomputed by you over the records before it | both hold; the root equals `prior_root` |
| P7 | The lifecycle check (§3.3) over the three boots | no boot is reported: the first holds no `WRITER_OPEN` and is not judged, the second is opened and closed, the third is the last |
| P8 | `payload-digest-vectors.json` (§11): for each of the 33 cases and 4 deep cases, either the canonical bytes and their SHA-256, or the conclusion that the value has no canonical form | 22 digested, with `canonical_utf8_hex` (or, for a deep case, `canonical_utf8_length`) and `sha256` as published; 15 with none, each for the `reason` given |

The entries of `semantics` that are rules in words (`outcome_rule`,
`continuation_rules`, `lifecycle_rule`, `reports_refused_rule`,
`source_rule`) are not values to reproduce. Read them against the
profile's text: a rule that says something the profile does not, or the
reverse, is a finding.

**An implementation that disagrees with any of P1–P8 is wrong, or the
profile is.** Both outcomes are results.

### SHOULD — cases you construct

Each shows a diagnosis the profile promises. A run that skips them still
passes; say which you ran.

| Case | What to build | What the profile says a reader does |
|---|---|---|
| `unclosed_boot` | the chain without its `seq` 26, re-linked so that it still verifies | reports the second boot as stopped without being closed (§3.3) |
| `last_boot_unclosed` | the chain without its `seq` 31 | reports nothing: the last boot is not judged (§3.3) |
| `continuation_wrong_predecessor` | `seq` 19 with a `SEG_PREDECESSOR_HEAD` that is not its `prev_hash`, the chain re-linked | an advisory; the core verdict does not change (§3.2) |
| `unknown_kind` | an `EVENT` whose kind r9 does not define | says it does not know the kind and carries on; nothing it does know changes meaning (§9.1) |

Removing or changing a record changes every hash after it, so each case
means rebuilding headers. That is part of the exercise: it shows whether
the header layout can be written from the text as well as read.

### Extras

Welcome, and not part of the pass bar: decrypting the body at `seq` 3
with the published key to the published plaintext (core §4.4); checking
what the `KEY_SHRED` at `seq` 6 names; values of your own for §11 that
the vectors do not hold.

## P3. What to submit

The three items of `README.md` §3.1, with `RUN-RECORD-PROFILE-TEMPLATE.md`
as the record. Title the issue `PALA-1 profile run (r9)`.

A run that meets the boundary is archived under
`../independent-runs/<name>/` and listed in
`../INDEPENDENT-VERIFICATION.md` §8, apart from the core runs: a profile
run says nothing about the frozen core, and the core runs say nothing
about the profile.

## P4. What a divergence means

r9 is not frozen the way the core is, and it is not edited in place
either. If your value disagrees and the profile's text is at fault, the
correction is a **new revision that says what it corrects**; the r9
vectors keep their bytes (§9.1). So a finding here does not change what
you tested — it changes what comes next.

Reduce a divergence to the first differing byte, or to the one sentence
of the profile that allows two readings, before you submit.
