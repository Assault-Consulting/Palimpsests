# PALA-1 verification kit — verify the frozen format yourself

PALA-1 is frozen at v1.0 on the strength of one sentence:

> **An independent party must be able to write a verifier from the
> specification alone, without our code.**

Five independent implementations — three of them by people outside the
project at the time of their runs — have passed that test. This kit
exists so that **anyone** can run the same exercise, on the same terms,
at any time. Every submitted run becomes part of the permanent
verification record.

The kit has two tracks. The **core track** is that exercise: the frozen
format. The **profile track** applies the same method to the latest
revision of the inference profile, which no one outside the project has
yet read as a whole.

No permission is needed. No contact with the maintainers is needed until
you submit. Expect roughly 1.5–4 hours for the core track and 4–8 for
the profile track.

## 0. What this kit tests, and what it does not

| Track | What is read | Pinned at | Task |
|---|---|---|---|
| **Core** | the PALA-1 core format, version 1.0, frozen 2026-08-09 | the format's tag `pala1-v1.0` | §2 of this file |
| **Profile** | the inference profile at revision **r9** — the latest revision, and the one Palimpsests 1.0 implements | the release tag `v0.15.0`, the first release that carries r9 | [`PROFILE-R9.md`](PROFILE-R9.md) |

The tracks are independent: do either, or both. The profile track needs
a core verifier, and you may write one during it.

Three things neither track is:

- **Not a test of a `palimpsests` package release.** Each track is pinned
  to a tag so that its inputs never move. Whatever the package's current
  version, the core track's inputs are the same four files and the
  profile track's the same six.
- **Not a test of whichever profile text is on `main` today.** The core
  track carries `profiles/inference.md` as it stood on the freeze day —
  context only; nothing in the core pass bar depends on it. The profile
  track carries it at r9. If the profile has moved past r9 by the time
  you read this, r9 is still what the profile track tests; a later
  revision gets a track file of its own.
- **Not the SCITT statement.** That is a separate surface with its own
  task and its own record (`../INDEPENDENT-VERIFICATION.md` §7).

## 1. The boundary — read this first

The exercise tests the *document*, not a conversation and not our code.
It is only meaningful if you work from the allowed inputs alone.

### 1.1 What you may use

- **The input files of your track**, fetched at the track's tag (§1.6).
  Core: `PALA-1.md`, `profiles/robotics.md`, `profiles/inference.md`,
  `test-vectors.json`. Profile: the six files listed in `PROFILE-R9.md`.
- **The files of this kit**: this README, `PROFILE-R9.md`, the two
  run-record templates and `fetch-inputs.sh`.
- **Public standards the specification itself cites**: RFC 2119,
  RFC 6962, RFC 3161, AES-GCM (NIST SP 800-38D, FIPS 197); for the
  profile track also RFC 8785 and RFC 7493.
- General knowledge of programming, hashing and cryptography, and any
  general-purpose library — a JSON parser, SHA-256, AES-GCM.

### 1.2 What you must not use, from the moment you start until you submit

These, by you or by an assistant:

- **The repository.** Do not clone it and do not browse it beyond this
  folder. It holds the reference implementation, the production
  verifier, the tests and earlier runs' verifiers.
- **The `palimpsests` package.** Do not install it, from PyPI or
  anywhere else: it ships the verifier and the vectors' expected
  answers.
- **The other documents next to the specification**:
  `../INDEPENDENT-VERIFICATION.md`, `../CLARIFICATIONS.md`,
  `../REGISTRIES.md`, `../ANCHOR-SOURCES.md`, `../consistency-proof.md`,
  and everything under `../independent-runs/`. The first two describe
  what earlier runs found and how each question was settled — exactly
  the answers this exercise asks you to reach, or not reach, yourself.
  This README names them so that you know where your run will be
  recorded; read them after you submit.
- **Other people's implementations and reports**, wherever they are
  hosted, including the public issue where agent reports are collected
  (#318).
- **A web search for implementations of PALA-1 or for answers to the
  task**, by you or by an assistant.

### 1.3 What you may read, and must list

The project's **website and notes** and its **Internet-Draft** describe
the format in prose. They are not off limits; most people arrive through
them. If you read any of them — before the run or during it — list them
in the record (the template has a line for it). A reader who
knows what you had in front of you can weigh your ambiguity log
properly; that is the whole reason for the line.

### 1.4 Questions are logged, not asked

If the text is ambiguous, record the ambiguity, make a documented
choice, and continue. Every logged ambiguity is a specification defect
by the spec's own standard — your log is a deliverable, not an
inconvenience. Do not ask the maintainers, and do not look the answer
up: an answer obtained either way tests something other than the
document.

### 1.5 AI assistance

Allowed, with disclosure. Three conditions:

- the assistant works under the same boundary — §1.1 to §1.3, no
  browsing of the repository, no search for other implementations;
- you name the tool and the model in the record;
- you say whether the model could have seen this repository in
  training. The repository has been public since 2026-07-06. If the
  model's training ends before that date, say so; if it ends after, or
  you do not know, say that.

### 1.6 Getting the inputs

```sh
sh fetch-inputs.sh            # core track    -> ./pala1-package/
sh fetch-inputs.sh profile    # profile track -> ./pala1-profile-r9-package/
```

It needs a POSIX shell, `curl`, and `sha256sum` or `shasum`, and checks
every digest. Leave `PALA1_REF` unset: it exists for the maintainers,
and any other ref fails the digest check.

Without a shell, download the files by hand and compute their SHA-256
yourself. For the core track:

```
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/PALA-1.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/profiles/robotics.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/profiles/inference.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/test-vectors.json
```

keeping the `profiles/` folder. The digests must be these. If one
differs, stop: you do not hold the frozen inputs.

```
b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5  PALA-1.md
20093ccd12075aef2062603b5282df83e70ce3a59944173d930183ca6e36fe56  profiles/robotics.md
3ef8feb3017bd24ca117710c7983641ee5a3803272b6dea82937d60735449a0f  profiles/inference.md
476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193  test-vectors.json
```

The profile track's addresses and digests are in `PROFILE-R9.md` §P1.

## 2. The task — core track

The profile track's task is in [`PROFILE-R9.md`](PROFILE-R9.md).

In any language, with no code from this repository:

1. Build the §2.4 file container from `test-vectors.json` (concatenate
   each record's `header_hex` and, where present, `body_hex`).
2. Implement §7.1 header-only chain verification and §7.2 completeness
   against an anchor.
3. Implement the §4.3 Merkle tree (either construction; both agree).
4. Reproduce, from that container, **every value in the §8 "Expected
   results" block** of `PALA-1.md`.

Section numbers in this section are those of `PALA-1.md`. The block
holds eleven values, numbered here as in the run record:

| # | Value | Note |
|---|---|---|
| 1 | `chain_head` | |
| 2 | `chain_ok` | |
| 3 | `record_count` | |
| 4 | `breaks` | empty |
| 5 | `gaps` | empty |
| 6 | `violations` | empty |
| 7 | `complete_to_anchor` | checked against the top-level `anchor_head` of `test-vectors.json` — not against the head carried inside the `ANCHOR` record, which the specification says is a different thing |
| 8 | `anchor_head` | |
| 9 | `merkle_tree_hash` | recomputed from the published leaves (`merkle.leaves`), not copied from the record |
| 10 | `merkle_leaf_count` | |
| 11 | inclusion proof for leaf 7 | length 5, verifying against the root you recomputed |

That block is the pass bar: **an implementation that disagrees with any
of these is wrong, or the specification is** — the spec's own words, and
earlier runs exercised both directions of that sentence.

Reproducing the seven §8 mutation demos (`body_bitflip`,
`unknown_record_type`, `tail_truncation`, `stale_anchor`, `seq_gap`,
`missing_genesis`, `unknown_time_with_clock`) is a SHOULD: each one
demonstrates a diagnosis the format promises. A run that skips them
still passes; say which you ran. The strongest prior finding came from a
demo constructed *more aggressively* than the published one — building
your own discriminating inputs is encouraged.

Anything beyond that is an extra and is welcome: recomputing every
`record_hash`, checking `body_digest`, decrypting the encrypted body.

## 3. What to submit

There are two ways to report, and they are recorded differently.

### 3.1 A recorded run

Three things:

1. **Your verifier source** — any language; nothing about your method
   has to resemble anything of ours.
2. **The filled run record** — `RUN-RECORD-TEMPLATE.md` for the core
   track, `RUN-RECORD-PROFILE-TEMPLATE.md` for the profile track,
   including the eligibility attestation.
3. **Your ambiguity log** — part of the template. "None" is a valid and
   valuable answer.

Send them by opening an issue on the repository — titled
`PALA-1 verification run` for the core track, `PALA-1 profile run (r9)`
for the profile track — with the three items attached, or by email to
the security contact in `SECURITY.md`. Every submission is answered.

A run that meets §1 is archived byte-exact under
`../independent-runs/<name>/` and listed in
`../INDEPENDENT-VERIFICATION.md`: core runs in §5, profile runs in §8.
The two are kept apart, because neither is evidence for the other. From
then on a run is off-limits to the next fresh run of its track.

**It is published.** The archive is this public repository. Your
verifier, record and log are kept there under the repository's licence
(`CONTRIBUTING.md`, "Licensing of contributions"), with your name and
contact as you write them in the record. If you want to be named
differently, or want your contact left out, say so in the record; that
is respected.

### 3.2 A short report from a coding agent

If you gave the task to a coding agent with the prompt from the
project's note and have only what it printed, post that as a comment on
issue #318. That prompt covers the core track only. Those reports are collected in one table. They are not
recorded runs and are not counted among the independent
implementations, because there is no verifier and no record to archive.
To turn one into a recorded run, submit the three items of §3.1.

## 4. What a divergence means

For the profile track, see `PROFILE-R9.md` §P4. For the core track: the
wire is frozen: if your value disagrees with §8, either your
implementation is wrong or the *frozen* specification is — and the
second outcome is exactly what this process exists to catch. A confirmed
text defect is fixed as an erratum with the vectors byte-identical; a
confirmed **wire** defect would be handled as a new format version,
never as an edit to v1.0. Minimize a divergence to the first differing
byte before submitting — it makes adjudication fast in both directions.

A divergence does not disqualify a run. Submit it as it is.

## 5. For maintainers

How the five core implementations are counted, and when each count held,
is in `../CLARIFICATIONS.md` ("Implementation count"). Runs #1–#4 and the
runs after the freeze are in `../INDEPENDENT-VERIFICATION.md` §5; profile
runs go in its §8.

**When the profile gets a new revision.** Add `PROFILE-R<n>.md` and a
track in `fetch-inputs.sh`, both pinned at the tag of the first release
that carries the revision, and change the row in §0. Leave
`PROFILE-R9.md` as it is: a run already made against r9 must stay
reproducible, and r9 is not edited in place (`profiles/inference.md`
§9.1).

`tests/test_verification_kit.py` holds this kit together: the digests
here and in `PROFILE-R9.md` are the ones `fetch-inputs.sh` enforces; the
frozen core files and the r9 profile files on disk have those digests;
the values, cases and rules the templates ask for are the ones the task
texts and the vectors name. If that test fails because the profile was
edited, the profile's own rule was broken, not the kit.
