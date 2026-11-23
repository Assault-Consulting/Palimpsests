# PALA-1 verification kit — verify the frozen format yourself

PALA-1 is frozen at v1.0 on the strength of one sentence:

> **An independent party must be able to write a verifier from the
> specification alone, without our code.**

Five independent implementations — three of them by people outside the
project at the time of their runs — have passed that test. This kit
exists so that **anyone** can run the same exercise, on the same terms,
at any time. Every submitted run becomes part of the permanent
verification record.

No permission is needed. No contact with the maintainers is needed until
you submit. Expect roughly 1.5–4 hours.

## 0. What this kit tests, and what it does not

**It tests one thing: the PALA-1 core format, version 1.0**, as it was
frozen on 2026-08-09 at the Git tag `pala1-v1.0`.

- **Not a release of the `palimpsests` package.** `pala1-v1.0` is the
  format's tag. Package releases have tags of their own (`v0.15.0` and
  so on) and are not what you verify here. Whatever the package's
  current version, the inputs of this kit are the same four files.
- **Not the inference profile as it is today.** The package holds
  `profiles/inference.md` as it stood on the freeze day. The profile has
  been revised since, on `main`; those revisions are outside this
  exercise. Do not fetch the current one.
- **Not the SCITT statement.** That is a separate surface with its own
  task and its own record (`../INDEPENDENT-VERIFICATION.md` §7).

The pass bar (§2) can be met from `PALA-1.md` and `test-vectors.json`
alone. The two profile documents travel with them because the
specification refers to them; nothing in the pass bar depends on their
content.

## 1. The boundary — read this first

The exercise tests the *document*, not a conversation and not our code.
It is only meaningful if you work from the allowed inputs alone.

### 1.1 What you may use

- **The four input files**, fetched at the `pala1-v1.0` tag:
  `PALA-1.md`, `profiles/robotics.md`, `profiles/inference.md`,
  `test-vectors.json`.
- **The three files of this kit**: this README, `RUN-RECORD-TEMPLATE.md`
  and `fetch-inputs.sh`.
- **Public standards the specification itself cites**: RFC 2119,
  RFC 6962, RFC 3161, AES-GCM (NIST SP 800-38D, FIPS 197).
- General knowledge of programming, hashing and cryptography, and any
  general-purpose library — a JSON parser, SHA-256, AES-GCM.

### 1.2 What you must not use, from the moment you start until you submit

Everything else that describes PALA-1. In particular:

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
- **Anything published about the format elsewhere**: the project's
  website and notes, the Internet-Draft, the public issue where agent
  reports are collected (#318), and other people's verifiers or reports
  wherever they are hosted.
- **A web search for PALA-1**, by you or by an assistant.

What you read *before* you decided to do a run does not disqualify you —
most people arrive through the website. Write it down in the record
(the template has a line for it), and from the start of the run use
only §1.1.

### 1.3 Questions are logged, not asked

If the text is ambiguous, record the ambiguity, make a documented
choice, and continue. Every logged ambiguity is a specification defect
by the spec's own standard — your log is a deliverable, not an
inconvenience. Do not ask the maintainers, and do not look the answer
up: an answer obtained either way tests something other than the
document.

### 1.4 AI assistance

Allowed, with disclosure. Three conditions:

- the assistant works under the same boundary — only §1.1, no browsing
  of the repository, no web search for PALA-1;
- you name the tool and the model in the record;
- you say whether the model could have seen this repository in
  training. The repository has been public since 2026-07-06. If the
  model's training ends before that date, say so; if it ends after, or
  you do not know, say that.

### 1.5 Getting the inputs

```sh
sh fetch-inputs.sh        # builds ./pala1-package/ and checks digests
```

It needs a POSIX shell, `curl`, and `sha256sum` or `shasum`. Leave
`PALA1_REF` unset: it exists for the maintainers, and any other ref
fails the digest check.

Without a shell, download the four files by hand from

```
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/PALA-1.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/profiles/robotics.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/profiles/inference.md
https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/test-vectors.json
```

keeping the `profiles/` folder, and compute their SHA-256 yourself.
Either way the digests must be these. If one differs, stop: you do not
hold the frozen inputs.

```
b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5  PALA-1.md
20093ccd12075aef2062603b5282df83e70ce3a59944173d930183ca6e36fe56  profiles/robotics.md
3ef8feb3017bd24ca117710c7983641ee5a3803272b6dea82937d60735449a0f  profiles/inference.md
476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193  test-vectors.json
```

## 2. The task

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
2. **The filled run record** — `RUN-RECORD-TEMPLATE.md` alongside this
   file, including the eligibility attestation.
3. **Your ambiguity log** — part of the template. "None" is a valid and
   valuable answer.

Send them by opening an issue on the repository titled
`PALA-1 verification run` with the three items attached, or by email to
the security contact in `SECURITY.md`. Every submission is answered.

A run that meets §1 is archived byte-exact under
`../independent-runs/<name>/` and listed in
`../INDEPENDENT-VERIFICATION.md` §5. From then on it is off-limits to
the next fresh run.

**It is published.** The archive is this public repository. Your
verifier, record and log are kept there under the repository's licence
(`CONTRIBUTING.md`, "Licensing of contributions"), with your name and
contact as you write them in the record. If you want to be named
differently, or want your contact left out, say so in the record; that
is respected.

### 3.2 A short report from a coding agent

If you gave the task to a coding agent with the prompt from the
project's note and have only what it printed, post that as a comment on
issue #318. Those reports are collected in one table. They are not
recorded runs and are not counted among the independent
implementations, because there is no verifier and no record to archive.
To turn one into a recorded run, submit the three items of §3.1.

## 4. What a divergence means

The wire is frozen: if your value disagrees with §8, either your
implementation is wrong or the *frozen* specification is — and the
second outcome is exactly what this process exists to catch. A confirmed
text defect is fixed as an erratum with the vectors byte-identical; a
confirmed **wire** defect would be handled as a new format version,
never as an edit to v1.0. Minimize a divergence to the first differing
byte before submitting — it makes adjudication fast in both directions.

A divergence does not disqualify a run. Submit it as it is.

## 5. For maintainers

How the five implementations are counted, and when each count held, is
in `../CLARIFICATIONS.md` ("Implementation count"). Runs #1–#4 and the
runs after the freeze are in `../INDEPENDENT-VERIFICATION.md` §5.
`tests/test_verification_kit.py` holds this kit to the frozen files: the
digests above are those of the four inputs at the tag, and the same ones
`fetch-inputs.sh` enforces.
