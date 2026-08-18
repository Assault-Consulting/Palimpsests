# PALA-1 v1.0 — independent verification run: method and rationale

A step-by-step account of how this run was executed and **why each
decision was taken that way**. It is written so that a reader who has
never seen the run can re-derive it, and so that a reviewer can attack
the choices rather than guess at them.

- **Date:** 2026-08-18
- **Target:** PALA-1 v1.0, frozen 2026-08-09, at tag `pala1-v1.0`
- **Result:** all 11 §8 values reproduced on first execution; all 7
  published demos reproduced; 13 further adversarial cases constructed and
  run; 140 checks total, 0 failures; 8 ambiguities logged; 1
  specification-completeness gap reported.

---

## 0. What the exercise actually asks for

The kit's `README.md` frames the task as a test of a **document**, not of
a codebase. The spec's own opening sentence is the pass condition:

> An independent party must be able to write a verifier from this
> document alone, without our code.

That framing determined nearly every decision below. Two consequences
worth making explicit up front, because they shape everything after:

1. **A run that reproduces the numbers but reads the reference code
   proves nothing.** The value of the exercise is entirely in the
   isolation. So the boundary is not a formality to be waved through — it
   is the deliverable's load-bearing element, and the first section below
   is about enforcing it.
2. **An ambiguity is a finding, not a nuisance.** The spec says so
   directly: *"Where the prose is ambiguous, the specification is
   defective — not the implementer."* So the correct behaviour on hitting
   an unclear passage is to record it, choose, document the choice, and
   continue — never to go looking for the answer in code, and never to
   quietly pick the reading that makes the numbers work.

---

## 1. The boundary, and how it was enforced

### 1.1 A local copy, and why it did not matter

The machine used for this run also holds a local copy of the project.
The project is open source and public, so a copy is something any reader
could obtain in a minute; its presence is worth a sentence, not a
paragraph. The relevant question is not whether a copy existed but
whether the run used it, and it did not: the four allowed inputs were
fetched fresh from the frozen tag and digest-checked, the verifier was
developed in a separate directory with no path into the copy, and the
files the kit places off-limits were not opened (`RUN-RECORD.md` →
"Eligibility" lists them).

**What the evidence supports independently of any attestation.** The
verifier is written in Perl, in an environment with **no working Python
interpreter at all** — so the Python reference implementation could not
have been executed even in principle, and no output of it exists to have
been copied. The verifier's structure follows the §7.1 pseudocode's own
ordering and sentinels rather than any idiom a Python codec would
suggest. And the run's one finding (§10) is a gap in §7 that reading the
reference implementation could not have revealed, because it concerns a
check the specification never defines for anyone to implement.

### 1.2 What was read, and what was not

**Read, in full:**

| File | Why permitted |
|---|---|
| `verification-kit/README.md`, `RUN-RECORD-TEMPLATE.md`, `fetch-inputs.sh` | The kit itself; reading them *is* the instruction |
| `PALA-1.md` | Allowed input |
| `profiles/robotics.md` | Allowed input |
| `profiles/inference.md` | Allowed input |
| `test-vectors.json` | Allowed input |

**Deliberately not opened at any point:** `palaudit_ref.py` (the
reference implementation), `gen_vectors.py` (the vector generator — it
would give away the intended construction of everything), everything
under `src/palimpsests/audit/`, everything under `tests/`, everything
under `docs/specs/pala-1/independent-runs/` (earlier runs' verifiers and
logs), `INDEPENDENT-VERIFICATION.md`, `ANCHOR-SOURCES.md`,
`REGISTRIES.md`, `profiles/inference-vectors.json`,
`profiles/gen_inference_vectors.py`.

Two of those merit a note:

- **`INDEPENDENT-VERIFICATION.md` was not read**, even though the kit
  cites it for the submission protocol (§6). It is the record of earlier
  runs, and the kit disqualifies reading *"any earlier run's verifier or
  logs"*. Knowing which four defects previous runs found would have told
  this run where to look — which is precisely the contamination the
  exercise exists to avoid. The cost is that the submission format here
  is inferred from `RUN-RECORD-TEMPLATE.md` alone. That is the cheaper
  error.
- **`gen_vectors.py` was not read** although it sits beside the spec and
  is not named in the kit's exclusion list. It generates the vectors, so
  it encodes the intended answer to every construction question. Treating
  it as forbidden follows the kit's stated principle rather than its
  literal enumeration.

Pathnames of excluded files were unavoidably observed (locating the kit
required listing the tree). No content was.

### 1.3 Sealing the inputs

Rather than reading the four files from the local clone — where they are
byte-identical but where the provenance would be muddled — the kit's own
script was run in an isolated scratch directory, fetching from
`raw.githubusercontent.com` at the `pala1-v1.0` tag:

```
fetching PALA-1.md               OK  b4ea536b…381d5
fetching profiles/robotics.md    OK  20093ccd…6fe56
fetching profiles/inference.md   OK  3ef8feb3…49a0f
fetching test-vectors.json       OK  476c05ce…a8193
```

All four matched the digests pinned in the kit. **Why bother, given the
local clone had the same bytes:** the digest check is the only mechanism
that proves *which* version was verified. A frozen spec's whole claim is
that its bytes do not move; a run that cannot name the bytes it read
cannot support a claim about them. The check costs one command.

The verifier was then developed in a scratch directory containing
**only** `pala1-package/` and the verifier's own source — no path into
the repository.

---

## 2. Environment survey, and the choice of Perl

Before writing anything, the available toolchains were surveyed. The
result was constraining: no Python (only the Microsoft Store stubs, which
do not execute), no Node, no Go, no compiler, and a .NET *runtime*
without an SDK. What did exist: **Perl 5.42.2 with core `Digest::SHA`
and `JSON::PP`**.

That turned a constraint into an advantage, and Perl was adopted
deliberately rather than reluctantly:

1. **The reference implementation is Python.** Writing the verifier in a
   different language removes any possibility of structural
   correspondence — no shared idiom, no shared library behaviour, no
   accidental convergence through a common `hashlib` or `struct` habit.
   An independent implementation in the *same* language as the reference
   is a weaker instrument even when honestly written.
2. **Core modules only.** `Digest::SHA` provides SHA-256; `JSON::PP`
   reads the vectors. No dependency resolution, nothing to audit beyond
   the run's own source, and the run reproduces on any stock Perl.
3. **Perl's `pack`/`unpack` are an explicit, auditable way to express a
   packed little-endian binary layout** — `Q<` for u64 LE, `q<` for i64
   LE, `v` for u16 LE, `V` for u32 LE. Each field decode reads as a
   direct transcription of the §2.1 offset table, which is what a
   reviewer needs to check.

The one cost: no AES-GCM anywhere in core. That is dealt with in §7
below.

---

## 3. Reading order, and why the spec was read before the vectors

The spec was read end to end **before** the vectors were examined in any
detail beyond their key structure. The order matters and was chosen on
purpose: reading the vectors first invites building an implementation
that reproduces *those bytes*, then rationalising it against the prose
afterwards. That is the failure mode the exercise is designed to catch —
it produces a verifier that agrees with the vectors and with nothing
else, and it cannot detect a defect because it has assumed the vectors
are correct.

Reading order used:

1. `PALA-1.md` in full (795 lines), §1 → §11.
2. `profiles/robotics.md` — the profile the vectors follow.
3. `profiles/inference.md` — read for completeness; it defers `MERKLE`
   and does not bear on the vectors.
4. `test-vectors.json` — **structure only** at first (key names, record
   count, which records carry bodies), enough to write the container
   builder. The expected values in `verify` and `merkle` were not
   consulted until the verifier was finished and run.

---

## 4. Architecture, and why it is shaped this way

Four source files, deliberately separated:

```
verifier/
  PALA1.pm            core: §2.1 decode, §2.2 TLV, §2.4 container,
                      §7.1 chain, §7.2 completeness, §4.3 Merkle
  AESGCM.pm           AES-256-GCM from FIPS-197 / SP 800-38D (§4.4 extra)
  build-container.pl  test-vectors.json -> chain.pala
  run-suite.pl        the 11 §8 values
  demos.pl            7 published demos + 13 constructed cases
  body-check.pl       §7.5 digests, §4.4 decryption
  narrative-check.pl  the §8 prose table vs. the actual bytes
```

Three architectural decisions carried real weight:

### 4.1 The verifier consumes a binary container, never the JSON

`build-container.pl` writes `chain.pala` (2315 bytes) once; everything
downstream reads *that file*. The verifier has no idea `test-vectors.json`
exists.

**Why:** §2.4 defines a file format whose records are self-delimiting,
with boundaries found by reading `header_len` and `body_len` out of the
records themselves. A verifier handed a pre-split JSON array never
exercises that. It cannot detect a truncated tail, cannot be fed a
byte-level mutation, and silently inherits the vectors' own framing
assumptions. Building the container first is what makes the §2.4 rules
testable at all — and it is what let case D (a file cut mid-record) be
constructed and correctly diagnosed as a truncated tail rather than a
chain break.

The builder does cross-check the vectors' declared `header_len` and
`body_len` against the hex strings they ship, and would abort on
disagreement. It did not fire.

### 4.2 §7.1 is transcribed from the pseudocode, in its order

The chain verifier follows the §7.1 pseudocode line by line, including
the order of checks and the `prev`/`expected` "unset" sentinels, rather
than being restructured into something more idiomatic.

**Why:** the pseudocode's *structure* is normative in places where the
prose is subtle — specifically the nesting of the zero-`prev_hash` check
inside `if h.record_type == GENESIS`, and the fact that `prev` starts
**unset** rather than as 32 zero bytes. Those two details are the entire
difference between the correct and the superseded reading of the
`missing_genesis` case (one violation and no break, versus two violations
and a spurious break). Restructuring for elegance is exactly how an
implementer loses them. Idiomatic Perl was traded away for traceability
to the source text.

### 4.3 Mutations are byte-level edits to the container

Every demo mutates `chain.pala` as bytes — flipping a bit at a computed
offset, truncating at a record boundary, splicing two record segments —
and feeds the result to the *same* verifier used for the pass bar.

**Why:** a demo that constructs a mutated case through the verifier's own
data structures tests the reporting layer, not the format. A bit flipped
in a file is the thing an auditor actually faces. It also means the demos
share no code path with the pass bar beyond the verifier itself, so a bug
in the verifier cannot hide by being present in both.

---

## 5. Implementing the sections: the decisions that were not free

Most of the spec transcribes without judgement. These did not.

**§2.1 header decode.** Field-by-field transcription of the offset table.
`wall_clock_ns` decoded with `q<` (signed) because the table types it
i64, even though §5 describes only non-negative values — the table is the
layout authority. This is ambiguity-log item 5.

**§2.3 `body_len` and the nonce.** The spec spends a paragraph warning
that the 12-byte nonce is *inside* `body_len`, not additional to it, and
names this "the one place where an implementer can be confidently wrong".
The implementation treats `body_len` as the total following the header
and slices `nonce ‖ ciphertext ‖ tag` out of it. Verified explicitly in
`body-check.pl`: `12 + len(ct) + 16 == body_len == 75`. Without that
paragraph this would very likely have been wrong.

**§2.4 container splitting.** Boundaries from `header_len + body_len`. A
final record ending exactly at EOF is well-formed; anything else is a
**truncated tail**, reported separately from `breaks` — §2.4 is explicit
that a truncated tail "is not a chain break at any earlier record", and
conflating them would destroy the §7.1/§7.2 distinction the format is
built on.

**§7.1 `breaks` vs. loop control.** The pseudocode's
`MUST h.magic == "PALA" else break, stop` overloads the word "break",
which also names a report field. Read as loop control; no `breaks` entry
emitted, since a record with bad magic has no trustworthy `seq` to key
one to. Ambiguity-log item 2.

**§7.1 `header_len` self-check.** `MUST h.header_len == actual header
bytes` cannot fire in a reader that uses `header_len` to find the header
in the first place. Implemented literally; the falsifiable weight was
placed on §7.4's "TLV items end exactly at `header_len`". Ambiguity-log
item 1.

**§7.4 applied only to interpretable records.** §7.6 says a verifier
MUST NOT apply §7.4 to unknown versions or types. Since §7.1 places the
TLV structural check inside §7.4, that check is skipped too — a reading
that is defensible but not the only one, given §7.6 freezes `header_len`
across all future versions. Ambiguity-log item 4, and tested sharply by
case F.

**§4.3 Merkle: both constructions implemented.** The spec says the
iterative promotion form and the RFC 6962 recursive form agree, and tells
the implementer not to go hunting for a discrepancy. Both were
implemented anyway and compared — on the published 30 leaves, and then on
every leaf count from 0 to 200.

**Why implement a construction the spec says is redundant:** because
"they agree" is a *claim in the document under test*, and this exercise
tests the document. Taking it on trust would have left one of the spec's
own assertions unverified while nominally verifying the spec. They do
agree, at all 201 sizes.

**§4.3 promotion, not duplication.** Unpaired nodes are promoted. Rather
than assert this, `demos.pl` case K computes what the *duplicating*
construction would produce for `[a,b,c]` and confirms it collides with
`root([a,b,c,c])` — CVE-2012-2459, reproduced — while the promoting
construction keeps them distinct.

**§4.3 proofs at promoted levels.** A promoted node has no sibling, so no
proof entry is emitted for that level. The spec does not say this. The
choice was validated two ways: the independently generated leaf-7 proof
is byte-identical to the published `merkle.proof`, and all 30 leaves
verify. It also explains the proof-length distribution (4 for two leaves,
5 for the other 28), which a fixed-depth reading would not produce.
Ambiguity-log item 3.

---

## 6. The pass bar

`run-suite.pl` computes all eleven values and compares each to the
published block. **All eleven matched on the first execution**, with no
subsequent adjustment to the implementation.

The two values that were computed the hard way on purpose:

- **`merkle_tree_hash` is recomputed from `merkle.leaves`**, never read
  from the `MERKLE` record's `0x0011` TLV. The kit asks for this
  specifically, and it is the difference between verifying a tree and
  echoing a field. The record's TLV is checked *afterwards*, as a separate
  assertion that the record commits to what the leaves produce.
- **The leaf-7 proof is folded against the recomputed root**, not against
  the published `tree_hash`. Folding against a published constant would
  verify the proof against an assumption rather than against the tree.

---

## 7. AES-256-GCM, written from the standards

§4.4 is normative, and nothing a header-only verifier does touches it.
Its two substantive claims — that the AAD binds a body to its position so
bodies cannot be swapped, and that destroying a key leaves the chain
intact — are both falsifiable, and both were worth testing rather than
believing. With no crypto library available, `AESGCM.pm` implements
AES-256 from FIPS-197 and GCM from NIST SP 800-38D.

Two implementation choices worth defending:

- **The S-box is computed from its algebraic definition** (multiplicative
  inverse in GF(2⁸), then the affine transform), not pasted as a 256-byte
  table. A pasted table is unauditable magic; a generated one can be
  checked against the standard's definition by reading eight lines.
- **The module self-tests before it is allowed to say anything about a
  PALA-1 body** — FIPS-197 C.3 for the block cipher, SP 800-38D GCM cases
  13, 14 and 16 for the mode, plus a round trip and a deliberately wrong
  AAD that must be rejected. An untested from-scratch cipher producing a
  plausible plaintext would be worse than no result, because it would look
  like evidence.

With that in place, §4.4 was tested rather than assumed:

| Claim | How it was tested | Result |
|---|---|---|
| Body decrypts to the published plaintext | derived nonce + 26-byte AAD | matches |
| Encryption is deterministic and the vectors are self-consistent | re-encrypt the plaintext | **byte-identical** to the published body |
| "Bodies cannot be swapped between records" | decrypt seq 3's body under seq 5's AAD | rejected |
| The binding is to `seq` specifically | alter only `seq` inside the AAD | rejected |
| Tampering is caught | flip one ciphertext bit | rejected |
| Crypto-shredding | decrypt with a destroyed key | unreadable, **`body_digest` still matches, chain still verifies** |

---

## 8. Checking the prose against the bytes

`narrative-check.pl` exists because the run record's defect section names
a category most verifiers never test: *"a demo that encodes something
other than what its prose claims"*. A verifier that only reproduces §8's
numeric block never checks whether the §8 *table* is true.

So every claim in the §8 narrative table was checked against the
container: all 12 record types at their stated `seq`; `SHED_CLASS = 1`,
`SHED_COUNT = 400`, `SHED_WINDOW_NS = 12 s`; `WITNESS_KIND = 1` covering
range 0–9; `SHRED_KEY_ID = 7`; the three `ORIGIN_*` TLVs including the
robotics profile's role vocabulary (`brain`, `eyes.tier1`,
`perception_health`); the `ANCHOR_HEAD` value §8 prints inline; and eight
cross-cutting envelope invariants. 50 checks.

**This is what produced the run's one substantive finding**, and it did so
through a failed assumption rather than a passed test — see below.

---

## 9. The two failures the run hit, and what they were

Neither touched a §8 value. Both are recorded because a run that reports
only its successes is not a report.

**Failure 1 — a bug in this verifier.** Two demo comparisons failed on
the free-text `anchor_reason` strings. Cause: the Perl source contained
em-dash literals without `use utf8`, so source bytes were compared
against JSON-decoded characters. Fixed by adding `use utf8` to the
module. A pure encoding defect on this side; the spec and vectors were
not involved.

**Failure 2 — a wrong assumption, which turned out to be the interesting
one.** `narrative-check.pl` asserted that the seq-3 `EVENT` (the `c'`
write) sits inside the brain span, i.e. shares seq 2's `span_id`. It does
not. Inspecting the span fields showed:

```
seq  type         span_id     parent_span_id
2    SPAN_START   1111…       0000…            (root span: "brain")
3    EVENT        2222…       1111…            (child of brain)
6    SAFETY       2222…       1111…            (child of brain)
8    SPAN_END     1111…       0000…
```

The vectors encode a **two-level span tree**, which is correct and richer
than assumed — `parent_span_id` is exercised properly, and the check was
corrected to match. But the inspection exposed something else: the child
span `2222…` is referenced by two records and has **no `SPAN_START` and no
`SPAN_END` anywhere in the chain**.

---

## 10. The finding, stated carefully

This is a specification-completeness gap. It is **not** a wire defect, it
contradicts **no** §8 value, and `chain_ok = true` is the correct result
for this chain under the text as written.

§3.1 makes an evidentiary promise in normative-sounding language — *"A
crash **must** leave a visibly unclosed span, because that is the
evidence"* — and §3.1 frames the design's central limit as *"detectable
silence"*. But **no check in §7 makes an unclosed span visible.** §7.4's
list covers time trust, `body_len`/`body_digest` agreement, key/length
constraints and TLV framing, and stops. `span_id` and `parent_span_id`
are envelope fields, not profile content, so this is not deferred to a
profile either.

What makes it worth raising rather than shrugging at is the **asymmetry**:
§7.4 explicitly justifies its one deliberate omission — *"`MERKLE_LEAF_COUNT`
is deliberately **not** among these checks"* — with a paragraph
explaining why a header-only verifier cannot check it. The span omission
gets no such note, so an implementer genuinely cannot tell whether it is
a decision or an oversight. And the committed vectors happen to contain a
span with neither endpoint, which no §7 check flags.

To be precise about what the vectors do and do not show: this is *not* a
`SPAN_START` without its `SPAN_END`, which would be §3.1's crash evidence
correctly demonstrated. It is a span referenced by two records with
neither endpoint present.

**Consequence:** two conformant verifiers will differ on whether a user is
ever shown an unpaired span, and the format's headline guarantee — that
absence is visible — is not operationalized anywhere a verifier is
instructed to look.

**Suggested resolution** (either is a text-only change; the vectors need
not move a byte):

1. Add a span-pairing check to §7.4, reported as a violation or as a
   distinct "unpaired span" class; or
2. Add a sentence to §7.4 stating that span structure is deliberately out
   of scope, and why — matching the treatment `MERKLE_LEAF_COUNT`
   already receives.

---

## 11. Reproducing this run

```bash
sh ../../verification-kit/fetch-inputs.sh && sh verifier/run-all.sh
```

Requires Perl 5 with core modules only. The full transcript is in
`output/full-run.log`.

| Suite | Checks | Result |
|---|---:|---|
| §8 expected results (pass bar) | 11 | 11 MATCH, 0 DIVERGE |
| §8 demos + constructed cases | 60 | 60 pass |
| §7.5 / §4.4 bodies and crypto | 19 | 19 pass |
| §8 narrative vs. bytes | 50 | 50 pass |
| **Total** | **140** | **0 failures** |

---

## 12. What was deliberately not done

Stated so the run's limits are not mistaken for coverage.

- **§7.3 witness verification.** Out of scope by the spec's own text — it
  follows the witness's protocol (Rekor, RFC 3161). Only the in-chain
  claim was checked: that the `WITNESS` record exists, is itself chained,
  and names its range explicitly (0–9).
- **The inference profile was not exercised.** It defers `MERKLE` until it
  defines a leaf source, and the committed vectors follow the robotics
  profile. Its own vectors were not fetched — they are not among the four
  allowed inputs.
- **No performance, concurrency or storage behaviour** was examined. The
  spec's open issue 2 (one chain or several) is explicitly unmeasured, and
  nothing here measures it.
- **Tier B/B+ claims were not evaluated.** They depend on hardware roots of
  trust and NV counters that no document-level exercise can reach; §6 and
  open issue 4 say as much.
- **No attempt was made to find the four previously-reported defects**, since
  the record describing them was deliberately not read. Any overlap between
  this run's ambiguity log and earlier findings is convergent, not derived.
