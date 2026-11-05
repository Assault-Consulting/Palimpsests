# DPS reading 2b: the negative vectors of Appendix D.6, on reading 2's verifier

This run extends dps-reading-2. Reading 2 replayed four OpenTimestamps proofs from the text of draft-fassbender-scitt-time-anchor-08 and reported each step on its own. It did not produce VERIFY-ANCHOR's verdict, and it did not run the draft's negative vectors.

This run does both with the same implementation:
- it adds the verdict of Section 4.1 on top of reading 2's parser and replay, leaving their logic unchanged;
- it runs the positive result Appendix D.3 states, and the two negative vectors of Appendix D.6.

This run was carried out by an AI assistant under the direction of Andrii Sparysh.

## What was read (pinned)

| Input | Pin | How read |
|---|---|---|
| `dps-reading-2.zip`, reading 2's record with its verifier | SHA-256 `e608c833a7d525296054e261e07667fdecc9a848ffc23039698bb7db6f68b1a2` | Uploaded by Andrii Sparysh; the digest matched the prompt's |
| draft-fassbender-scitt-time-anchor-08 | SHA-256 `687000b938fcea6b15871f9ea20dc4694f89b7a78f719bacc72ef0ecf1da3394` | Uploaded by Andrii Sparysh; the digest matched the prompt's. Placed at `inputs/ietf/` because www.ietf.org was not reachable from the sandbox |
| `dps-reading-2b-PROMPT.md` | SHA-256 `b50b1a9a0d30a60ed6682a8df2ac0f3514dab3570669b1200d891c19487f26be` | Uploaded; digest recorded as the prompt asks |
| Proofs, artifacts and headers (Laurent-Lemonnier/dps-scitt-decision-layer at `549b50afb146c172d92177063b4e3d3d3e17beab`) | 10 files, SHA-256 checked by reading 2's fetch script | Fetched by `dps-reading-2/inputs/dps-reading-2-fetch-inputs.sh`; read as data |
| decision-provenance-standard/standard at `007f8c9…` | 14 files, SHA-256 checked by the same script | Fetched by the script; not opened by this run |
| RFCs the draft cites | none fetched | www.rfc-editor.org was not reachable. Applied from knowledge: RFC 8610 (CDDL maps are closed; `.regexp` matches the whole string) and RFC 8949 (deterministic encoding, through cbor2) |
| Bitcoin block header format | none | Applied from knowledge as reading 2 applied it, through its `header_fields`, `sha256d` and `target` |

Recorded in `out/pins.json`. That file also records that reading 2's replay (`verifier/ots_replay.py`) was rerun before anything new was written. Its output was byte-identical to the published `out/ots-replay.json` (SHA-256 `4d530f93d2417d412fd0bc45eb9d9f7747328b4c28189d32d5b49cb5e01e6927`, compared with `cmp`).

**Parts of draft -08 read.**
- §1 (to §1.1) and §1.3;
- §2.2 (Proof Bundle) and §2.3 (Notation, to "Storage and control flow");
- §3.4 to §3.4.3; §4.1 to §4.3;
- the opening paragraph of §5; §7.2.1;
- Appendix D, D.1 to D.7.

Draft -03 was not read.

**Parts of reading 2's record read.**
- `README.md`, `ambiguity-log.md`, `out/changes.md`;
- findings F03 and F04;
- `verifier/dpsr/ots.py`, `verifier/ots_replay.py`, `verifier/requirements.txt`, and the fetch script;
- the opening lines of `verifier/dpsr/cbor_strict.py`, opened and not used.

Not opened: its other modules, its suite outputs, findings F01 and F02.

**Events at the boundary.**
- None. No OpenTimestamps or Bitcoin library was installed, read or searched for. The web was not searched.
- Not opened:
  - the `scitt-time-anchor-verifier` repository and verify-anchoring.org;
  - any code, README or Internet-Draft of Laurent Lemonnier's, including `interop/umarise/verify_anchor.py` and `interop/umarise/README.md`;
  - any code or repository of the draft's author;
  - any issue, pull request or commit history.
- Of Lemonnier's repository, only the files reading 2's script fetches were read: the four `.ots`, the four `.txt` and the two headers JSON files.

**Tools.** Python 3.12.3 with the packages of reading 2's `verifier/requirements.txt` and nothing else: `cryptography` 50.0.2, `asn1crypto` 1.5.1, `cbor2` 6.1.5, `jsonschema` 4.26.0 and `referencing` 0.37.0, which pull in attrs 26.1.0, rpds-py 2026.9.1 and jsonschema-specifications 2025.9.1. This run's code imports `cbor2` and the standard library.

## How the run was carried out

1. The three digests were checked (13:19:40Z), reading 2's record was unzipped and its fetch script run. Both SHA-256 checks passed; the draft and the RFCs could not be fetched (see above).
2. Reading 2's replay was rerun and compared byte for byte (identical).
3. The parts of the draft and of reading 2's record listed above were read.
4. The check (`verifier/verify_anchor.py`, `verifier/chain.py`) and the harness (`verifier/run_2b.py`) were written.
   - Before the first run, reading 2's `parse` and `replay` were timed on one proof to size the runs: 0.14 ms each. This was not a VERIFY-ANCHOR run.
5. Every group was run once (`out/first-run/`, 13:26:12Z).
6. One change was made to the harness (`out/changes.md`, C01) and every group was run again (`out/final/`, 13:26:53Z). `verifier/make_report.py` then wrote `out/report.json`.
7. After all runs, reading 2's record and a fresh unzip of `dps-reading-2.zip` were compared with `diff -r` (no difference), and reading 2's replay was run again (byte-identical).
8. Rerun from a clean copy:
   - `verifier/` was copied next to a fresh unzip of reading 2 and run again.
   - Every file of `out/final/` except `timing.json`, and `out/report.json`, were reproduced byte for byte.

## The implementation

`verifier/verify_anchor.py` imports reading 2's `verifier/` by path and calls its `dpsr.ots.parse`, `replay` and `bitcoin_height` unchanged. Each step of §4.1 maps to code as follows.

| Step | What runs |
|---|---|
| Input | `proof_bundle` is a CBOR map built as §3.4.3's CDDL defines it, decoded and held against the CDDL before step 1 (B01, B11) |
| 1, 2 | SHA-256 of the artifact; `HEX(computed_hash) != STRIP-PREFIX(claimed_hash)` returns invalid |
| 3 | OTS-DESERIALIZE is reading 2's `parse`. A `ProofError` returns invalid, as do a file hash operation other than SHA-256 and `msg != computed_hash`. A Bitcoin attestation whose payload is not a height counts as a parse failure (B05) |
| 4 | No Bitcoin attestation (tag `0588960d73d71901`) anywhere in the tree returns unverifiable |
| 5 | OTS-REPLAY is reading 2's `replay`, started from `computed_hash`. It gives no digest for a branch with an operation other than append, prepend or SHA-256. Each branch keeps its digest and its height together |
| 6 | OTS-ATTESTED-HEIGHT is reading 2's `bitcoin_height` |
| 7a | FETCH-BLOCK-HEADER-BY-HEIGHT reads Lemonnier's `headers-957289-957300.json`: 80 bytes, or NULL (B10) |
| 7b | VALIDATE-HEADER-ON-CHAIN gives NULL with no view. With a header set, it returns the candidate only where the set holds a header at H equal to it (B07(a)) |
| 8 | §4.1's classification and combination as written: `unsupported`, `unavailable`, `verified`, `mismatched`; lowest verified height selected; header bytes 36 to 67 compared as they are (reading 2's A09) |
| 9 | CONFIRMATIONS-ON: the consecutive heights from H held in the set (B08); `k < 6` or NULL returns unverifiable |
| 10, 11 | `block_height_H`, `block_time_RWCP` from nTime. Median Time Past is not attempted (OPTIONAL; the eleven headers before H are not held). Returns valid |

**The header sets.** This run holds no validated chain. Every header set used as `validated_chain` is a test fixture drawn from Lemonnier's file, declared validated for the test, and not validated by this run.

| Fixture | Heights | Used in |
|---|---|---|
| fixture-12 | 957289–957300 | P2, A3, N1, N1o, A7 |
| fixture-11 | 957290–957300 | N2b, and A1 under the other reading of B07 |
| fixture-6 | 957289–957294 | A6 |
| fixture-5 | 957289–957293 | A5 |
| fixture-0 | empty | A4 |

`out/final/fixtures.json` records each set's internal checks (80 bytes, linkage, proof of work against its own bits, as reading 2 reported them) as a description of the fixture, not as validation.

**The bundles.**
- `claimed_hash` is `sha256:` followed by D.1's hash of the artifact. A2 and A3 use it without the prefix.
- `origin_id` and `bitcoin_block_height` are omitted (B02).
- Each bundle's CBOR digest is in `out/final/bundles.json`; vector 1's is 1977 bytes, SHA-256 `9902ed50…f2cc`.

**Deciding step.** Each run records `return_step`, the step whose RETURN produced the verdict, and `decided_by_step`. The two differ only for an unverifiable RETURN at step 8: `decided_by_step` then names the step that left the branch unevaluated (7b in every such run here), as D.6 states it (B06).

## Results

142,192 runs of VERIFY-ANCHOR. Every run returned a verdict; none is `not attempted`. Per-run results are in `out/final/`; one verdict per run, with totals, is in `out/report.json`.

### The positives, and D.6's second vector

| Run | validated_chain | vector1 | vector2 | vector3 | vector4 | Expected |
|---|---|---|---|---|---|---|
| P1 | none | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b |
| P2 | fixture-12 ¹ | valid, 11 | valid, 11 | valid, 11 | valid, 11 | valid (D.3) |
| N2 (D.6, second vector) | none | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b |
| N2b (D.6, second vector) | fixture-11 ¹ (957290–957300, lacks 957289) | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b | unverifiable, 7b, if D.6's words cover this set (B07) |

¹ The header set was declared validated for the test and was not validated by this run.

In P2, every vector replays to `81383c9c…43ef` over 82 operations. The candidate at 957289 is placed by the fixture (the bytes come from the same file, B10), and the branch is verified. k = 12, so step 9 passes, and step 10 gives `block_height_H` 957289 and `block_time_RWCP` 2026-07-09T10:02:59Z.

P1 and N2 are the same inputs, run as separate runs for the two task items. Each returns at step 8 with the single Bitcoin branch `unavailable` because step 7b returned NULL.

**The set 957290–957300.**
- D.6's words "a validated header set that does not reach the attested height" do not describe this set literally: the set extends past 957289 and starts above it.
- Under this run's reading of VALIDATE-HEADER-ON-CHAIN (a view establishes the header at H by holding it, B07(a)), step 7b returns NULL and the verdict is unverifiable for all four.
- Under the other reading (957290's previous-block hash establishes the header at 957289, B07(b)), the verdict is valid for all four (A1 below). Finding G01.

### D.6, first vector: every single-byte substitution

Original proof and original bundle; fixture-12 as `validated_chain`, declared validated for the test and not validated by this run (B04).

| Artifact | Runs (46 positions × 255 values) | invalid at step 2 | Exceptions |
|---|---|---|---|
| vector1 | 11,730 | 11,730 | none |
| vector2 | 11,730 | 11,730 | none |
| vector3 | 11,730 | 11,730 | none |
| vector4 | 11,730 | 11,730 | none |
| Total | 46,920 | 46,920 | none |

Rows (position, original byte, substituted byte, verdict, step) are in `out/final/d6_substitution.json` and `out/report.json`.

**Optional, reported apart from D.6.** Same proof, bundle and fixture as above.

| Artifact | One byte inserted: runs (47 positions × 256 values; 11,986 distinct byte strings) | invalid at step 2 | One byte deleted: runs (46 positions; 44 distinct byte strings) | invalid at step 2 |
|---|---|---|---|---|
| vector1 | 12,032 | 12,032 | 46 | 46 |
| vector2 | 12,032 | 12,032 | 46 | 46 |
| vector3 | 12,032 | 12,032 | 46 | 46 |
| vector4 | 12,032 | 12,032 | 46 | 46 |

Inserting at adjacent positions a byte equal to its neighbour, or deleting either of two equal adjacent bytes, gives the same byte string. Each such run was run and is counted as a run.

### Additional runs, reported apart

These are not in the prompt's task list. Each tests a value the text does not fix, or a condition the vectors do not reach.

| Group | What differs | Result per vector (v1, v2, v3, v4) | Bears on |
|---|---|---|---|
| A1 | fixture-11 under reading B07(b) ¹ | valid, 11 (all four) | G01 |
| A2 | `claimed_hash` without `sha256:`, no view | unverifiable, 7b (all four) | B02 |
| A3 | `claimed_hash` without `sha256:`, fixture-12 ¹ | valid, 11 (all four) | B02 |
| A4 | an empty header set as the view ¹ | unverifiable, 7b (all four) | B09 |
| A5 | fixture-5 (957289–957293) ¹: k = 5 | unverifiable, 9 (all four) | B08, G03 |
| A6 | fixture-6 (957289–957294) ¹: k = 6 | valid, 11 (all four) | B08 |
| A7 | every single-byte substitution, with `claimed_hash` computed from the presented bytes; fixture-12 ¹ | 46,920 runs: invalid at step 3 (`parsed.msg != computed_hash`) in all 46,920 | B03, G02 |

¹ The header set was declared validated for the test and was not validated by this run.

### First run against final

Every verdict and every deciding step is the same in `first-run/` and `final/`. The one change (C01) concerns how A7's exceptions to D.6's step are stored.

## What these results show, and what they do not

**What they show.**
- With the parser and replay of reading 2 unchanged, a VERIFY-ANCHOR written from §4.1 returns, for the four pairs:
  - unverifiable at step 7b with no view;
  - valid with the twelve headers declared validated for the test.
- It returns invalid at step 2 for every single-byte substitution of every artifact (46,920 runs) with the original bundle.
- It returns unverifiable at step 7b for every unmodified pair with no view and with the set 957290–957300.

**What they do not show.**
- That block 957289 is on the Bitcoin most-work chain. This run validated no header chain. Every valid result here rests on a header set declared validated for the test, whose bytes came with the proofs.
- That step 7b distinguishes headers from different sources: in every run where it returned a header, candidate and fixture came from the same file (B10).
- Behaviour on paths no run reaches:
  - step 4's unverifiable (no Bitcoin attestation);
  - step 5's unsupported branch;
  - step 8's invalid (a mismatched branch);
  - proofs with more than one Bitcoin branch;
  - B05 and B11.

  Every proof here has one Bitcoin branch and four pending attestations.
- That D.6's first vector holds for changes other than one byte substituted, inserted or deleted.
- That the text alone was enough: the proof grammar still comes from outside it (reading 2's A01, F03).

## Not checked

- Median Time Past (step 10, OPTIONAL): not attempted in every valid run; the eleven headers before 957289 are not held.
- The header bytes against a block explorer or a node: not attempted (no network to either).
- The RFCs the draft cites: none fetched. RFC 8610 and 8949 were applied from knowledge.
- Draft -03: not read.
- A bundle encoded otherwise than as CBOR, and bundles carrying `origin_id` or `bitcoin_block_height`: not run.
- D.6's first vector with no view: not run (B04). Step 2 returns before the view is read.

## Ambiguities and findings

`ambiguity-log.md` lists eleven places (B01 to B11) not in reading 2's log, with the reading chosen and the runs that test it. Reading 2's A01, A09 and A27 are read as reading 2 read them.

`findings/` holds three drafts, none filed or sent:

| Finding | Divergence | Minimised to | Fault seems to be in |
|---|---|---|---|
| G01 | D.6's second vector: for the set 957290–957300, two readings of "establishes" give unverifiable and valid; §3.4 requires one output per view | vector 1, fixture-11 ¹ | text (D.6's wording; VALIDATE-HEADER-ON-CHAIN) |
| G02 | D.6's first vector: "step 2" holds only with the original `claimed_hash`; computed from the presented bytes, step 3 decides | vector 1, byte 0 from 0x64 to 0x00 | text (D.6 does not state the bundle) |
| G03 | D.3's expected result omits step 9: block 957289 placed, five blocks held, unverifiable | vector 1, fixture-5 ¹ | text (D.3's summary sentence) |

¹ The header set was declared validated for the test and was not validated by this run.

## How to rerun

From reading 2's record and the draft, in an empty directory:

```
unzip dps-reading-2.zip                       # reading 2's record, unchanged
sh dps-reading-2/inputs/dps-reading-2-fetch-inputs.sh inputs
mkdir -p inputs/ietf && cp draft-fassbender-scitt-time-anchor-08.txt inputs/ietf/   # if www.ietf.org is not reachable
pip install -r dps-reading-2b/verifier/requirements.txt
export PYTHONDONTWRITEBYTECODE=1              # keeps __pycache__ out of reading 2's record
python dps-reading-2/verifier/ots_replay.py inputs /tmp/ots-replay.json && cmp /tmp/ots-replay.json dps-reading-2/out/ots-replay.json
python dps-reading-2b/verifier/run_2b.py dps-reading-2 inputs dps-reading-2b/out/final
python dps-reading-2b/verifier/make_report.py dps-reading-2b/out
```

`run_2b.py` takes reading 2's directory, the inputs directory and an output directory. `make_report.py` reads `out/final/` and `out/pins.json`. Laid out under `docs/interop/`, the first argument is `docs/interop/dps-reading-2`. Every file but `timing.json` should reproduce byte for byte; the whole run takes about 10 seconds.

## Files

- `verifier/`: only the new code.
  - `verify_anchor.py`: VERIFY-ANCHOR and the Proof Bundle.
  - `chain.py`: the header source, the fixtures, VALIDATE-HEADER-ON-CHAIN and CONFIRMATIONS-ON.
  - `run_2b.py`: the harness.
  - `make_report.py`
  - `requirements.txt`
- `out/pins.json`: digests, and the replay reproduction.
- `out/first-run/`: every group as first run.
- `out/final/`: the results reported here.
  - `runs_small.json`: the 40 small runs, with full traces.
  - `d6_substitution.json`
  - `d6_insert_delete.json`
  - `a7_substitution_claimed_from_presented.json`
  - `fixtures.json`
  - `bundles.json`
  - `inputs_check.json`: the `.txt` files equal D.1's strings and hashes; the `.ots` files equal D.5's Base64; every Appendix D constant reading 2 copies is found in the draft.
  - `timing.json`
- `out/changes.md`
- `out/report.json`: one verdict per run, with totals; about 3.8 MB.
- `ambiguity-log.md`
- `findings/`

## Wall-clock time

- First session: 13:19:40Z (digest check) to about 13:30Z.
  - Reading and code until 13:26Z.
  - First run 13:26:12Z to 13:26:22Z; final run 13:26:53Z to 13:27:02Z.
  - Report, change record, ambiguity log and findings followed.
- Second session: 14:04:55Z to about 14:07Z. This README, the rerun from a clean copy (14:05Z) and packaging.
- About 13 minutes of work over about 47 minutes elapsed. Nothing was run between sessions.
- The runs themselves take about 10 seconds; 8.3 of them are A7.

**Packaging, 5 November 2026.** Every file of `out/` larger than 1 MB is stored gzip-compressed (`gzip -9`, no name or time in the header) as `<name>.json.gz`, so that the record stays small in the repository and in the package's source distribution. `out/UNCOMPRESSED-SHA256SUMS` holds the SHA-256 of each file uncompressed; a rerun reproduces those files, and `gunzip -c <file>.json.gz | sha256sum` gives the same digest. Nothing else in the record was changed.
