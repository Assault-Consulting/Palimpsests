# DPS reading 2: the anchoring checkpoint and an OpenTimestamps replay, from the text

An outside reading of the anchoring extension (0.2.0, Proposal) of the Decision Provenance Standard, and a replay of four OpenTimestamps proofs without OpenTimestamps software, from the text of draft-fassbender-scitt-time-anchor. Requested by Laurent Lemonnier. The question under test: is the text alone enough?

This reading was carried out by an AI assistant under the direction of Andrii Sparysh.

## What was read (pinned)

| Input | Pin | How read |
|---|---|---|
| decision-provenance-standard/standard | `007f8c99ec910564bac1c508b76c8ce8391fa11e` | 14 files fetched by `inputs/dps-reading-2-fetch-inputs.sh`, SHA-256 checked (`inputs/SHA256SUMS`) |
| Laurent-Lemonnier/dps-scitt-decision-layer | `549b50afb146c172d92177063b4e3d3d3e17beab` | 10 files fetched by the same script, SHA-256 checked |
| draft-fassbender-scitt-time-anchor-08 | SHA-256 `687000b938fcea6b15871f9ea20dc4694f89b7a78f719bacc72ef0ecf1da3394` | The script could not reach www.ietf.org from the sandbox; the file was uploaded by Andrii Sparysh and its digest recorded |
| draft-fassbender-scitt-time-anchor-03 | none (no digest) | Read with the web fetch tool from its datatracker page (`https://datatracker.ietf.org/doc/draft-fassbender-scitt-time-anchor/03/`), as HTML; the fetched text ran to its section 4.4. Used only to compare with -08 on the proof format (§1.4, §1.5, §2.4.1, §2.4.2, §3.1) |
| RFCs the anchoring text cites | none fetched | www.rfc-editor.org was not reachable from the sandbox. Applied from knowledge: RFC 3161 and 5816 (TSTInfo, accuracy, ESSCertIDv2), 5652 (signed attributes as a SET OF), 5280 and 8017 (key encodings), 8032 (Ed25519), 8259 (integers), 9052 (COSE_Sign1, Sig_structure), 9162 (leaf and node hashes, inclusion proof), 9597 (CWT claims label 15), 9864 (alg -19 and -8), 9942 and 9943 (receipts, labels 395 and 396). Not used: 6979, 8392, 8785, 9500 (the RSA key's equality with RFC 9500's text is reported not attempted) |
| Bitcoin block header format | none | Applied from knowledge: 80 bytes, little-endian fields, double SHA-256 shown reversed, target from compact `bits` |
| OpenTimestamps serialisation | none | Not stated in either draft revision (ambiguity log A01, findings F03 and F04). Applied from knowledge; no implementation read |

Uploaded with the request: `dps-reading-2-PROMPT.md` (SHA-256 `a681965d…858d`) and the fetch script (SHA-256 `35fa1d2d…9481`, copied unchanged to `inputs/`).

## How the run was carried out

- The fetch script was run; both SHA-256 checks passed.
- Read, in this order: `extensions/README.md`; `anchoring/README.md`; `portable-verification/README.md` (export, covered bytes, chain rule); the four anchoring schemas; the portable verification export schema; `tests/cases.json`; `tests/vectors.json`; then draft -08, and -03 where -08 does not state the proof format (it does not either). The signatures README was not opened: the anchoring parts this check implements did not need it.
- The check (`verifier/dpsr/`) was written from those texts, then the suites were run once (`out/first-run/`), then changed as recorded in `out/changes.md`.
- Lemonnier's files were read last, as data: the `.ots` proofs, their `.txt` artifacts, and the two headers files.

**Events at the boundary.**
- None. No `.py` file of either repository, no README of Lemonnier's repository, no Internet-Draft of his and no `interop/SPARYSH-READINGS-2026-11.md` was opened.
- No OpenTimestamps or Bitcoin library was installed or read. No issue, pull request or commit history was opened, and no earlier reading.
- Rule 1: before reading the two JSON files of the second input, their top-level keys were listed: block heights (`957289` to `957300`), and explorer names (`blockstream`, `mempool`). Both are data, so they were read.
- Rule 2: no file read turned out to hold someone's reading or code.
- Rule 3: no block explorer was consulted (the sandbox reaches only package hosts), so no header was cross-checked against one.

**Tools.** Python 3.12.3, with `cryptography` 50.0.2, `asn1crypto` 1.5.1, `cbor2` 6.1.5 (only to cross-check the strict CBOR reader in V19), `jsonschema` 4.26.0 and `referencing` 0.37.0. No other package.

## Results: the anchoring checkpoint

Each case of `tests/cases.json` was run against its expected outcome. Per-case results are in `out/final/*.json`, and one boolean or `not attempted` per check is in `out/report.json`.

| Suite | Cases | Agree | Do not agree | Not attempted |
|---|---|---|---|---|
| Schema cases | 163 | 163 | 0 | 0 |
| Vector cases | 25 | 24 | 0 | 1 (V13) |
| Timestamp cases | 99 | 99 | 0 | 0 |
| Checkpoint cases | 141 | 141 | 0 | 0 |
| Pairing cases | 54 | 51 | 3 (J45, J46, J47) | 0 |

**Not agreeing.**
- J45 expects consistent; this reader finds inconsistent at `/checkpoints/3/signature/key_ref`.
- J46 and J47 expect inconsistent and get it, but at the same member, not at the receipt they describe. They are counted as not agreeing (change C09).
- All three follow from one vector value: `beside_results/st_a` names `witness-a-1` for a statement signed by `witness-a-scitt-1`. See finding F01 and `out/counterfactual-J45-J47.json`.

**Not attempted, or partly.**
- V13 (vectors.json reproduced byte for byte) needs `generate_vectors.py`, which the boundary forbids.
- V06 and V16 compare the RSA test key with the values the vectors and the case state, not with RFC 9500's text, which was not fetched. In `out/report.json` they carry separate `not attempted` entries (`V06b`, `V16b`).

**First run against final.**

| Suite | First run: agree / do not | Final |
|---|---|---|
| Schema | 163 / 0 | 163 / 0 |
| Vector | 23 / 1, plus V13 not attempted | 24 / 0, plus V13 not attempted |
| Timestamp | 39 / 60 | 99 / 0 |
| Checkpoint | 126 / 15 | 141 / 0 |
| Pairing | 47 / 7 | 51 / 3 |

The changes are in `out/changes.md`:
- C01, a fault in this reading's check, accounts for 60 timestamp, 8 checkpoint and 6 pairing cases.
- C02 is a choice where the text is silent (ambiguity log A16).
- C03 to C08 and C10 are faults in the harness.
- C09 is the review of J46 and J47.

**What the harness compares.**
- Timestamp and checkpoint cases: every check and dimension the case names, with the cases' stated defaults ("expected verified unless expected says otherwise"). For a result the schema fixes, the default is that value (A26).
- Where a case expects a finding, the harness looks for the case's phrase in this reading's findings. This reading worded its findings to carry those phrases. Those parts therefore show that a reason of that kind is given, not that independent wording matches: T82, T83, T94, T96, T97, K96, K133, K137, K139, K141, and V25's reasons.
- Pairing cases: the reader recomputes the report from the documents and compares every member but `findings`, type-strictly (A21).

**What these results show, and what they do not.**
- They show that a check written from the anchoring text reproduces the expected verdict of every case except the three above. Where the text was silent, the check takes the choices in the ambiguity log, several of which the cases fix.
- They do not show that the reference check gives the same reasons.
- They do not show behaviour on inputs no case covers. Ten choices in the ambiguity log are marked untested (A03 to A06, A12, A13, A15, A23 to A25), and an eleventh (A02) is tested only above its limit.
- They do not show that the extension's OpenTimestamps branch can be implemented from its text: the proof grammar came from outside the text (F04).

## Results: the OpenTimestamps replay

Each `.ots` proof under `interop/umarise/vectors/` was parsed with this reading's strict reader. The parser's byte grammar is not in the draft (A01). Each proof was then replayed from the SHA-256 of its `.txt` and held against the headers file.

Each step is reported separately, per proof (`out/ots-replay.json`; booleans in `out/report.json`).

| Step (draft -08, §4.1 unless stated) | vector1 | vector2 | vector3 | vector4 |
|---|---|---|---|---|
| File is 1877 bytes (D.4); its SHA-256 is the one D.5 prints; its bytes equal D.5's Base64 | yes | yes | yes | yes |
| Step 1: SHA-256 of the `.txt` (46 bytes, no newline) equals D.1's hash | yes | yes | yes | yes |
| Step 2: claimed hash | no Proof Bundle is supplied with the files; the D.1 comparison above is the only one made | | | |
| Step 3: parsed strictly, nothing left over; file hash op SHA-256; message equals the artifact's SHA-256 | yes | yes | yes | yes |
| Step 4: a Bitcoin attestation present (one; four pending ones: bob, alice, catallaxy, finney) | yes | yes | yes | yes |
| Step 5: Bitcoin branch has only append, prepend, SHA-256; 82 operations (D.4) | yes | yes | yes | yes |
| Replay passes D.1's nonce and leaf, D.2's node and root, an 89-byte prepend ending `6a20` (op 40), append `689b0e00` (op 41), `3cad384e…` after op 43 and `81383c9c…` after op 82 (D.4, in internal byte order, A09) | yes | yes | yes | yes |
| Step 6: attested height 957289 (D.3) | yes | yes | yes | yes |
| Step 7a: an 80-byte candidate header at 957289, from Lemonnier's headers file | yes | yes | yes | yes |
| Step 7b: that header placed on a validated chain | not attempted: no validated chain is held (A27) | | | |
| Step 8 comparison: replayed digest equals header bytes 36 to 67, `81383c9c…43ef` (D.3 "as committed"; D.3's "as displayed" is its reverse) | yes | yes | yes | yes |
| Header double SHA-256 equals D.3's block hash `…890e3534`, and the hash both entries of `headers-sources.json` give; header bytes equal both entries | yes | yes | yes | yes |
| Proof of work: header hash ≤ target from `bits` `17021a42` | yes | yes | yes | yes |
| nTime 2026-07-09T10:02:59Z equals D.3's projection | yes | yes | yes | yes |
| Step 9: confirmations on a validated chain | not attempted (A27). Twelve headers 957289 to 957300 are supplied | | | |
| Median Time Past | not attempted: the eleven preceding headers are not supplied | | | |
| Header cross-checked with a block explorer | not attempted (sandbox network) | | | |

**Linkage from the starting header.** For each of the twelve headers 957289 to 957300 in the headers file:
- it is 80 bytes;
- its proof of work holds against its own `bits` (all `17021a42`);
- each from 957290 on names the double SHA-256 of the one before as its previous hash.

**What this shows, and what it does not.**
- The four proofs replay to the Merkle root of the header supplied for block 957289. That header carries valid proof of work and heads a linked run of twelve such headers.
- If that header is the main chain's, each artifact's bytes existed before block 957289 was mined.
- It does not show that the header is the main chain's. This reader validated nothing before 957289, and both explorer copies come in Lemonnier's file. Under -08's §4.1, VERIFY-ANCHOR therefore returns unverifiable for all four proofs (step 7b). Steps 1 to 8's comparison hold as listed.
- It shows nothing about time beyond that: nTime is the miner's statement. It also shows nothing about who committed the bytes or what they mean.

**Is the text alone enough?**
- Not for parsing. Neither -08 nor -03 states the byte grammar of a proof (F03), and anchoring 0.2.0 names none (F04).
- With that grammar taken from outside, everything else the replay needed was in -08: the operations, the tags, the header comparison in internal byte order, and the validated-chain condition. Every value -08's Appendix D prints that this reading checked was reproduced.

## Ambiguities and findings

`ambiguity-log.md` lists 27 places where the text admits more than one reading or is silent, with the choice made and whether a case fixes it.

`findings/` holds four drafts, none filed:

| Finding | For | First differing field | Fault |
|---|---|---|---|
| F01 | Standard | `vectors.json /beside_results/st_a/signature/key_ref`: `witness-a-1`, where the statement is signed by `witness-a-scitt-1` | vector (and the descriptions of K85, K127, K128) |
| F02 | Standard | V19's count of statements cbor2 "reads": `cbor2.loads` returns for `st_a_trailing` with one byte unread | case description |
| F03 | Lemonnier | byte 0 of each `.ots`: the magic, which -08 does not give; the draft leaves the proof format unspecified | scope of the draft, not the files |
| F04 | Standard | anchoring README, "An OpenTimestamps proof as a timestamp": no specification or pinned release named for the serialisation it reads strictly | text |

## How to rerun

```
sh inputs/dps-reading-2-fetch-inputs.sh inputs     # needs www.ietf.org for the draft, or place it in inputs/ietf/
pip install -r verifier/requirements.txt
python verifier/run_suites.py inputs out/final
python verifier/ots_replay.py inputs out/ots-replay.json
python verifier/counterfactual_j45.py inputs out/counterfactual-J45-J47.json
python verifier/make_report.py out
```

The suites read `inputs/standard/`; the replay reads `inputs/lemonnier/` and `inputs/ietf/draft-fassbender-scitt-time-anchor-08.txt`. `run_suites.py` applies `verifier/review.json` (change C09) after a run.

## Wall-clock time

- Started 2026-11-05 11:04:39Z (fetch).
- First session ended about 11:15Z, with the reading done and four modules written.
- Second session: 12:21Z to about 12:40Z. Suites first run at 12:27:12Z; changes, replay, log, findings and README followed.
- Third session: 13:05Z to about 13:08Z. One count in this README corrected (Ten choices untested, where a draft said seventeen), a rerun from a clean copy of `verifier/` that reproduced every output file byte for byte, and packaging.
- About 35 minutes of work over about 2 h 05 min elapsed. Nothing was run between sessions.
