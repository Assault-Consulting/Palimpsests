# Independent verification: the PALA-1 SCITT-bridge Signed Statement

**Result: verified and reproduced byte-for-byte.** 61/61 checks pass.
Four findings, none of which contradict the published bytes.

| | |
|---|---|
| Vector under test | `docs/interop/scitt-statement-vector.json` (v2) |
| Vector sha256 | `e51575d0e8959694d6e3567a97432fba1f4403d7cff1331f720bb8dcd1570ec7` |
| Vector commit | `d84be55a4e1bc72b681eecfce54d181b7ba05393` |
| Task doc sha256 | `91e3ae8aba84ea4414a3e8f612ec5d55a19860bfb4f3eb8bb3af5d47eff76191` |
| Repo HEAD at run time | `4b07237f0ec256976ff622e1259962d2d7e15580` |
| Date | 2026-08-30 |
| Language / runtime | Python 3.12.10, standard library only |
| Wall clock | ~12 min end to end (21:29–21:41); the verifier itself runs in 0.08 s |

## Contamination boundary — what was and was not read

Read: RFC 9052, RFC 9597, RFC 9679, RFC 8032, RFC 8949, RFC 8392 (for CWT
claim keys), the task file, the vector file, and — for provenance only —
`docs/specs/pala-1/test-vectors.json`.

Not read: `src/palimpsests/**`, `tests/**`, `benchmarks/**`, and the
previous bridge run at
`docs/specs/pala-1/independent-runs/turak/scitt-statement/`. Everything
known here about run B1's findings F1–F4 and cases A1/A8/A10 comes from
the task file and the vector's own prose, which describe them.

Three disclosures, in the interest of the record.

**1 — B1's filenames were visible; its contents were not.** A `git merge`
transcript exposed B1's *filenames* (`verifier/cbor.py`,
`verifier/ed25519.py`, `verifier/scitt_verify.py`). This run
independently chose the same three names — they are the obvious ones —
and none of those files' contents were opened while the verifier was
written or the findings fixed. The code here was written from the RFCs.

**2 — `INDEPENDENT-VERIFICATION.md` was read after the report was
final.** This document, which narrates B1's F1–F4 in detail, was opened
only *after* `RUN-RECORD.md` and `ambiguity-log.md` were written and
delivered — to determine where a B2 row belongs and in what format. No
finding, measurement or ambiguity entry was added, removed or reworded
afterwards. Same for B1's `README.md`, read at submission time for the
house layout of this file.

**3 — the boundary here was held by restraint, not by construction.**
§6.2 gives an external implementer a *sealed package* precisely so the
boundary does not depend on their discipline. This run had the live
repository checked out: `src/palimpsests/**` and `tests/**` were a
`cat` away throughout and were not read, but that is an assertion about
conduct, not a property of the setup. It is the material difference
between this run and a §6 external one, and it is why the row in §7
records this as a maintainer run.

## Affiliation

**Maintainer run — not an unaffiliated external run**, on the same
footing as B1 and for the same reason: the implementer is a maintainer,
and is additionally the B1 implementer, which disqualifies them from an
external label on this surface under §6.1 and §6.3 (a fresh run that has
seen an earlier verifier tests that file, not the specification).

Method disclosure, as for run #4 and B1: produced with an AI coding agent
(Claude) under the implementer's direction and review. The repository
postdates the agent's training cutoff, so training-data contamination for
this repository is not possible.

What *is* independent here, and is the claim this run makes: the verifier
was written from RFC 9052, RFC 9597, RFC 9679, RFC 8032, RFC 8949 and
RFC 8392 without reading the bridge implementation, and it reproduces the
published statement byte-for-byte. That is an implementation-independence
claim, not a personnel-independence one. An unaffiliated confirmation of
F-2 in particular would still be worth having.

## Toolchain

No COSE library, no CBOR library, no crypto library.

- `verifier/cbor.py` — RFC 8949 decoder and deterministic encoder. The
  decoder is strict by default: it rejects non-minimal length heads,
  indefinite-length items, and trailing data, and it preserves map order
  plus the raw encoded key bytes so §4.2.1 ordering can be *checked*
  rather than assumed.
- `verifier/ed25519.py` — RFC 8032 Ed25519, extended-coordinate point
  arithmetic. Anchored on RFC 8032 §7.1 TEST 1 and TEST 2 (key
  derivation, signature bytes, verification, and negative case) before it
  is trusted with anything else.
- `verifier/scitt_verify.py` — the run.

## What was done, in order

1. **Self-test.** `ed25519.py` against RFC 8032 §7.1. Then: the vector's
   `public_key_hex` is re-derived from `private_seed_hex`. It matches,
   and matches TEST 1 — the key really is the published one.
2. **Parse** the statement as a tagged COSE_Sign1 under the strict
   decoder. First byte `0xd2`; 4-element array; protected 205 B, empty
   unprotected map, attached 53 B payload, 64 B signature. No
   non-minimal heads anywhere in the message.
3. **Verify.** Sig_structure assembled independently as
   `["Signature1", protected, h'', payload]` — 275 bytes. Ed25519
   verifies against `public_key_hex`.
4. **Payload.** Decodes to `{1: <32-byte head>, 2: 0, 3: 11,
   4: "pala-1/v1.0"}`. The head equals `chain_head_hex`; the map
   re-encodes to identical bytes.
5. **Protected header.** alg `-8`; content type, kid, and CWT claims all
   in the protected bucket; labels `[1, 3, 4, 15]`; CWT `iss`/`sub`
   match, and `sub` carries the full 64-hex head (F4 confirmed fixed).
   `kid` recomputed from scratch as an RFC 9679 COSE Key Thumbprint —
   matches (see A3 below for the ordering that makes it match).
6. **Reproduce.** Protected header, payload, signature, and the full
   tagged message all rebuilt from `statement_inputs` and compared:
   **byte-for-byte identical to `expected.statement_hex`**, 331 bytes,
   sha256 `ce47efa9…f941`. Repeated three times, identical each time.
7. **Tamper.** All five `tamper_expectations` behave as claimed.
8. **Adversarial.** Eleven cases of our own; all behaved as a careful
   verifier should. Details in the log.

**Provenance cross-check.** `docs/specs/pala-1/test-vectors.json` has 12
records, seq 0–11, `chain_head` equal to the statement's committed head.
The statement's `[first_seq, last_seq] = [0, 11]` covers exactly that
chain. The subject chain is what the vector says it is.

## Findings

None of these contradict the published bytes. F-1 and F-2 are worth a
vector edit; F-3 and F-4 are precision.

### F-1 — moving `kid` to the unprotected bucket is **length-neutral** here, so `statement_length_bytes` does not detect it

`byte_stability.2` says, of that move: *"measured: moving kid to
unprotected grew a test statement and left verification green."* For
**this** statement it does not grow it. Measured:

| | protected bstr | unprotected | total |
|---|---|---|---|
| published | 205 B (head `58cd`) | `a0`, 1 B | **331 B** |
| kid moved | 170 B (head `58aa`) | 36 B | **331 B** |

−35 in the protected bucket, +35 in the unprotected one, and the bstr
length head stays two bytes wide (`58cd` → `58aa`). Same length,
different bytes: sha256 `947f73a3…566a` vs `ce47efa9…f941`.

The prose is presumably true of the other test statement it was measured
on, but as written a reader can reasonably infer that a length check
catches bucket moves. It does not — only the sha256 or a full byte
comparison does. Suggest saying so explicitly, since
`statement_length_bytes` is published right next to `statement_sha256`
and looks like a peer check.

### F-2 — the tamper expectations miss Ed25519 signature malleability (S+L)

*"flip any bit of the signature: verification MUST fail"* is true, and
this run confirms it. But bit-flips are not the only way to produce a
different 64-byte signature that a verifier may accept. Replacing the
scalar `S` with `S + L` (L = the group order) yields:

```
cb2ef1d5ef03b37e377359b5bba5ebfeb07bb5808ea4edb3bb13ad8c04d5a713
```

a *second, distinct* 64-byte signature over the identical Sig_structure.
It is **rejected** by a verifier that enforces RFC 8032 §5.1.7's
`0 <= S < L` range check, and **accepted** by one that omits it. Both
behaviours exist in the wild; the check is the only thing standing
between the two.

This is a signature-*uniqueness* failure, not a forgery — no new content
is signed. It matters for the bridge specifically because a transparency
service that deduplicates, indexes, or counts registrations by signature
bytes can be made to see two registrations of one statement. Suggest a
sixth tamper expectation: *"replace S with S+L: a verifier conforming to
RFC 8032 §5.1.7 MUST reject; one omitting the range check will accept."*

### F-3 — the detached-payload case belongs with the other artifact-identity splits

`byte_stability` enumerates four ways bytes can honestly differ, and
`expected.note` correctly separates artifact identity from signature
validity. There is a fifth instance of exactly that split, not listed:
replacing the attached payload with `nil` (`0xf6`) and supplying the
payload out of band. The Sig_structure is unchanged, so **the published
signature still verifies** — over a 277-byte artifact that is not the
published statement. Same lesson as modes 2 and 3, and cheap to add.

### F-4 — `kid_note` should pin the hash and the encoding, not just cite RFC 9679

`kid_note` says label 4 is the *"RFC 9679 COSE Key Thumbprint (SHA-256)
of the verification key"*. That resolved correctly here, but RFC 9679
leaves an implementer two decisions the note does not make: (a) the
thumbprint is carried as the **raw digest**, with no multihash or
algorithm-identifier prefix, and (b) the required-member map is ordered
by RFC 8949 §4.2.1 **bytewise-on-encoded-key**, which for OKP means
`{1, -1, -2}` and *not* numeric `{-2, -1, 1}` (see A3). An implementer
who guesses the other ordering gets a 32-byte value that simply does not
match, with no diagnostic pointing at ordering. One sentence in the note
would save that.

## Verdict

Every expectation in the vector file is reproduced. The statement parses,
verifies, commits to the published chain head over the correct sequence
range, carries all four parameters in the protected bucket in
deterministic order, and rebuilds byte-for-byte from public standards
alone. B1's F1, F2 and F4 are confirmed fixed in v2; F3's rescoping is
confirmed correct, and this run reproduces the F3/A1 mechanism directly
(re-encoding the protected bstr's length head keeps the signature valid
while changing bytes, sha256 and length — and a strict RFC 8949 §4.2.1
decoder rejects it).

The four findings above are refinements to the vector's prose and tamper
list, not defects in the bytes.
