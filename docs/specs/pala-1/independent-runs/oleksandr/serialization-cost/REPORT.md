# Independent measurement — serialization / integrity cost (PALA-1)

**Independent measurer.** The harness was built from public standards
(FIPS 180-4 SHA-256, RFC 9052 COSE_Sign1, RFC 8032 Ed25519, FIPS 186-5 ECDSA
P-256, RFC 8949 CBOR, RFC 8785 JCS) and the published PALA-1 header layout
(§2.1) + `test-vectors.json` alone. Contamination boundary held: `benchmarks/**`
(incl. `bench_cose_compare.py`), `src/palimpsests/**`, `tests/**`, and the
benchmark's PRs/issues/commits were **not** opened. Isolation: a separate
directory with only three allowed files copied in by exact `cp`.

- **Vectors commit:** `604fb114f4015f129fe61c0d21f07f711e203959` (last commit
  touching `docs/specs/pala-1/test-vectors.json`; repo HEAD at run: `4e52c4d`).
- **Allowed inputs used:** `PALA-1.md` (§2.1 header layout), `test-vectors.json`
  (the 12 real record headers), `BENCHMARKING.md` (method standard).

## Framing (kept deliberately, not "PALA-1 cheaper than SCITT")

This does **not** claim "PALA-1 is cheaper than SCITT." SCITT/COSE_Sign1 signs a
**self-sufficient statement**: one signed record proves itself, standalone. A
PALA-1 record proves **only in sequence** — its integrity is the `prev_hash`
chain link, and a single record out of its chain proves nothing. What is
measured here is the price of a *hypothetical per-record signature*
(COSE_Sign1) against *chain hashing* (one SHA-256 per record). Where chain
hashing is cheaper, that saving is **bought by** the weaker per-record property.
The report states this trade-off rather than hiding it behind a ratio.

## Step 0 — Hardware (the most important thing here)

| | |
|---|---|
| CPU | Intel Core Ultra 9 185H (Meteor Lake), 16 physical / 22 logical cores, x86-64 |
| Clock | base 2.50 GHz; **current 2.30 GHz at run** (below base) |
| Frequency scaling | **Balanced** power plan — clock **not pinned**; scaling/throttling active. A source of run-to-run variance, captured in the spread. Not tuned to a fixed clock, on purpose (honesty rule). |
| RAM | 31.5 GiB |
| OS | Windows 11 Pro build 26200 (10.0.26200) |
| Power | **AC / on mains** (battery status = 2) |
| Hygiene | no explicit sleep in the harness; no foreground load during the run |

> **Workstation run — upper bound.** This is a workstation, **not** constraint
> class. The absolute times are a comfortable ceiling; **constraint-class
> hardware (an SBC) is where the claim bites** — the per-record signing cost
> below scales up there while the chain hash stays cheap. If an SBC is provided,
> a separate run there is owed.

## Method (per `BENCHMARKING.md`)

- **Input:** the **real 156-byte fixed header** of each of the 12 test-vector
  records (`header_hex[:156]`, the §2.1 fixed header; records with TLVs were
  truncated to their fixed-header prefix), cycled to N. No synthetic headers.
- **N:** `N_HASH = 200_000` (SHA-256 is sub-µs → large N so per-call Python
  overhead is negligible); `N_SIG = 20_000` (sign/verify are tens of µs → smaller
  N, still ≫ per-call overhead). Same byte input to both sides; no bodies.
- **Repeats:** 6 timed passes per measurement, **first discarded as warm-up**, 5
  kept. **Headline statistic = minimum** (the least-perturbed estimator of a
  deterministic op — noise only ever *adds* time); median (the `BENCHMARKING.md`
  convention) and spread (max, stdev) are reported alongside. See ambiguity log.
- **Raw data:** every repeat is in `raw/repeats.csv`, `raw/results.json`,
  `raw/native_primitives.json`.

### Pinned versions (`pip freeze`, relevant)

```
cryptography==50.0.1
pycose==1.1.0
cbor2==5.6.5        # pinned <6: pycose 1.1.0 checks isinstance(list); cbor2>=6 returns tuples (see ambiguity log)
rfc8785==0.1.4
ecdsa==0.19.2       # pulled by pycose; it is the ES256 backend — see the honesty note in M1
cffi==2.1.1
pycparser==3.0
```
Python 3.12.10. Correctness gate before timing: ES256 + EdDSA COSE_Sign1
round-trip **verifies on all 12 headers** (harness aborts otherwise).

---

## M1 — write path (ns per record, over N; min is headline)

| variant | min | median | max | stdev | n |
|---|--:|--:|--:|--:|--:|
| **A — SHA-256 chain hash** | **414.8** | 429.0 | 457.9 | 14.1 | 200 000 |
| B — COSE_Sign1 **ES256** (pycose) | 803 597 | 812 643 | 827 596 | 8 978 | 20 000 |
| B — COSE_Sign1 **EdDSA** (pycose) | 77 671 | 78 964 | 79 736 | 816 | 20 000 |

## M2 — verify path (ns per record)

| variant | min | median | max | stdev | n |
|---|--:|--:|--:|--:|--:|
| **A — SHA-256 chain recompute** | **419.0** | 424.5 | 432.1 | 4.3 | 200 000 |
| B — COSE_Sign1 **ES256** verify (pycose) | 1 502 079 | 1 515 875 | 1 527 270 | 9 679 | 20 000 |
| B — COSE_Sign1 **EdDSA** verify (pycose) | 87 819 | 88 206 | 91 567 | 1 423 | 20 000 |

**Boundary (M2), stated explicitly:** keys and verifier objects are constructed
**once, before** the timed loop; the COSE messages to verify are pre-encoded
once. The timed region is per-record only: recompute-SHA-256 for the chain,
`verify_signature()` (which includes CBOR `decode()`, because a received record
arrives as bytes) for COSE. Rationale — a real verifier is long-lived and loads
its key once; charging key setup per record would measure setup, not verify.

### Honesty note — the ES256 number is a library artifact, not the primitive cost

pycose's ES256 path uses the pure-Python `ecdsa` library. Its 804 µs sign /
1502 µs verify are dominated by that backend, **not** by the ECDSA primitive.
Measured through `cryptography` (OpenSSL) over the same 156-byte headers as a
reference (not a replacement — the harness was **not** tuned to swap it):

| native primitive (cryptography) | sign min | verify min |
|---|--:|--:|
| ECDSA P-256 | 18 871 ns (18.9 µs) | 48 727 ns (48.7 µs) |
| Ed25519 | 25 139 ns (25.1 µs) | 70 446 ns (70.4 µs) |

So pycose ES256 is **~43× (sign) / ~31× (verify)** slower than native ECDSA — a
backend artifact. pycose EdDSA (77.7 / 87.8 µs) sits ~3× / ~1.25× above native
Ed25519, the CBOR-envelope + Python overhead. **Report the native row as the
fair floor for per-record signing.**

### What the numbers say (min, native floor for signing)

| ratio vs SHA-256 chain | write | verify |
|---|--:|--:|
| native ECDSA P-256 / hash | **45×** | **116×** |
| native Ed25519 / hash | **61×** | **168×** |
| pycose COSE_Sign1 EdDSA / hash | 187× | 210× |
| pycose COSE_Sign1 ES256 / hash | 1 937× | 3 585× |

**Result, honestly:** per-record signing costs **one-to-two orders of magnitude**
more than a chain hash *even at the native-primitive floor* — ~19–25 µs to sign
and ~49–70 µs to verify, against ~0.4 µs to hash. This is **not** "negligible on
this hardware": at a sustained high write rate the gap is real — hashing at
~0.4 µs/record keeps up with a fast writer, native signing at ~19 µs/record does
not, and the COSE-envelope path is slower again. The chain buys this by giving up
the standalone-provable property (see Framing). *(The sub-µs hash is near the
Python-call-overhead floor, so it is itself an upper bound on the true SHA-256
cost — which only widens the gap, not narrows it.)*

## M3 — on-wire bytes per protected record

| | bytes |
|---|--:|
| Chain record (the 156-byte header; integrity carried **inside** it) | **156** |
| — of which marginal integrity = the `prev_hash` link | 32 |
| COSE_Sign1 ES256 total | 231 |
| — envelope overhead (total − 156 payload) | **75** |
| COSE_Sign1 EdDSA total | 231 |
| — envelope overhead | **75** |
| payload (both) | 156 |

COSE_Sign1 adds **75 bytes** of envelope (protected header + unprotected map +
64-byte signature + CBOR structure) over the 156-byte payload; ES256 and EdDSA
tie at 231 B (both use 64-byte signatures). The chain's marginal integrity cost
is **32 bytes** (the `prev_hash` already living in the header) — roughly **2.3×
less** on-wire integrity overhead than COSE, again bought by the weaker
per-record property.

## M4 — timestamp boundary (code-proof, not performance)

A nanosecond wall-clock is a large integer: `1_786_000_000_123_456_789`, which
**exceeds 2⁵³** (9 007 199 254 740 992 — the exact-integer ceiling of IEEE-754
doubles).

1. **Does the JCS lib encode it?** `rfc8785==0.1.4` **refuses**: it raises
   `IntegerDomainError: … exceeds safe integer domain for JSON floats`. RFC 8785
   serialises numbers as ECMAScript doubles, so integers past 2⁵³ are unsafe;
   this implementation is **fail-loud**. (Behaviour differs across JCS impls —
   some silently down-convert; the difference is itself the finding. One impl
   was tested here.)
2. **What a doubles-based JSON consumer yields.** `int(float(ns))` =
   `1_786_000_000_123_456_768` — a **−21 ns** error from truth. A consumer that
   *doesn't* fail loud silently loses ~21 ns of precision on this value (the loss
   grows with magnitude).
3. **Workaround byte-cost + ordering.**
   - CBOR unsigned integer: **9 bytes** (`1b 18c925899834cd15`), lossless and
     numerically ordered.
   - RFC 3339 string `"2026-08-14T05:06:40.123456789Z"`: **30 bytes** (**3.3×**
     bigger) — and variable fractional precision **breaks lexical ordering**:
     `"…40.09Z"` sorts *after* `"…40.1Z"` though 0.09 s is *earlier* than 0.1 s.
     Fixed-width zero-padded RFC 3339 avoids it, but the general string workaround
     carries the trap.

**Design-relevant:** PALA-1's binary header stores `wall_clock_ns` as a
fixed-width integer (§2.1, offset 108, 8 bytes, little-endian) — the binary
format **sidesteps the 2⁵³ JSON boundary entirely**. A JSON/JCS transport for
the same value cannot carry it losslessly without the string workaround (bytes +
ordering cost) or an out-of-band convention.

---

## Ambiguity log

Every place the spec / vectors / task admitted more than one reading — even
where resolved correctly.

1. **"156-byte headers."** Records carry `header_len ≥ 156`; three test vectors
   have TLVs (165 / 170 / 214 B). Resolved to the **§2.1 fixed-header prefix**
   `header_hex[:156]` — real header bytes, uniform 156 B, matching "156-byte
   headers." (Using full `header_len` would vary the input size and the hash cost
   per record; the task pinned 156.)
2. **Headline statistic.** `BENCHMARKING.md` says "median and spread"; the task
   says "minimum and spread, name which and why." Both are reported;
   **minimum is the headline** for these deterministic micro-ops (noise only adds
   time), median is given as the house convention. No axis was re-cut to a number.
3. **M2 timing boundary.** Whether key loading / verifier construction is inside
   the timed loop is a choice that changes the number. Chosen: **excluded** (loaded
   once, long-lived-verifier model); `decode()` **included** (a received record is
   bytes). Stated in M2.
4. **Chain "on-wire" bytes.** The chain stores no per-record `record_hash`; its
   integrity is the 32-byte `prev_hash` *inside* the 156-byte header. So "chain
   record bytes" is ambiguous between **156** (the whole protected header) and
   **32** (the marginal integrity link). Both reported (M3).
5. **`pycose` cbor2 pin.** pycose 1.1.0 decodes via `isinstance(cose_obj, list)`,
   but `cbor2 ≥ 6` returns CBOR arrays as **tuples**, so decode raised
   "Bytes cannot be decoded as COSE message". Pinned `cbor2==5.6.5` (returns
   lists). A compatibility pin, not a result-affecting tune — it only makes decode
   work; timings are unaffected by the cbor2 minor.
6. **`pycose` ES256 backend.** Not an ambiguity in the spec but a
   measurement-validity caveat: the COSE_Sign1 **ES256** figure reflects pycose's
   pure-Python `ecdsa` backend, not the ECDSA primitive. Reported as-measured
   **and** annotated with the native-`cryptography` reference (M1 honesty note),
   rather than silently swapping libraries to get a nicer number.
7. **M4 timestamp value / JCS impl.** The specific ns value is representative
   (only "> 2⁵³" matters); one JCS implementation (`rfc8785`) was tested. Its
   fail-loud behaviour is one point on a spectrum other impls differ on.

## Unmeasured (honestly)

- **Constraint-class hardware.** Not available in this run; the claim's real bite
  is there. Marked for a separate run if an SBC is provided — not extrapolated to
  a number here.
- **Native ECDSA *inside* a COSE_Sign1 envelope.** The native reference measures
  the bare primitives; a COSE_Sign1 built on an OpenSSL ECDSA backend would land
  between the native row and the pycose row. Not synthesised — would need a COSE
  lib with an OpenSSL ECDSA backend, out of scope for the pinned set.

## Artifacts

- Harness, as-ran (unpolished): `harness/harness.py`, `harness/supplement_native.py`.
- Raw per-repeat data: `raw/repeats.csv`, `raw/results.json`, `raw/native_primitives.json`.
- Allowed inputs (copied): `allowed/{PALA-1.md, test-vectors.json, BENCHMARKING.md}`.
- **Wall-clock spent:** harness ≈ 2.5 min compute (M1 + M2 + native supplement);
  full task incl. setup, isolation, debugging the cbor2 pin, and writing ≈ 35 min.
