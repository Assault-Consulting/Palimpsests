<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Measurement — PALA-1 serialization and integrity cost — workstation

Issue #184: what does the chain-hash design cost, against per-record
COSE_Sign1 signatures, in time and in bytes on the wire?

| Field | Value |
|---|---|
| Run ID | `serialization-cost-workstation` |
| Date | 2026-08-28 (report compiled 2026-09-08) |
| Measured by | Oleksandr Verteletskyi (`@olksandrvertel-arch`) — harness and run |
| Report compiled by | Rodion Bakaiev (`@BakaievRodion`), from the issue thread and the harness output |
| Hardware | Intel Core Ultra 9 185H workstation, Windows 11 |
| Vectors | 12 PALA-1 record headers from `docs/specs/pala-1/test-vectors.json` at commit `604fb11`, cycled to N |
| Contamination boundary | Harness written from public standards (FIPS 180-4, RFC 9052, RFC 8949, RFC 8785) and `test-vectors.json` alone; no access to `benchmarks/`, `src/` or `tests/` |
| Harness | Gist `olksandrvertel-arch/57f80522d7394cedbb3c3d7a5fa92b72` — **not pinned in this repository yet** (see "Outstanding" below) |
| Canonical? | **No.** One machine, one OS, one Python. Ratios travel; absolute values do not. |

**Method.** Six timed passes per measurement, the first discarded as
warm-up, five kept. Headline is the minimum (the least-perturbed pass
for a deterministic operation); min, median, max and stdev are all
reported below so the reader can pick differently.

## M1 — write path, ns per record

| Variant | Min | Median | Max | Stdev | N |
|---|---|---|---|---|---|
| SHA-256 chain hash | **414.8** | 429.0 | 457.9 | 14.1 | 200 000 |
| COSE_Sign1 ES256 (pycose) | 803 597 | 812 643 | 827 596 | 8 978 | 20 000 |
| COSE_Sign1 EdDSA (pycose) | 77 671 | 78 964 | 79 736 | 816 | 20 000 |

Native primitives for reference (`cryptography` / OpenSSL): ECDSA P-256
sign 18 871 ns; Ed25519 sign 25 139 ns.

## M2 — verify path, ns per record

| Variant | Min | Median | Max | Stdev | N |
|---|---|---|---|---|---|
| SHA-256 chain recompute | **419.0** | 424.5 | 432.1 | 4.3 | 200 000 |
| COSE_Sign1 ES256 verify (pycose) | 1 502 079 | 1 515 875 | 1 527 270 | 9 679 | 20 000 |
| COSE_Sign1 EdDSA verify (pycose) | 87 819 | 88 206 | 91 567 | 1 423 | 20 000 |

Native primitives for reference: ECDSA P-256 verify 48 727 ns; Ed25519
verify 70 446 ns.

### Ratios, against the native primitives (the fair baseline)

| Operation | vs SHA-256 chain |
|---|---|
| ECDSA P-256 sign | 45× |
| Ed25519 sign | 61× |
| ECDSA P-256 verify | 116× |
| Ed25519 verify | 168× |

**The library artifact, stated rather than used.** pycose's ES256 runs
on the pure-Python `ecdsa` backend: 803 µs write against 18.9 µs for the
native primitive — a 43× gap that belongs to the library, not to the
signature scheme. The ratios above therefore use the native numbers.
Quoting the pycose column as "the cost of COSE" would overstate the case
for the chain by more than an order of magnitude.

## M3 — bytes on the wire, per record

| Format | Total | Payload | Integrity overhead |
|---|---|---|---|
| PALA-1 chain | 156 B | 156 B | **32 B** (`prev_hash`) |
| COSE_Sign1 (ES256) | 231 B | 156 B | 75 B (envelope) |
| COSE_Sign1 (EdDSA) | 231 B | 156 B | 75 B (envelope) |

The COSE envelope costs 2.3× more bytes for integrity than the chain
link.

## M4 — nanosecond timestamps and IEEE-754

Nanosecond wall-clock values exceed the exact-integer range of an
IEEE-754 double (2⁵³ = 9 007 199 254 740 992). Example:
`1 786 000 000 123 456 789`.

- `rfc8785==0.1.4` raises `IntegerDomainError` — fails loud.
- Another JCS implementation in the same test silently lost precision
  (~21 ns on this value).
- The RFC 3339 string workaround costs 30 bytes (3.3× the CBOR integer)
  and breaks lexical ordering.
- PALA-1 stores the value as a fixed-width 8-byte little-endian integer
  in the header (§2.1): lossless, ordered, deterministic.

This is the measured form of the core's §1.1 argument for a binary
format. Note the scope: one JCS implementation was tested for the
silent-precision case; the behaviour differs across implementations, and
the report does not claim otherwise.

## Trade-off, both directions

| | Chain hashing | Per-record COSE_Sign1 |
|---|---|---|
| Cost | ~0.4 µs/record write and verify | 19–70 µs native; more with a slow backend |
| Wire | 32 B marginal | 75 B envelope |
| Key handling | none per record | a signing key per record |
| What one record proves alone | nothing — the property is sequence-dependent | itself: a single record is self-proving |
| Independence | needs its neighbours | standalone |

Cheaper and sequence-dependent, against costlier and standalone. The
project's own answer to the second column is the anchor and the witness
(core §7.2, §7.3), which buy back completeness and existence-in-time at
the chain level rather than per record — that is a different trade, not
a refutation of this one.

## Pinned dependencies

```
cryptography==50.0.1
pycose==1.1.0
cbor2==5.6.5        # <6: pycose checks isinstance(list); cbor2>=6 returns tuples
rfc8785==0.1.4
ecdsa==0.19.2       # pure-Python ES256 backend
cffi==2.1.1
pycparser==3.0
```

## Ambiguities logged during the run

1. **156-byte header scope** — resolved to the §2.1 fixed-header prefix, not the full `header_len` with TLVs.
2. **Headline statistic** — minimum chosen for a deterministic operation; median reported beside it.
3. **M2 timing boundary** — key loading excluded (a long-lived verifier holds its key); `decode()` included.
4. **"On-wire bytes"** — both total and marginal reported, because the two answer different questions.
5. **cbor2 pinning** — a compatibility fix, not a tune; no effect on timings.
6. **ES256 backend** — both pycose and native baselines reported, with the gap attributed.
7. **Timestamp value and JCS implementation** — one implementation tested for the silent-loss case.

## Not measured

- **Constraint-class hardware (SBC).** Not available for this run. The
  ratios are expected to move; the direction is not assumed here.
- **Native ECDSA inside a COSE envelope.** Would fall between the native
  primitive and the pycose column; needs an OpenSSL-backed COSE library.
- **Anything about correctness.** This is a cost measurement. Whether an
  implementation is correct is what the independent verification runs
  (`docs/specs/pala-1/independent-runs/`) answer.

## Outstanding

The harness lives in a gist and is **not pinned in this repository**.
Until it is copied in with a SHA-256 beside it, the numbers above are
usable internally but are not citable in release notes, mappings, or
correspondence — the project's own rule is that a name is not evidence
and a digest is. Copying the harness in and re-running it is a small
task and would also let the run be repeated on other hardware.
