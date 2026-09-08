# Independent Measurement Report: PALA-1 Serialization Cost Analysis

**Issue:** #184 — independent measurement: serialization cost  
**Repository:** Assault-Consulting/Palimpsests  
**Measurer:** @olksandrvertel-arch  
**Date:** August 28, 2026  
**Hardware:** Intel Core Ultra 9 185H workstation (Windows 11)  
**Status:** Completed

---

## Executive Summary

An independent benchmark of PALA-1's serialization and integrity costs was conducted following the project's BENCHMARKING.md methodology. The measurement compares chain-hash verification (PALA-1's approach) against per-record COSE_Sign1 signatures, establishing concrete performance and wire-overhead trade-offs.

**Key finding:** Chain hashing is **45–61× cheaper** than native signature verification and **116–168× cheaper** than signature verification, but provides weaker per-record properties (sequence-dependent, not self-proving). The cost difference is substantial and measurable at scale.

---

## Measurement Scope

**Contamination boundary:** Measurement harness built from public standards (FIPS 180-4, RFC 9052, RFC 8949, RFC 8785) and `test-vectors.json` alone. No access to `benchmarks/`, `src/`, or `tests/` directories.

**Vectors tested:** 12 real PALA-1 record headers from `test-vectors.json` (commit `604fb11`), cycled to N repeats.

**Methodology:** 6 timed passes per measurement, first discarded as warm-up, 5 kept. Headline = minimum (least-perturbed). Min, median, max, and stdev reported.

**Hardware scope:** Workstation (upper bound). Constraint-class measurements (SBC) marked for future work if hardware provided.

---

## Results

### M1 — Write Path (ns per record)

| Variant | Min | Median | Max | Stdev | N |
|---------|-----|--------|-----|-------|---------|
| **SHA-256 chain hash** | **414.8** | 429.0 | 457.9 | 14.1 | 200,000 |
| COSE_Sign1 ES256 (pycose) | 803,597 | 812,643 | 827,596 | 8,978 | 20,000 |
| COSE_Sign1 EdDSA (pycose) | 77,671 | 78,964 | 79,736 | 816 | 20,000 |

**Native primitive reference** (cryptography/OpenSSL):
- ECDSA P-256: 18.9 µs (18,871 ns)
- Ed25519: 25.1 µs (25,139 ns)

### M2 — Verify Path (ns per record)

| Variant | Min | Median | Max | Stdev | N |
|---------|-----|--------|-----|-------|---------|
| **SHA-256 chain recompute** | **419.0** | 424.5 | 432.1 | 4.3 | 200,000 |
| COSE_Sign1 ES256 verify (pycose) | 1,502,079 | 1,515,875 | 1,527,270 | 9,679 | 20,000 |
| COSE_Sign1 EdDSA verify (pycose) | 87,819 | 88,206 | 91,567 | 1,423 | 20,000 |

**Native primitive reference:**
- ECDSA P-256: 48.7 µs (48,727 ns)
- Ed25519: 70.4 µs (70,446 ns)

### Cost Ratios (native primitives as fair baseline)

| Operation | vs SHA-256 chain |
|-----------|------------------|
| Native ECDSA P-256 sign | 45× costlier |
| Native ECDSA P-256 verify | 116× costlier |
| Native Ed25519 sign | 61× costlier |
| Native Ed25519 verify | 168× costlier |

### M3 — On-Wire Bytes per Record

| Format | Total | Payload | Integrity overhead |
|--------|-------|---------|-------------------|
| **PALA-1 chain** | 156 B | 156 B | **32 B** (prev_hash) |
| COSE_Sign1 (ES256) | 231 B | 156 B | 75 B (envelope) |
| COSE_Sign1 (EdDSA) | 231 B | 156 B | 75 B (envelope) |

**Margin:** COSE envelope adds **2.3× more bytes** for integrity than PALA-1's chain link.

### M4 — Timestamp Boundary (Nanosecond Integers)

**Problem:** Nanosecond wall-clock values exceed IEEE-754 double precision (2⁵³ = 9,007,199,254,740,992).

Example: `1,786,000,000,123,456,789` (real nanosecond timestamp)

**JSON/JCS approach:**
- `rfc8785==0.1.4` raises `IntegerDomainError` (fail-loud)
- Other JCS implementations silently lose precision (~21 ns error on this value)
- RFC 3339 string workaround: 30 bytes (3.3× CBOR overhead), breaks lexical ordering

**PALA-1 binary approach:**
- Fixed-width 8-byte little-endian integer in header (§2.1)
- Lossless, numerically ordered, deterministic

**Implication:** Binary format sidesteps JSON's fundamental limitation on large integers; JSON transport would require convention or data loss.

---

## Library Artifacts vs Primitive Cost

**ES256 caveat:** pycose's ES256 uses pure-Python `ecdsa` backend.

- pycose ES256: **803 µs** (write), **1502 µs** (verify)
- Native ECDSA (cryptography): **18.9 µs** (write), **48.7 µs** (verify)
- **Gap: 43× slower** (backend artifact, not primitive cost)

The report documents this honestly: native ECDSA is fair baseline, pycose ES256 overstates true cost due to library choice.

---

## Design Trade-Offs (Explicitly Framed)

**PALA-1 chain hashing wins on:**
- Speed (0.4 µs/record vs 19–70 µs for signing)
- Wire overhead (32 bytes marginal vs 75 bytes envelope)
- Simplicity (SHA-256 in stdlib, no key management per record)

**COSE_Sign1 signatures win on:**
- Self-provability (single record proves itself)
- Independence (no chain dependency, no sequence requirement)

**Trade-off:** Chain cheaper but sequence-dependent; COSE more expensive but standalone.

The report presents both sides equally rather than optimizing framing toward PALA-1.

---

## Pinned Dependencies

```
cryptography==50.0.1
pycose==1.1.0
cbor2==5.6.5        # pinned <6: pycose checks isinstance(list); cbor2>=6 returns tuples
rfc8785==0.1.4
ecdsa==0.19.2       # pure-Python ES256 backend
cffi==2.1.1
pycparser==3.0
```

**Compatibility note:** cbor2 ≥ 6 returns CBOR arrays as tuples, breaking pycose's `isinstance(list)` check. Pinned to 5.6.5.

---

## Ambiguity Log

Seven ambiguities documented:

1. **156-byte header scope** — Resolved to §2.1 fixed-header prefix (not full `header_len` with TLVs)
2. **Headline statistic** — Both minimum and median reported; minimum chosen for deterministic ops
3. **M2 timing boundary** — Key loading excluded (long-lived verifier model), `decode()` included
4. **"On-wire bytes"** — Reported both total (156 B) and marginal (32 B)
5. **cbor2 pinning** — Compatibility fix, not a tune; no impact on timings
6. **ES256 backend disclosure** — Both pycose and native baselines provided with annotations
7. **Timestamp value / JCS implementation** — One impl tested; behaviour differs across impls

All ambiguities resolved by documentation and transparency, not hidden.

---

## Unmeasured (Stated Plainly)

- **Constraint-class hardware (SBC):** Not available; marked for future run if provided
- **Native ECDSA inside COSE envelope:** Would fall between native baseline and pycose; needs OpenSSL-backed COSE library
- These are genuine limitations, stated upfront rather than extrapolated.

---

## Honesty Principles Applied

1. **No cherry-picked numbers:** Min, median, max, stdev all reported
2. **Library artifacts labeled:** ES256 slowness attributed to backend, not primitive
3. **Both sides presented:** Chain advantages and COSE advantages both listed
4. **Limitations stated:** Hardware class, unmeasured scenarios documented
5. **Ambiguities logged:** Interpretation choices transparent
6. **Methodology detailed:** Boundary conditions and choices explained

---

## Significance

This measurement serves as:
- **Performance baseline** for PALA-1 deployment (0.4 µs/record at scale)
- **Design justification** for chain-vs-COSE trade-off
- **Binary-format validation** (timestamps prove JSON's limitation)
- **Honest benchmark** (trade-offs not hidden behind ratios)

The work took ~35 min task time + ~2.5 min harness runtime.

---

## Conclusion

The independent measurement confirms PALA-1's design claims: chain hashing is substantially cheaper than per-record signatures while trading off the self-proving property. The measurement is thorough, transparent about limitations, and documents findings equally (not just in favor of the design).

**Verdict:** The benchmark is production-ready documentation of PALA-1's performance characteristics and design rationale.

---

**Report compiled from:** GitHub issue Assault-Consulting/Palimpsests#184  
**Harness repository:** https://gist.github.com/olksandrvertel-arch/57f80522d7394cedbb3c3d7a5fa92b72  
**Date compiled:** 2026-09-08
