# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""D2.8 — PALA-1 chain hashing vs COSE_Sign1 per-record signing.

Run: python benchmarks/bench_cose_compare.py  (needs the [scitt] extra)

Honest-comparison rules, stated up front:
- Inputs are the REAL 156-byte headers from the published core vectors,
  cycled to N. No synthetic layout.
- The COSE payload is the same 156 bytes, so both sides protect the
  same content. Neither side includes record bodies.
- Time is a proxy for cycles/energy. A container run is NON-CANONICAL;
  rerun on pinned hardware before any number enters the draft.
- SCITT signs once per REGISTERED STATEMENT, not per log line; this
  table answers "what would per-record signing cost", which is the C1
  question, not a claim about SCITT's own cost model.
"""
from __future__ import annotations

import json
import statistics
import time
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from palimpsests.audit import pala
from palimpsests.audit.pala import scitt, vectors

N = 20_000
REPS = 5


def real_headers(n: int) -> list[bytes]:
    v = vectors.load("core")
    base = [bytes.fromhex(r["header_hex"]) for r in v["records"]]
    assert all(
        len(b) == r["header_len"] and len(b) >= pala.FIXED_HEADER_LEN
        for b, r in zip(base, v["records"], strict=True)
    )
    return [base[i % len(base)] for i in range(n)]


def best_of(fn, reps: int = REPS) -> float:
    times = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return min(times)


def main() -> None:
    headers = real_headers(N)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()

    # --- write path -------------------------------------------------
    t_hash = best_of(lambda: [pala.record_hash(h) for h in headers])
    t_es = best_of(
        lambda: [scitt._cose_sign1(h, ec_key, alg=scitt.ALG_ES256) for h in headers[: N // 10]]
    ) * 10
    t_ed = best_of(
        lambda: [scitt._cose_sign1(h, ed_key, alg=scitt.ALG_EDDSA) for h in headers[: N // 10]]
    ) * 10

    # --- verify path ------------------------------------------------
    t_vh = best_of(lambda: pala.verify_headers(headers))
    es_msgs = [scitt._cose_sign1(h, ec_key, alg=scitt.ALG_ES256) for h in headers[: N // 10]]
    ed_msgs = [scitt._cose_sign1(h, ed_key, alg=scitt.ALG_EDDSA) for h in headers[: N // 10]]
    ec_pub, ed_pub = ec_key.public_key(), ed_key.public_key()
    t_ves = best_of(lambda: [scitt._cose_verify1(m, ec_pub) for m in es_msgs]) * 10
    t_ved = best_of(lambda: [scitt._cose_verify1(m, ed_pub) for m in ed_msgs]) * 10

    # --- bytes per record -------------------------------------------
    b_pala = pala.FIXED_HEADER_LEN
    b_es = statistics.mean(len(m) for m in es_msgs)
    b_ed = statistics.mean(len(m) for m in ed_msgs)

    # --- JCS / double-semantics nanosecond demo ---------------------
    ts_ns = 1_756_300_000_123_456_789  # a real wall-clock nanosecond value
    round_trip = json.loads(json.dumps(ts_ns))  # parsers that go through double
    lossy_float = int(float(ts_ns))
    cbor_exact = __import__("cbor2").loads(__import__("cbor2").dumps(ts_ns)) == ts_ns
    cbor_len = len(__import__("cbor2").dumps(ts_ns))

    def us(t: float, n: int = N) -> str:
        return f"{t / n * 1e6:8.2f}"

    def rps(t: float, n: int = N) -> str:
        return f"{n / t:12,.0f}"

    print(
        f"inputs: {N:,} real vector headers "
        f"(156-byte fixed part + TLV tail, 12 published records cycled), best of {REPS}"
    )
    print()
    print("| operation (per record)            | µs/record | records/s | vs PALA-1 |")
    print("|---|---:|---:|---:|")
    print(f"| PALA-1 record_hash (SHA-256)      | {us(t_hash)} | {rps(t_hash)} | 1.0× |")
    print(f"| COSE_Sign1 sign, Ed25519          | {us(t_ed)} | {rps(t_ed)} | {t_ed/t_hash:5.1f}× |")
    print(f"| COSE_Sign1 sign, ES256            | {us(t_es)} | {rps(t_es)} | {t_es/t_hash:5.1f}× |")
    print(f"| PALA-1 verify_headers (full chain)| {us(t_vh)} | {rps(t_vh)} | 1.0× |")
    r_ed = f"{t_ved / t_vh:5.1f}"
    r_es = f"{t_ves / t_vh:5.1f}"
    print(f"| COSE_Sign1 verify, Ed25519        | {us(t_ved)} | {rps(t_ved)} | {r_ed}× |")
    print(f"| COSE_Sign1 verify, ES256          | {us(t_ves)} | {rps(t_ves)} | {r_es}× |")
    print()
    print("| integrity carrier                 | bytes/record |")
    print("|---|---:|")
    print(f"| PALA-1 header (fixed part)        | {b_pala} |")
    print(f"| COSE_Sign1 (Ed25519, same payload)| {b_ed:.0f} |")
    print(f"| COSE_Sign1 (ES256, same payload)  | {b_es:.0f} |")
    print()
    print("nanosecond wall-clock value, 1_756_300_000_123_456_789:")
    print(f"  json round-trip preserved: {round_trip == ts_ns}   (2^53 = {2**53:_})")
    print(f"  through IEEE-754 double:   {lossy_float:_}  (lossy: {lossy_float != ts_ns})")
    print(f"  CBOR integer exact: {cbor_exact}, encoded length: {cbor_len} bytes")
    print()
    print("keys needed to verify: PALA-1 chain = none; COSE_Sign1 = issuer public key")
    print("NOTE: container run — NON-CANONICAL. Rerun on pinned hardware for the draft.")


if __name__ == "__main__":
    main()
