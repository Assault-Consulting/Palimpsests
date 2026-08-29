"""Independent measurement — serialization / integrity cost, PALA-1.

Built from public standards (FIPS 180-4 SHA-256, RFC 9052 COSE_Sign1,
RFC 8032 Ed25519, FIPS 186-5 ECDSA P-256, RFC 8949 CBOR, RFC 8785 JCS) and
the published PALA-1 header layout (§2.1) + test-vectors.json alone. No
reference to benchmarks/**, src/palimpsests/**, or tests/**.

What is compared, stated honestly (framing): this is NOT "PALA-1 is cheaper
than SCITT". SCITT/COSE_Sign1 signs a self-sufficient statement; a PALA-1
record proves only in sequence (its integrity is the prev_hash chain link).
We measure the price of a *hypothetical per-record signature* (COSE_Sign1)
against *chain hashing* (one SHA-256 per record). If chain hashing is cheaper,
that saving is bought by the weaker per-record property, and the report says so.

Method: input is the REAL 156-byte fixed header of each test-vector record
(header_hex[:312]), cycled to N. >=5 timed repeats per measurement + 1 warm-up
discarded. We report min (headline, least-perturbed estimator for a
deterministic op), median (BENCHMARKING.md convention), and spread (max/stdev).
Raw per-repeat data is written to ../raw/.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import statistics
import sys
import time

import cbor2
from pycose.algorithms import EdDSA, Es256
from pycose.headers import Algorithm
from pycose.keys import EC2Key, OKPKey
from pycose.messages import Sign1Message

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(ROOT, "raw")
VEC = os.path.join(ROOT, "allowed", "test-vectors.json")

REPEATS = 6          # 1 warm-up (discarded) + 5 kept
N_HASH = 200_000     # SHA-256 is sub-µs; large N so per-call Python overhead is negligible
N_SIG = 20_000       # sign/verify are ~10s of µs; smaller N, still >> per-call overhead


def load_headers() -> list[bytes]:
    d = json.load(open(VEC, encoding="utf-8"))
    hs = [bytes.fromhex(r["header_hex"])[:156] for r in d["records"]]
    assert all(len(h) == 156 for h in hs), "every fixed header must be 156 bytes"
    return hs


def measure(fn, n: int) -> float:
    """Run fn over n records (cycling headers inside fn); return ns/record."""
    t0 = time.perf_counter_ns()
    fn(n)
    dt = time.perf_counter_ns() - t0
    return dt / n


def repeat(fn, n: int, label: str) -> dict:
    per = []
    for i in range(REPEATS):
        ns_per = measure(fn, n)
        per.append({"repeat": i, "warmup": i == 0, "n": n, "ns_per_record": ns_per})
    kept = [r["ns_per_record"] for r in per if not r["warmup"]]
    return {
        "label": label, "n": n, "kept": len(kept),
        "min_ns": min(kept), "median_ns": statistics.median(kept),
        "max_ns": max(kept), "stdev_ns": statistics.pstdev(kept),
        "raw": per,
    }


# ── M1 write path ───────────────────────────────────────────────────────────
def m1(headers, ec2, okp):
    def hash_write(n):
        for i in range(n):
            hashlib_sha256(headers[i % 12]).digest()

    def es256_write(n):
        for i in range(n):
            m = Sign1Message(phdr={Algorithm: Es256}, payload=headers[i % 12])
            m.key = ec2
            m.encode()

    def eddsa_write(n):
        for i in range(n):
            m = Sign1Message(phdr={Algorithm: EdDSA}, payload=headers[i % 12])
            m.key = okp
            m.encode()

    return {
        "A_chain_sha256": repeat(hash_write, N_HASH, "M1 write: SHA-256 chain hash"),
        "B_cose_es256": repeat(es256_write, N_SIG, "M1 write: COSE_Sign1 ES256"),
        "B_cose_eddsa": repeat(eddsa_write, N_SIG, "M1 write: COSE_Sign1 EdDSA"),
    }


# ── M2 verify path ──────────────────────────────────────────────────────────
# Boundary decision: keys/verifier objects are constructed ONCE, before the
# timed loop, and the COSE messages to verify are pre-encoded once. The timed
# region is per-record verification only (recompute-hash for the chain;
# verify_signature for COSE). Rationale: a real verifier is long-lived and loads
# its key once; charging key setup per record would measure setup, not verify.
def m2(headers, ec2, okp):
    es_msgs = []
    ed_msgs = []
    for i in range(12):
        me = Sign1Message(phdr={Algorithm: Es256}, payload=headers[i]); me.key = ec2
        es_msgs.append(me.encode())
        mo = Sign1Message(phdr={Algorithm: EdDSA}, payload=headers[i]); mo.key = okp
        ed_msgs.append(mo.encode())

    def hash_verify(n):
        for i in range(n):
            hashlib_sha256(headers[i % 12]).digest()   # chain check = recompute

    def es256_verify(n):
        for i in range(n):
            m = Sign1Message.decode(es_msgs[i % 12]); m.key = ec2
            m.verify_signature()

    def eddsa_verify(n):
        for i in range(n):
            m = Sign1Message.decode(ed_msgs[i % 12]); m.key = okp
            m.verify_signature()

    return {
        "A_chain_sha256": repeat(hash_verify, N_HASH, "M2 verify: SHA-256 chain recompute"),
        "B_cose_es256": repeat(es256_verify, N_SIG, "M2 verify: COSE_Sign1 ES256"),
        "B_cose_eddsa": repeat(eddsa_verify, N_SIG, "M2 verify: COSE_Sign1 EdDSA"),
        "_note": "decode() is included in verify (a received record is bytes); key set once outside timing per boundary decision above",
    }


# ── M3 on-wire bytes ────────────────────────────────────────────────────────
def m3(headers, ec2, okp):
    h = headers[0]
    me = Sign1Message(phdr={Algorithm: Es256}, payload=h); me.key = ec2
    es = me.encode()
    mo = Sign1Message(phdr={Algorithm: EdDSA}, payload=h); mo.key = okp
    ed = mo.encode()
    return {
        "chain_record_bytes": 156,
        "chain_integrity_marginal_bytes": 32,  # the prev_hash link carried in the header
        "cose_es256_total_bytes": len(es),
        "cose_es256_envelope_overhead_bytes": len(es) - 156,
        "cose_eddsa_total_bytes": len(ed),
        "cose_eddsa_envelope_overhead_bytes": len(ed) - 156,
        "payload_bytes": 156,
    }


# ── M4 timestamp boundary (code-proof, not perf) ────────────────────────────
def m4():
    import rfc8785
    ns = 1_786_000_000_123_456_789      # a nanosecond wall-clock; > 2**53
    two53 = 2 ** 53
    out = {"ns_value": ns, "exceeds_2^53": ns > two53, "2^53": two53}

    # 1. does the JCS lib encode the big integer, and how?
    try:
        jcs = rfc8785.dumps({"t": ns})
        out["jcs_rfc8785_output"] = jcs.decode() if isinstance(jcs, bytes) else jcs
        out["jcs_lib"] = "rfc8785==0.1.4"
    except Exception as e:  # noqa: BLE001
        out["jcs_rfc8785_error"] = f"{type(e).__name__}: {e}"
        out["jcs_lib"] = "rfc8785==0.1.4"

    # 2. what a JSON consumer on IEEE-754 doubles yields, and the delta
    as_double = float(ns)
    back = int(as_double)
    out["ieee754_double_roundtrip"] = back
    out["ieee754_delta_ns"] = back - ns

    # 3. workaround byte cost
    rfc3339 = "2026-08-14T05:06:40.123456789Z"       # same instant, RFC 3339 string
    cbor_int = cbor2.dumps(ns)                        # CBOR unsigned integer
    out["workaround_rfc3339_string"] = rfc3339
    out["workaround_rfc3339_bytes"] = len(rfc3339.encode())
    out["workaround_cbor_integer_bytes"] = len(cbor_int)
    out["workaround_cbor_integer_hex"] = cbor_int.hex()
    # numeric ordering under string comparison: differing fractional-digit counts break it
    a = "2026-08-14T05:06:40.1Z"
    b = "2026-08-14T05:06:40.09Z"   # earlier instant (0.09 < 0.1) but sorts AFTER as a string
    out["string_order_pitfall"] = {
        "earlier_instant": b, "later_instant": a,
        "string_sorts_earlier_first": b < a,
        "note": "0.09s precedes 0.1s in time but '...40.09Z' > '...40.1Z' lexically",
    }
    return out


import hashlib  # noqa: E402
hashlib_sha256 = hashlib.sha256


def main():
    os.makedirs(RAW, exist_ok=True)
    headers = load_headers()
    ec2 = EC2Key.generate_key(crv="P_256")
    okp = OKPKey.generate_key(crv="Ed25519")

    # correctness gate before timing: the harness must actually verify
    for i in range(12):
        me = Sign1Message(phdr={Algorithm: Es256}, payload=headers[i]); me.key = ec2
        d = Sign1Message.decode(me.encode()); d.key = ec2
        assert d.verify_signature(), "ES256 self-verify failed"
        mo = Sign1Message(phdr={Algorithm: EdDSA}, payload=headers[i]); mo.key = okp
        d2 = Sign1Message.decode(mo.encode()); d2.key = okp
        assert d2.verify_signature(), "EdDSA self-verify failed"
    print("correctness gate: ES256 + EdDSA COSE_Sign1 round-trip verifies on all 12 headers", flush=True)

    results = {
        "env": {
            "python": sys.version.split()[0], "platform": platform.platform(),
            "processor": platform.processor(),
        },
        "params": {"REPEATS_incl_warmup": REPEATS, "N_HASH": N_HASH, "N_SIG": N_SIG,
                   "headers": "12 real 156-byte fixed headers from test-vectors.json, cycled"},
        "M1_write": m1(headers, ec2, okp),
        "M2_verify": m2(headers, ec2, okp),
        "M3_bytes": m3(headers, ec2, okp),
        "M4_timestamp": m4(),
    }

    json.dump(results, open(os.path.join(RAW, "results.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    # flat CSV of every kept+warmup repeat
    with open(os.path.join(RAW, "repeats.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["measurement", "variant", "repeat", "warmup", "n", "ns_per_record"])
        for m in ("M1_write", "M2_verify"):
            for var, block in results[m].items():
                if not isinstance(block, dict) or "raw" not in block:
                    continue
                for r in block["raw"]:
                    w.writerow([m, var, r["repeat"], r["warmup"], r["n"], f"{r['ns_per_record']:.3f}"])

    # console summary
    def line(b):
        return (f"  {b['label']:<38} min {b['min_ns']:>10.1f}  median {b['median_ns']:>10.1f}  "
                f"max {b['max_ns']:>10.1f}  stdev {b['stdev_ns']:>8.1f}  ns/record  (n={b['n']}, kept={b['kept']})")
    print("\n=== M1 write (ns/record) ===")
    for k in ("A_chain_sha256", "B_cose_es256", "B_cose_eddsa"):
        print(line(results["M1_write"][k]))
    print("\n=== M2 verify (ns/record) ===")
    for k in ("A_chain_sha256", "B_cose_es256", "B_cose_eddsa"):
        print(line(results["M2_verify"][k]))
    print("\n=== M3 bytes ===")
    for k, v in results["M3_bytes"].items():
        print(f"  {k}: {v}")
    print("\n=== M4 timestamp boundary ===")
    for k, v in results["M4_timestamp"].items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
