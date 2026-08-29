"""Supplementary reference measurement — native crypto primitives.

The primary harness measures COSE_Sign1 via pycose (as the task allows). pycose's
ES256 path uses the pure-Python `ecdsa` library, so its ES256 figure is dominated
by that backend, NOT by the ECDSA primitive's real cost. This supplement measures
the raw primitives through `cryptography` (OpenSSL backend) over the same 156-byte
headers, so the report can separate "library artifact" from "crypto cost". It does
NOT replace the primary result — it annotates it.
"""

from __future__ import annotations

import json
import os
import statistics
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(ROOT, "raw")
VEC = os.path.join(ROOT, "allowed", "test-vectors.json")
REPEATS = 6
N = 20_000


def headers():
    d = json.load(open(VEC, encoding="utf-8"))
    return [bytes.fromhex(r["header_hex"])[:156] for r in d["records"]]


def rep(fn, label):
    per = []
    for i in range(REPEATS):
        t0 = time.perf_counter_ns(); fn(N); dt = time.perf_counter_ns() - t0
        per.append({"repeat": i, "warmup": i == 0, "ns_per_record": dt / N})
    kept = [r["ns_per_record"] for r in per if not r["warmup"]]
    return {"label": label, "n": N, "min_ns": min(kept), "median_ns": statistics.median(kept),
            "max_ns": max(kept), "stdev_ns": statistics.pstdev(kept), "raw": per}


def main():
    hs = headers()
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()

    # pre-sign for the verify measurements
    ecdsa_sigs = [ec_priv.sign(h, ec.ECDSA(hashes.SHA256())) for h in hs]
    ed_sigs = [ed_priv.sign(h) for h in hs]

    def ecdsa_sign(n):
        for i in range(n):
            ec_priv.sign(hs[i % 12], ec.ECDSA(hashes.SHA256()))

    def ecdsa_verify(n):
        for i in range(n):
            ec_pub.verify(ecdsa_sigs[i % 12], hs[i % 12], ec.ECDSA(hashes.SHA256()))

    def ed_sign(n):
        for i in range(n):
            ed_priv.sign(hs[i % 12])

    def ed_verify(n):
        for i in range(n):
            ed_pub.verify(ed_sigs[i % 12], hs[i % 12])

    res = {
        "note": "native cryptography (OpenSSL) primitives over the 156-byte headers; "
                "reference to separate pycose ES256's pure-Python backend from the primitive cost",
        "cryptography": __import__("cryptography").__version__,
        "ecdsa_p256_sign": rep(ecdsa_sign, "native ECDSA P-256 sign (cryptography)"),
        "ecdsa_p256_verify": rep(ecdsa_verify, "native ECDSA P-256 verify (cryptography)"),
        "ed25519_sign": rep(ed_sign, "native Ed25519 sign (cryptography)"),
        "ed25519_verify": rep(ed_verify, "native Ed25519 verify (cryptography)"),
    }
    json.dump(res, open(os.path.join(RAW, "native_primitives.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    for k in ("ecdsa_p256_sign", "ecdsa_p256_verify", "ed25519_sign", "ed25519_verify"):
        b = res[k]
        print(f"  {b['label']:<42} min {b['min_ns']:>9.1f}  median {b['median_ns']:>9.1f}  "
              f"stdev {b['stdev_ns']:>7.1f} ns/record (n={b['n']})")


if __name__ == "__main__":
    main()
