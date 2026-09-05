# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the prefix-consistency companion vectors.

Derived from the inference-profile companion chain
(``profiles/inference-vectors.json``, 17 records): the §4.3 tree over
every record's hash in seq order, and RFC 6962 consistency paths between
prefixes of it. A verifier that reproduces these roots and accepts these
paths has the derived tree and the RFC 9162 verification right.

Companion, like the profile vectors: ``test-vectors.json`` is frozen with
the core and untouched. This file carries its own regeneration gate in
the test suite. Standard library plus ``palaudit_ref`` only — the
reference implementation, not the package, so the vectors are an
independent statement of what the package must reproduce.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import palaudit_ref as R  # noqa: E402

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "profiles" / "inference-vectors.json"
OUT = HERE / "consistency-vectors.json"


def leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def mth(nodes: list[bytes]) -> bytes:
    """RFC 6962 recursive tree hash over already leaf-hashed nodes."""
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    return node(mth(nodes[:k]), mth(nodes[k:]))


def subproof(m: int, nodes: list[bytes], b: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF, verbatim."""
    n = len(nodes)
    if m == n:
        return [] if b else [mth(nodes)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return subproof(m, nodes[:k], b) + [mth(nodes[k:])]
    return subproof(m - k, nodes[k:], False) + [mth(nodes[:k])]


def root(hashes: list[bytes]) -> bytes:
    if not hashes:
        return hashlib.sha256(b"").digest()
    return mth([leaf(h) for h in hashes])


src = json.loads(SOURCE.read_text())
hashes = [R.record_hash(bytes.fromhex(r["header_hex"])) for r in src["records"]]
assert [r["record_hash"] for r in src["records"]] == [h.hex() for h in hashes]
n = len(hashes)

roots = {str(i): root(hashes[:i]).hex() for i in range(0, n + 1)}
pairs = [(1, n), (2, n), (4, n), (7, n), (8, n), (13, n), (16, n), (n, n), (4, 8), (3, 7), (5, 12)]
proofs = []
for first, second in pairs:
    path = subproof(first, [leaf(h) for h in hashes[:second]], True)
    proofs.append(
        {
            "first": first,
            "second": second,
            "first_root": root(hashes[:first]).hex(),
            "second_root": root(hashes[:second]).hex(),
            "path": [p.hex() for p in path],
        }
    )

out = {
    "$comment": (
        "Prefix-consistency companion vectors: the PALA-1 §4.3 tree over "
        "record hashes of the inference companion chain, in seq order, and "
        "RFC 6962 consistency paths between its prefixes (RFC 9162 §2.1.4.2 "
        "verification). Derived; nothing on the wire. test-vectors.json is "
        "frozen and untouched."
    ),
    "format": "pala-consistency-proof/1",
    "source": "profiles/inference-vectors.json",
    "source_chain_head": src["chain_head"],
    "records": n,
    "leaves": "record_hash of each record, seq order; leaf(d) = SHA-256(0x00 || d)",
    "roots_by_count": roots,
    "proofs": proofs,
    "negative": {
        "$comment": "each MUST verify False",
        "truncated_path": {**proofs[3], "path": proofs[3]["path"][:-1]},
        "wrong_first_root": {**proofs[3], "first_root": roots["6"]},
        "swapped_sizes": {**proofs[3], "first": proofs[3]["second"], "second": proofs[3]["first"]},
    },
}
OUT.write_text(json.dumps(out, indent=2) + "\n")
print(f"wrote {OUT.name}: {n} records, {len(proofs)} proofs, head {src['chain_head'][:16]}…")
