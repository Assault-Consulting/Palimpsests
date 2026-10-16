# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the SCITT statement vector, construction v3.

Two v3 statements over the published core-vector chain — one over its
first 8 records, one over all 12 — and the prefix-consistency proof
between their roots. Together they are the case v3 exists for: a holder
of the two statements and the proof, with no chain at all, checks the
signatures, reads the roots the signatures cover, and verifies that the
later state extends the earlier one.

Inputs are reused from the v2 vector (same RFC 8032 test key, issuer,
kid, chain), never re-typed. The roots are computed by the CC0 reference
implementation (``palaudit_ref.merkle_root``), not by the package; the
statements are built by the package, which is what the vector pins. An
independent reproduction of the statement bytes is a separate run.

The v2 vector (``scitt-statement-vector.json``) is not touched: the
published draft and run B2 cite it.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "docs" / "specs" / "pala-1"))
import palaudit_ref as R  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from palimpsests.audit.pala import scitt  # noqa: E402
from palimpsests.audit.pala.merkle import consistency_proof  # noqa: E402

V2 = json.loads((HERE / "scitt-statement-vector.json").read_text(encoding="utf-8"))
CORE = json.loads((ROOT / "docs" / "specs" / "pala-1" / "test-vectors.json").read_text())
OUT = HERE / "scitt-statement-vector-v3.json"

headers = [bytes.fromhex(r["header_hex"]) for r in CORE["records"]]
hashes = [R.record_hash(h) for h in headers]
assert len(hashes) == 12 and hashes[-1].hex() == V2["subject_chain"]["chain_head_hex"]

key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V2["key"]["private_seed_hex"]))
issuer = V2["statement_inputs"]["issuer"]


def statement(count: int, first_seq: int) -> dict:
    head = hashes[count - 1]
    root = R.merkle_root(hashes[:count])  # always over the prefix 0..last_seq
    subject = f"pala-1:chain:{head.hex()}"
    stmt = scitt.build_signed_statement(
        head, first_seq=first_seq, last_seq=count - 1, key=key,
        issuer=issuer, subject=subject, alg=scitt.ALG_EDDSA, root=root,
    )
    return {
        "inputs": {
            "chain_head_hex": head.hex(),
            "first_seq": first_seq,
            "last_seq": count - 1,
            "subject": subject,
            "root_hex": root.hex(),
            "root_covers": f"records 0..{count - 1} (the {count}-record prefix)",
        },
        "expected": {
            "statement_hex": stmt.hex(),
            "statement_sha256": hashlib.sha256(stmt).hexdigest(),
            "statement_length_bytes": len(stmt),
        },
    }


earlier = statement(8, 0)
later = statement(12, 8)  # reports records 8..11; its root still covers 0..11
path = consistency_proof(hashes, 8)

doc = {
    "format": "pala-1 scitt-bridge statement vector, construction v3",
    "relation_to_v2": (
        "v2 (scitt-statement-vector.json) is unchanged and remains valid. v3 adds payload "
        "key 5, the derived root over records 0..last_seq, and is named by its own content "
        "type in the protected header, so a v2 verifier - which requires exactly keys 1-4 - "
        "rejects a v3 statement by type rather than misreading it."
    ),
    "purpose": (
        "Two v3 statements of one chain and the prefix-consistency proof between their "
        "roots. A holder of these three artifacts and no chain verifies both signatures, "
        "reads the two roots the signatures cover, and verifies that the 12-record state "
        "extends the 8-record state - the check v2 statements cannot support, because they "
        "carry heads and the proof connects roots. Real crypto, fake entropy - never use "
        "this key outside a test vector."
    ),
    "key": V2["key"],
    "subject_chain": {
        "source": V2["subject_chain"]["source"],
        "record_hashes_hex": [h.hex() for h in hashes],
        "note": "record_hash of each core-vector record, seq order - the leaves of the tree",
    },
    "construction": {
        "content_type": scitt.CONTENT_TYPE_V3,
        "content_type_note": (
            "protected header label 3; the v2 type is " + scitt.CONTENT_TYPE + ". A root "
            "under the v2 type, or the v3 type without a root, MUST be refused."
        ),
        "payload": (
            "attached CBOR map: {1: chain head (32 bytes), 2: first_seq, 3: last_seq, "
            "4: 'pala-1/v1.0', 5: derived root (32 bytes)}"
        ),
        "root_rule": (
            "key 5 is the PALA-1 section 4.3 tree over the record hashes of records "
            "0..last_seq in seq order (consistency-proof.md section 1): leaf(d) = "
            "SHA-256(0x00 || d), node(l, r) = SHA-256(0x01 || l || r), an unpaired node "
            "promoted, never duplicated. ALWAYS from record 0 - it does not depend on "
            "first_seq: the later statement here reports records 8..11 (first_seq = 8) and "
            "its root covers 0..11. A root over first_seq..last_seq would connect to nothing."
        ),
        "issuer": issuer,
        "kid_hex": V2["statement_inputs"]["kid_hex"],
        "everything_else": "exactly as v2: key, kid derivation, CWT claims, header order, tag 18",
    },
    "statements": {"earlier": earlier, "later": later},
    "consistency": {
        "format": "pala-consistency-proof/1",
        "first": 8,
        "second": 12,
        "first_root": earlier["inputs"]["root_hex"],
        "second_root": later["inputs"]["root_hex"],
        "path": [p.hex() for p in path],
        "verification": "RFC 9162 section 2.1.4.2 with the roots read from the two statements",
    },
    "tamper_expectations": [
        "flip any bit of the root inside a statement's payload: signature verification "
        "MUST fail (the payload is signed)",
        "a root that is not the derived root over 0..last_seq of the chain: a verifier "
        "holding the chain MUST reject it",
        "a root computed over first_seq..last_seq (here 8..11) instead of the prefix: "
        "MUST be rejected against the chain, and does not verify in the consistency proof",
        "a root over last_seq or last_seq + 2 records instead of last_seq + 1: MUST be "
        "rejected against the chain",
        "the v3 content type with no key 5, or key 5 under the v2 content type: MUST be "
        "refused, whatever the signature says",
        "drop the last node of the consistency path, or swap the two roots: the proof "
        "MUST NOT verify",
        "without the chain, a verifier reports the root as carried, not recomputed - "
        "never as verified",
    ],
}
OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
print(f"wrote {OUT.name}: earlier {earlier['expected']['statement_length_bytes']} B, "
      f"later {later['expected']['statement_length_bytes']} B, path {len(path)} nodes")
