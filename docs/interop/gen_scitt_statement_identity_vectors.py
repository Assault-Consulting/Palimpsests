# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the SCITT statement identity vectors.

What to refer to a PALA-1 SCITT statement by, shown on the published
statements: ``statement_id`` is the SHA-256 of the statement with an
**empty unprotected header**, in the one encoding the verifier accepts.

Two things are shown. For each published statement, its id — which is the
hash of its bytes, because it is published with an empty unprotected
header. And the same statements with something in the unprotected header,
as a statement has after a transparency service attaches a receipt
(RFC 9943 puts receipts under label 394 there): other bytes, another
hash, the same signature, and **the same id**.

The published statements are read from their vectors, never re-typed, and
none of those files is touched. Nothing is signed here: the unprotected
header is outside the signature. The receipt is a placeholder, sixteen
bytes of text standing where one would be; no receipt is verified by
this package.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from palimpsests.audit.pala import scitt  # noqa: E402

V2 = json.loads((HERE / "scitt-statement-vector.json").read_text(encoding="utf-8"))
V3 = json.loads((HERE / "scitt-statement-vector-v3.json").read_text(encoding="utf-8"))
A19 = json.loads((HERE / "scitt-statement-vector-alg19.json").read_text(encoding="utf-8"))
OUT = HERE / "scitt-statement-identity-vectors.json"

PUBLIC = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(V2["key"]["public_key_hex"]))
LATER = V3["statements"]["later"]
BASES = {
    "v2": ("scitt-statement-vector.json, expected.statement_hex",
           bytes.fromhex(V2["expected"]["statement_hex"]),
           bytes.fromhex(V2["subject_chain"]["chain_head_hex"])),
    "v3": ("scitt-statement-vector-v3.json, statements.later.expected.statement_hex",
           bytes.fromhex(LATER["expected"]["statement_hex"]),
           bytes.fromhex(LATER["inputs"]["chain_head_hex"])),
    "v2-alg19": ("scitt-statement-vector-alg19.json, statements.v2.expected.statement_hex",
                 bytes.fromhex(A19["statements"]["v2"]["expected"]["statement_hex"]),
                 bytes.fromhex(A19["statements"]["v2"]["inputs"]["chain_head_hex"])),
}
RECEIPT = b"not a receipt..."
assert len(RECEIPT) == 16


def with_unprotected(statement: bytes, header: dict | bytes) -> bytes:
    """The statement with this unprotected header: a map, or the header's
    own bytes where the case is about how it is written."""
    protected, _empty, payload, sig = cbor2.loads(statement).value
    encoded = header if isinstance(header, bytes) else cbor2.dumps(header, canonical=True)
    return (b"\xd2\x84" + cbor2.dumps(protected) + encoded + cbor2.dumps(payload)
            + cbor2.dumps(sig))


published, carrying = [], []
for name, (source, statement, head) in BASES.items():
    check = scitt.verify_statement(statement, PUBLIC, head)
    sha = hashlib.sha256(statement).digest()
    assert check.statement_id == sha  # published with an empty unprotected header
    published.append({
        "base": name, "source": source,
        "statement_sha256": sha.hex(), "statement_id": check.statement_id.hex(),
        "expected_head_hex": head.hex(),
    })

kid = cbor2.loads(cbor2.loads(BASES["v2-alg19"][1]).value[0])[4]
for name, change, header in [
    ("v2", "the unprotected header holds a receipt placeholder under label 394: "
           "{394: [h'6e6f74206120726563656970742e2e2e']}", {394: [RECEIPT]}),
    ("v3", "the same, on the v3 statement", {394: [RECEIPT]}),
    ("v2", "two placeholders under label 394", {394: [RECEIPT, RECEIPT[::-1]]}),
    ("v2-alg19", "the unprotected header repeats the key id under label 4", {4: kid}),
    ("v2", "the unprotected header holds a private label: {99: 'note'}", {99: "note"}),
    ("v2", "the unprotected header is empty, its count written in two bytes (b8 00): "
           "the header's own encoding is not judged", b"\xb8\x00"),
    ("v2", "labels 99 and 4 in that order, and the placeholder array of label 394 with "
           "an indefinite length: another party's encoder, not judged",
     b"\xa3\x18\x63\x61x\x04\x41k\x19\x01\x8a\x9f\x50" + RECEIPT + b"\xff"),
]:
    source, statement, head = BASES[name]
    changed = with_unprotected(statement, header)
    check = scitt.verify_statement(changed, PUBLIC, head)
    assert changed != statement
    assert check.statement_id == hashlib.sha256(statement).digest()
    carrying.append({
        "id": f"carrying-{len(carrying) + 1:02d}", "base": name, "change": change,
        "statement_hex": changed.hex(),
        "statement_sha256": hashlib.sha256(changed).hexdigest(),
        "statement_id": check.statement_id.hex(),
        "expected_head_hex": head.hex(),
        "verifies": True,
    })

doc = {
    "format": "pala-1 scitt-bridge statement identity vectors",
    "purpose": (
        "What to refer to a PALA-1 SCITT statement by. statement_id is the SHA-256 of "
        "the statement with an empty unprotected header, in the one encoding a "
        "verifier accepts. Real crypto, fake entropy - never use this key outside a "
        "test vector."),
    "rule": [
        "A verifier accepts one encoding of a statement: tag 18 as the byte d2, a "
        "definite array of four (84), each byte string with its shortest definite "
        "length, and the protected header and the payload in the deterministic "
        "encoding of RFC 8949 section 4.2.1.",
        "The unprotected header is a map of a definite length with no label twice. "
        "What it holds, and how that is written, is not restricted: it is not signed, "
        "and a transparency service writes its receipts there with its own encoder.",
        "statement_id = SHA-256( d2 84 || bstr(protected) || a0 || bstr(payload) || "
        "bstr(signature) ): the statement with the unprotected header emptied.",
        "A statement whose unprotected header is the one byte a0 has statement_id equal "
        "to the SHA-256 of its bytes. A receipt attached later (RFC 9943, label 394, "
        "in the unprotected header) changes the bytes and their hash and leaves "
        "statement_id as it was.",
        "statement_id names the signed statement, not its content: the same payload "
        "signed twice with a non-deterministic algorithm is two statements.",
    ],
    "key": {"public_key_hex": V2["key"]["public_key_hex"], "source": V2["key"]["source"]},
    "published": published,
    "carrying_an_unprotected_header": carrying,
    "receipt_placeholder": (
        "The 16 bytes under label 394 are the text 'not a receipt...'. They stand where "
        "a receipt would be; nothing here is a receipt and none is verified."),
    "refused": (
        "Other writings of the signed parts and the envelope - a longer tag or length, "
        "an indefinite length - and an unprotected header that is not such a map are "
        "refused, and are in "
        "scitt-statement-refusal-vectors.json under non_deterministic_encoding and "
        "unprotected_header_malformed."),
}
OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"wrote {OUT.name}: {len(published)} published, {len(carrying)} carrying")
