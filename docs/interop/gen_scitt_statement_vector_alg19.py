# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the SCITT statement vector for COSE alg -19 (Ed25519, RFC 9864).

The two published statements — the v2 statement of
``scitt-statement-vector.json`` and the later v3 statement of
``scitt-statement-vector-v3.json`` — built again from the same inputs with
one thing changed: the protected header's ``alg`` is ``-19`` where it was
``-8``. Same RFC 8032 test key, same issuer and subject, same payloads.

What the pair shows, and what the vector states so a reader can check it
without this package: the payload bytes are identical; the ``kid`` is
identical, because a thumbprint is of the key and not of the algorithm;
the protected header differs in exactly one byte (``0x27``, the encoding of
-8, becomes ``0x32``, the encoding of -19); and the signature differs,
because the protected header is signed.

Inputs are read from the two existing vectors, never re-typed. Neither of
those files is touched.
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
OUT = HERE / "scitt-statement-vector-alg19.json"

key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V2["key"]["private_seed_hex"]))
issuer = V2["statement_inputs"]["issuer"]


def parts(message: bytes) -> tuple[bytes, bytes, bytes]:
    protected, _unprotected, payload, signature = cbor2.loads(message).value
    return protected, payload, signature


def pair(name: str, published_hex: str, inputs: dict, root_hex: str | None) -> dict:
    """The published -8 statement beside the same statement under -19."""
    published = bytes.fromhex(published_hex)
    args = {
        "first_seq": inputs["first_seq"], "last_seq": inputs["last_seq"], "key": key,
        "issuer": issuer, "subject": inputs["subject"],
        "root": bytes.fromhex(root_hex) if root_hex else None,
    }
    head = bytes.fromhex(inputs["chain_head_hex"])
    # the package must still build the published bytes under -8, or the
    # comparison below is between two things this generator made up
    assert scitt.build_signed_statement(head, alg=scitt.ALG_EDDSA, **args) == published, name
    stmt = scitt.build_signed_statement(head, alg=scitt.ALG_ED25519, **args)

    p8, pl8, sig8 = parts(published)
    p19, pl19, sig19 = parts(stmt)
    differing = [i for i, (a, b) in enumerate(zip(p8, p19, strict=True)) if a != b]
    assert pl8 == pl19 and sig8 != sig19 and len(differing) == 1
    assert (p8[differing[0]], p19[differing[0]]) == (0x27, 0x32)
    assert cbor2.loads(p8)[4] == cbor2.loads(p19)[4]  # kid

    return {
        "inputs": {**inputs, **({"root_hex": root_hex} if root_hex else {})},
        "published_under_alg_minus_8": {
            "source": ("scitt-statement-vector.json" if root_hex is None
                       else "scitt-statement-vector-v3.json, statements.later"),
            "statement_sha256": hashlib.sha256(published).hexdigest(),
        },
        "expected": {
            "statement_hex": stmt.hex(),
            "statement_sha256": hashlib.sha256(stmt).hexdigest(),
            "statement_length_bytes": len(stmt),
            "protected_hex": p19.hex(),
            "payload_hex": pl19.hex(),
            "signature_hex": sig19.hex(),
            "verifies_with_public_key": True,
        },
        "against_the_published_statement": {
            "payload": "identical bytes",
            "kid": "identical",
            "protected_header": (
                f"identical but for byte {differing[0]}: 0x27 (alg -8) there, "
                "0x32 (alg -19) here"),
            "signature": "different - the protected header is signed",
            "length": "identical",
        },
    }


later = V3["statements"]["later"]
doc = {
    "format": "pala-1 scitt-bridge statement vector, COSE alg -19",
    "purpose": (
        "The published v2 statement and the later published v3 statement, each built "
        "again with COSE alg -19 (Ed25519, RFC 9864) in place of -8 (EdDSA). Nothing "
        "else changes. A verifier that admits -19 accepts these with the same public "
        "key; one that admits only -7 and -8 refuses them as an unsupported algorithm "
        "and reads nothing - that is the compatibility, and it runs one way. Real "
        "crypto, fake entropy - never use this key outside a test vector."),
    "relation_to_the_other_vectors": (
        "scitt-statement-vector.json and scitt-statement-vector-v3.json are unchanged "
        "and remain valid. -19 is not a new construction: the content types, the "
        "payloads and the protected header's labels are those of v2 and v3. What is "
        "extended is the set of values label 1 (alg) may take, from {-7, -8} to "
        "{-7, -8, -19}."),
    "key": {
        "alg": "Ed25519, COSE alg -19 (RFC 9864); the same key the other vectors sign "
               "with under alg -8",
        "source": V2["key"]["source"],
        "private_seed_hex": V2["key"]["private_seed_hex"],
        "public_key_hex": V2["key"]["public_key_hex"],
        "kid_hex": V2["statement_inputs"]["kid_hex"],
        "kid_note": (
            "RFC 9679 thumbprint of the key: kty, crv and x - not alg. The same under "
            "-8 and -19, so a signer that changes identifier keeps its kid."),
    },
    "rules": {
        "alg_values": "label 1 is -7, -8 or -19; any other value MUST be refused",
        "key_type": (
            "-8 and -19 both mean Ed25519 here. A verifier MUST refuse a key that is "
            "not Ed25519 under either - Ed448 in particular, which -8 as a family name "
            "would otherwise admit - and MUST refuse a key that is not P-256 under -7"),
        "what_alg_changes": (
            "one signed byte of the protected header. The Sig_structure, the "
            "signature algorithm and the verification are those of -8"),
        "byte_stability": (
            "Ed25519 is deterministic (RFC 8032), so these statements reproduce byte "
            "for byte, like the -8 ones"),
    },
    "statements": {
        "v2": pair(
            "v2", V2["expected"]["statement_hex"],
            {"chain_head_hex": V2["subject_chain"]["chain_head_hex"],
             "first_seq": V2["subject_chain"]["first_seq"],
             "last_seq": V2["subject_chain"]["last_seq"],
             "subject": V2["statement_inputs"]["subject"]},
            None),
        "v3": pair(
            "v3", later["expected"]["statement_hex"],
            {k: later["inputs"][k]
             for k in ("chain_head_hex", "first_seq", "last_seq", "subject")},
            later["inputs"]["root_hex"]),
    },
    "tamper_expectations": [
        "set the alg byte of the protected header back to 0x27 (-8) and keep the "
        "signature: verification MUST fail - the protected header is signed, so a "
        "statement cannot be relabelled from one identifier to the other",
        "verify with an Ed448 public key: MUST be refused before any signature check - "
        "the key is not of the type -19 means",
        "every tamper expectation of the -8 vectors holds unchanged",
    ],
}
OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"wrote {OUT.name}: v2 {doc['statements']['v2']['expected']['statement_sha256'][:16]}… "
      f"v3 {doc['statements']['v3']['expected']['statement_sha256'][:16]}…")
