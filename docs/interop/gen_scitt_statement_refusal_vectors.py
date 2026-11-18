# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the SCITT statement refusal vectors.

One file with a refused statement for every code of
``STATEMENT_REFUSAL_CODES``, so that another verifier can compare its
refusals with this one's without running this package. Each case is a
published statement with one change. It is refused by the first check
that the change breaks, in the order given under ``check_order``.

The published statements are read from the three existing vectors, never
re-typed: the v2 statement of ``scitt-statement-vector.json``, the later
v3 statement of ``scitt-statement-vector-v3.json`` (with its subject
chain) and the v2 statement under alg -19 of
``scitt-statement-vector-alg19.json``. None of those files is touched.
A changed statement is signed again with the same RFC 8032 test key, so
that a case fails on the check it is about and not on the signature.
Ed25519 is deterministic, so the file reproduces byte for byte.

The keys that are not the test key are derived from fixed labels, written
in the file, so they reproduce too.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519  # noqa: E402
from palimpsests.audit.pala import proofs, scitt  # noqa: E402
from palimpsests.audit.pala.frontier import MerkleFrontier  # noqa: E402

V2 = json.loads((HERE / "scitt-statement-vector.json").read_text(encoding="utf-8"))
V3 = json.loads((HERE / "scitt-statement-vector-v3.json").read_text(encoding="utf-8"))
A19 = json.loads((HERE / "scitt-statement-vector-alg19.json").read_text(encoding="utf-8"))
OUT = HERE / "scitt-statement-refusal-vectors.json"

KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V2["key"]["private_seed_hex"]))
LATER = V3["statements"]["later"]
HASHES = [bytes.fromhex(h) for h in V3["subject_chain"]["record_hashes_hex"]]

BASES = {
    "v2": {
        "source": "scitt-statement-vector.json, expected.statement_hex",
        "statement": bytes.fromhex(V2["expected"]["statement_hex"]),
        "head": bytes.fromhex(V2["subject_chain"]["chain_head_hex"]),
    },
    "v3": {
        "source": "scitt-statement-vector-v3.json, statements.later.expected.statement_hex",
        "statement": bytes.fromhex(LATER["expected"]["statement_hex"]),
        "head": bytes.fromhex(LATER["inputs"]["chain_head_hex"]),
    },
    "v2-alg19": {
        "source": "scitt-statement-vector-alg19.json, statements.v2.expected.statement_hex",
        "statement": bytes.fromhex(A19["statements"]["v2"]["expected"]["statement_hex"]),
        "head": bytes.fromhex(A19["statements"]["v2"]["inputs"]["chain_head_hex"]),
    },
}


# ── keys ───────────────────────────────────────────────────────────────────

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _scalar(label: str, curve: ec.EllipticCurve, digest) -> ec.EllipticCurvePrivateKey:
    value = int.from_bytes(digest(label.encode()).digest(), "big")
    return ec.derive_private_key(value, curve)


P256 = _scalar("pala-1 refusal vectors P-256", ec.SECP256R1(), hashlib.sha256).public_key()
P384 = _scalar("pala-1 refusal vectors P-384", ec.SECP384R1(), hashlib.sha384).public_key()
ED448 = ed448.Ed448PrivateKey.from_private_bytes(
    hashlib.shake_256(b"pala-1 refusal vectors Ed448").digest(57)).public_key()

KEYS = {"ed25519-test": KEY.public_key(), "p256": P256, "p384": P384, "ed448": ED448}


def _jwk(name: str) -> dict:
    key = KEYS[name]
    if isinstance(key, ed25519.Ed25519PublicKey):
        raw = key.public_bytes_raw()
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw),
                "source": V2["key"]["source"]}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"kty": "OKP", "crv": "Ed448", "x": _b64(key.public_bytes_raw()),
                "derivation": "private key = SHAKE-256('pala-1 refusal vectors Ed448'), "
                              "57 bytes"}
    nums = key.public_numbers()
    size = (key.curve.key_size + 7) // 8
    crv, hname = ("P-256", "SHA-256") if key.curve.name == "secp256r1" else ("P-384", "SHA-384")
    return {"kty": "EC", "crv": crv,
            "x": _b64(nums.x.to_bytes(size, "big")), "y": _b64(nums.y.to_bytes(size, "big")),
            "derivation": f"private scalar = {hname}('pala-1 refusal vectors {crv}') "
                          "as a big-endian integer"}


# ── building changed statements ────────────────────────────────────────────

def parts(message: bytes) -> tuple:
    return tuple(cbor2.loads(message).value)


def message(protected, unprotected, payload, sig) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, sig]))


def signed(protected: bytes, payload: bytes) -> bytes:
    """A COSE_Sign1 over exactly these bytes, signed with the test key."""
    return message(protected, {}, payload, KEY.sign(scitt._sig_structure(protected, payload)))


def with_payload(base: str, change) -> bytes:
    protected, _u, payload, _s = parts(BASES[base]["statement"])
    decoded = cbor2.loads(payload)
    change(decoded)
    return signed(protected, cbor2.dumps(decoded, canonical=True))


def with_protected(base: str, change) -> bytes:
    protected, _u, payload, _s = parts(BASES[base]["statement"])
    header = cbor2.loads(protected)
    change(header)
    return signed(cbor2.dumps(header, canonical=True), payload)


def one_more_entry(encoded_map: bytes, key, value) -> bytes:
    """The same map with one entry appended and its count raised by one —
    an entry whose key the map already has, for a repeated key."""
    assert 0xa0 <= encoded_map[0] < 0xb7  # a map of fewer than 23 entries
    return bytes([encoded_map[0] + 1]) + encoded_map[1:] + cbor2.dumps(key) + cbor2.dumps(value)


def v3_with(last_seq: int, root: bytes) -> bytes:
    """The later v3 statement, built again with this last_seq and root."""
    i = LATER["inputs"]
    return scitt.build_signed_statement(
        bytes.fromhex(i["chain_head_hex"]), first_seq=i["first_seq"], last_seq=last_seq,
        key=KEY, issuer=V2["statement_inputs"]["issuer"], subject=i["subject"],
        alg=scitt.ALG_EDDSA, root=root)


S2 = BASES["v2"]["statement"]
P, U, PL, SIG = parts(S2)
P3, _U3, PL3, _SIG3 = parts(BASES["v3"]["statement"])
LAST2 = cbor2.loads(PL)[3]


def relabelled_es256() -> bytes:
    """The v2 statement under alg -7, signed with the Ed25519 test key: a key
    check refuses it before the signature is read."""
    return with_protected("v2", lambda h: h.__setitem__(1, scitt.ALG_ES256))


# (code, base, key, chain, change, statement)
CASES = [
    ("not_cose_sign1", None, "ed25519-test", False, "empty input", b""),
    ("not_cose_sign1", None, "ed25519-test", False, "five bytes of text, 'hello'", b"hello"),
    ("not_cose_sign1", "v2", "ed25519-test", False,
     "the first 20 bytes of the statement", S2[:20]),
    ("not_cose_sign1", None, "ed25519-test", False, "the CBOR integer 5", cbor2.dumps(5)),
    ("not_cose_sign1", "v2", "ed25519-test", False,
     "the four members as an untagged array", cbor2.dumps([P, U, PL, SIG])),
    ("not_cose_sign1", None, "ed25519-test", False,
     "tag 18 around the integer 5", cbor2.dumps(cbor2.CBORTag(18, 5))),
    ("not_cose_sign1", "v2", "ed25519-test", False,
     "tag 18 around three members (no signature)",
     cbor2.dumps(cbor2.CBORTag(18, [P, U, PL]))),
    ("not_cose_sign1", "v2", "ed25519-test", False,
     "the four members under tag 17 (COSE_Mac0) instead of 18",
     cbor2.dumps(cbor2.CBORTag(17, [P, U, PL, SIG]))),
    ("trailing_bytes", "v2", "ed25519-test", False,
     "the statement followed by one zero byte", S2 + b"\x00"),
    ("trailing_bytes", "v2", "ed25519-test", False,
     "the statement followed by itself", S2 + S2),
    ("protected_header_malformed", "v2", "ed25519-test", False,
     "the protected header is the integer 5, not a byte string", message(5, U, PL, SIG)),
    ("protected_header_malformed", "v2", "ed25519-test", False,
     "the protected header is the bytes ff ff, not CBOR", message(b"\xff\xff", U, PL, SIG)),
    ("protected_header_malformed", "v2", "ed25519-test", False,
     "the protected header is empty", message(b"", U, PL, SIG)),
    ("protected_header_malformed", "v2", "ed25519-test", False,
     "the protected header encodes an array, not a map",
     message(cbor2.dumps([1]), U, PL, SIG)),
    ("protected_header_malformed", "v2", "ed25519-test", False,
     "the protected header map is followed by a zero byte, signed again",
     signed(P + b"\x00", PL)),
    ("detached_payload", "v2", "ed25519-test", False,
     "the payload is nil (detached)", message(P, U, None, SIG)),
    ("payload_malformed", "v2", "ed25519-test", False,
     "the payload is the bytes ff ff ff, signed", signed(P, b"\xff\xff\xff")),
    ("payload_malformed", "v2", "ed25519-test", False,
     "the payload is empty, signed", signed(P, b"")),
    ("payload_malformed", "v2", "ed25519-test", False,
     "the payload encodes an array, not a map, signed", signed(P, cbor2.dumps([1, 2]))),
    ("payload_malformed", "v2", "ed25519-test", False,
     "the payload map is followed by a zero byte, signed", signed(P, PL + b"\x00")),
    ("payload_malformed", "v2", "ed25519-test", False,
     "the payload is the integer 7, not a byte string", message(P, U, 7, SIG)),
    ("repeated_key", "v2", "ed25519-test", False,
     "the payload map repeats key 1, signed",
     signed(P, one_more_entry(PL, 1, BASES["v2"]["head"]))),
    ("repeated_key", "v2", "ed25519-test", False,
     "the protected header repeats label 1, signed",
     signed(one_more_entry(P, 1, scitt.ALG_EDDSA), PL)),
    ("indefinite_length_map", "v2", "ed25519-test", False,
     "the payload map has indefinite length, signed", signed(P, b"\xbf" + PL[1:] + b"\xff")),
    ("unsupported_alg", "v2", "ed25519-test", False,
     "alg is -35 (ES384), signed", with_protected("v2", lambda h: h.__setitem__(1, -35))),
    ("unsupported_alg", "v2", "ed25519-test", False,
     "alg is the text 'EdDSA', signed",
     with_protected("v2", lambda h: h.__setitem__(1, "EdDSA"))),
    ("unsupported_alg", "v2", "ed25519-test", False,
     "the protected header has no alg, signed", with_protected("v2", lambda h: h.pop(1))),
    ("unsupported_alg", "v2", "ed25519-test", False,
     "alg is the simple value true, signed",
     with_protected("v2", lambda h: h.__setitem__(1, True))),
    ("key_type_mismatch", "v2", "p256", False,
     "the published statement (alg -8) verified with a P-256 key", S2),
    ("key_type_mismatch", "v2", "p384", False,
     "the published statement (alg -8) verified with a P-384 key", S2),
    ("key_type_mismatch", "v2", "ed448", False,
     "the published statement (alg -8) verified with an Ed448 key", S2),
    ("key_type_mismatch", "v2-alg19", "p256", False,
     "the published statement under alg -19 verified with a P-256 key",
     BASES["v2-alg19"]["statement"]),
    ("key_type_mismatch", "v2-alg19", "p384", False,
     "the published statement under alg -19 verified with a P-384 key",
     BASES["v2-alg19"]["statement"]),
    ("key_type_mismatch", "v2-alg19", "ed448", False,
     "the published statement under alg -19 verified with an Ed448 key",
     BASES["v2-alg19"]["statement"]),
    ("key_type_mismatch", "v2", "ed25519-test", False,
     "the statement relabelled alg -7 (ES256) and signed with the Ed25519 test key, "
     "verified with that Ed25519 key", relabelled_es256()),
    ("key_type_mismatch", "v2", "p384", False,
     "the statement relabelled alg -7, verified with a P-384 key", relabelled_es256()),
    ("key_type_mismatch", "v2", "ed448", False,
     "the statement relabelled alg -7, verified with an Ed448 key", relabelled_es256()),
    ("signature_invalid", "v2", "ed25519-test", False,
     "the last signature byte with its low bit flipped",
     message(P, U, PL, SIG[:-1] + bytes([SIG[-1] ^ 1]))),
    ("signature_invalid", "v2", "ed25519-test", False,
     "the signature cut to its first 10 bytes", message(P, U, PL, SIG[:10])),
    ("signature_invalid", "v2", "ed25519-test", False,
     "the signature is the integer 7", message(P, U, PL, 7)),
    ("signature_invalid", "v2", "ed25519-test", False,
     "the last payload byte with its low bit flipped, signature unchanged",
     message(P, U, PL[:-1] + bytes([PL[-1] ^ 1]), SIG)),
    ("head_mismatch", "v2", "ed25519-test", False,
     "payload key 1 (chain head) is 32 bytes of 0x33, signed",
     with_payload("v2", lambda d: d.__setitem__(1, b"\x33" * 32))),
    ("format_id_mismatch", "v2", "ed25519-test", False,
     "payload key 4 is 'pala-1/v9', signed",
     with_payload("v2", lambda d: d.__setitem__(4, "pala-1/v9"))),
    ("range_invalid", "v2", "ed25519-test", False,
     "first_seq is last_seq + 1, signed",
     with_payload("v2", lambda d: d.__setitem__(2, LAST2 + 1))),
    ("range_invalid", "v2", "ed25519-test", False,
     "first_seq is -1, signed", with_payload("v2", lambda d: d.__setitem__(2, -1))),
    ("range_invalid", "v2", "ed25519-test", False,
     "last_seq is the text '11', signed",
     with_payload("v2", lambda d: d.__setitem__(3, str(LAST2)))),
    ("range_invalid", "v2", "ed25519-test", False,
     "last_seq is the simple value true, signed",
     with_payload("v2", lambda d: d.__setitem__(3, True))),
    ("content_type_unknown", "v2", "ed25519-test", False,
     "content type is 'application/x-other', signed",
     with_protected("v2", lambda h: h.__setitem__(3, "application/x-other"))),
    ("content_type_unknown", "v2", "ed25519-test", False,
     "the protected header has no content type, signed",
     with_protected("v2", lambda h: h.pop(3))),
    ("payload_keys_mismatch", "v2", "ed25519-test", False,
     "a 32-byte root in payload key 5 under the v2 content type, signed",
     with_payload("v2", lambda d: d.__setitem__(5, bytes.fromhex(LATER["inputs"]["root_hex"])))),
    ("payload_keys_mismatch", "v2", "ed25519-test", False,
     "an extra payload key 'note', signed",
     with_payload("v2", lambda d: d.__setitem__("note", 1))),
    ("payload_keys_mismatch", "v2", "ed25519-test", False,
     "the v2 statement relabelled with the v3 content type, so it has no root, signed",
     with_protected("v2", lambda h: h.__setitem__(3, scitt.CONTENT_TYPE_V3))),
    ("protected_labels_mismatch", "v2", "ed25519-test", False,
     "protected label 33 (x5chain) added, signed",
     with_protected("v2", lambda h: h.__setitem__(33, b"x5chain"))),
    ("protected_labels_mismatch", "v2", "ed25519-test", False,
     "the protected header has no kid (label 4), signed",
     with_protected("v2", lambda h: h.pop(4))),
    ("protected_labels_mismatch", "v3", "ed25519-test", False,
     "protected label 33 added to the v3 statement, signed",
     with_protected("v3", lambda h: h.__setitem__(33, b"x"))),
    ("protected_labels_mismatch", "v2", "ed25519-test", False,
     "a text label 'x5t' among the integer labels, signed",
     with_protected("v2", lambda h: h.__setitem__("x5t", b"x"))),
    ("root_malformed", "v3", "ed25519-test", False,
     "the v3 root (payload key 5) is the 5 bytes 'short', signed",
     signed(P3, cbor2.dumps({**cbor2.loads(PL3), 5: b"short"}, canonical=True))),
    ("root_malformed", "v3", "ed25519-test", False,
     "the v3 root is the text 'text', signed",
     signed(P3, cbor2.dumps({**cbor2.loads(PL3), 5: "text"}, canonical=True))),
    ("chain_too_short", "v3", "ed25519-test", True,
     "last_seq is 12 against the 12-record subject chain (records 0..11), with the root "
     "over all 12 records, signed",
     v3_with(len(HASHES), MerkleFrontier.from_record_hashes(HASHES).root())),
    ("root_mismatch", "v3", "ed25519-test", True,
     "the root over records 0..10 (one short) where 0..11 is required, signed",
     v3_with(len(HASHES) - 1, MerkleFrontier.from_record_hashes(HASHES[:-1]).root())),
    ("root_mismatch", "v3", "ed25519-test", True,
     "the root over records 8..11 (first_seq..last_seq) where 0..11 is required, signed",
     v3_with(len(HASHES) - 1, MerkleFrontier.from_record_hashes(HASHES[8:]).root())),
]


class _Chain:
    """What ``chain_root`` reads: the headers, in order. The subject chain is
    published as record hashes, so the reader is an object whose headers are
    those hashes."""

    def __init__(self, record_hashes: list[bytes]) -> None:
        self._headers = record_hashes


def _self_check(code: str, base: str | None, key: str, chain: bool, stmt: bytes) -> None:
    head = BASES[base or "v2"]["head"]
    saved = proofs._record_hash
    proofs._record_hash = lambda h: h  # the chain's headers ARE its record hashes here
    try:
        scitt.verify_statement(stmt, KEYS[key], head, reader=_Chain(HASHES) if chain else None)
    except scitt.StatementRefused as e:
        assert e.code == code, (code, e.code, str(e))
        return
    finally:
        proofs._record_hash = saved
    raise AssertionError(f"{code}: accepted")


# The published statements themselves verify: the bases are valid.
for b in BASES.values():
    scitt.verify_statement(b["statement"], KEY.public_key(), b["head"])

cases, numbers = [], Counter()
for code, base, key, chain, change, stmt in CASES:
    _self_check(code, base, key, chain, stmt)
    numbers[code] += 1
    cases.append({
        "id": f"{code}-{numbers[code]:02d}",
        "code": code,
        "base": base,
        "change": change,
        "statement_hex": stmt.hex(),
        "statement_sha256": hashlib.sha256(stmt).hexdigest(),
        "verify_with": {
            "key": key,
            "expected_head_hex": BASES[base or "v2"]["head"].hex(),
            "chain": "subject_chain" if chain else None,
        },
    })
missing = set(scitt.STATEMENT_REFUSAL_CODES) ^ set(numbers)
assert not missing, missing  # every code has a case, and no case has another code

doc = {
    "format": "pala-1 scitt-bridge statement refusal vectors",
    "purpose": (
        "A refused statement for every code a verifier of the PALA-1 SCITT statement "
        "refuses with, so that another verifier can compare its refusals with this "
        "one's. Each case is a published statement with one change, refused by the "
        "first check the change breaks. Real crypto, fake entropy - never use these "
        "keys outside a test vector."),
    "relation_to_the_other_vectors": (
        "The bases are the published statements of scitt-statement-vector.json, "
        "scitt-statement-vector-v3.json and scitt-statement-vector-alg19.json, which "
        "verify and are unchanged. A changed statement is signed again with their test "
        "key, so it fails on the check it is about and not on the signature, unless the "
        "signature is what the case is about."),
    "codes": sorted(scitt.STATEMENT_REFUSAL_CODES),
    "codes_note": (
        "An open vocabulary: a release may add a code, never rename one or give it "
        "another meaning. The code names the check that failed, never a cause."),
    "check_order": [
        "message structure: not_cose_sign1, trailing_bytes, protected_header_malformed "
        "(with repeated_key in the protected header), detached_payload, payload_malformed "
        "for a payload that is not a byte string",
        "unsupported_alg (label 1 is -7, -8 or -19)",
        "key_type_mismatch (-8 and -19 mean Ed25519, -7 means P-256), before any signature",
        "signature_invalid",
        "the payload as CBOR: payload_malformed, repeated_key, indefinite_length_map",
        "head_mismatch",
        "format_id_mismatch",
        "range_invalid (0 <= first_seq <= last_seq, both integers)",
        "by the protected content type: v2 - payload_keys_mismatch, then "
        "protected_labels_mismatch; v3 - payload_keys_mismatch, root_malformed, then "
        "protected_labels_mismatch; any other - content_type_unknown",
        "with a chain at hand: chain_too_short, then root_mismatch",
    ],
    "keys": {name: _jwk(name) for name in KEYS},
    "bases": {name: {"source": b["source"],
                     "statement_sha256": hashlib.sha256(b["statement"]).hexdigest(),
                     "expected_head_hex": b["head"].hex()}
              for name, b in BASES.items()},
    "subject_chain": {
        "source": "scitt-statement-vector-v3.json, subject_chain.record_hashes_hex",
        "records": len(HASHES),
        "use": (
            "a case with verify_with.chain set is verified against this chain: the v3 "
            "root is recomputed as the PALA-1 section 4.3 tree over the record hashes of "
            "records 0..last_seq"),
    },
    "counts": {"cases": len(cases), **dict(sorted(numbers.items()))},
    "not_in_this_file": [
        "inputs that are not bytes (a text string or nil handed to the verifier as the "
        "message) and keys that are not public keys (a private key, nil, a string): "
        "they depend on a language's types and stay in this package's test suite",
        "an expected head of the wrong kind (text, nil, an empty byte string): refused "
        "as head_mismatch in the test suite",
        "ES256 statements that verify: an ECDSA signature does not reproduce byte for "
        "byte",
    ],
    "cases": cases,
}
OUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"wrote {OUT.name}: {len(cases)} cases, {len(numbers)} codes")
