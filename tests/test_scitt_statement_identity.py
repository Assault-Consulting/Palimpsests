# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""One encoding of a statement, and a name for it.

Measured before the rule: ``verify_statement`` accepted every re-encoding
of a published statement that left the signed bytes alone — a longer tag,
a longer array head, longer or chunked byte strings, any unprotected
header at all, a map or not. One Sig_structure, one valid signature, and
tens of thousands of distinct SHA-256 values. None is a forgery: the signed
content is the same. But "this is that statement" was not something the
verifier said or checked, and a reference by digest, a deduplication or a
transparency log's leaf held only until the next party touched the bytes.

Since 0.15 one encoding of the signed parts and of the envelope is
accepted, and ``StatementCheck.statement_id`` is the hash to refer to a
statement by. The unprotected header is held only to what RFC 9052 says
it is — a map — with a definite length, no label twice and its count in
the shortest form: a transparency service writes its receipts there with
its own encoder, nothing in it is signed, and it is outside the id.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import pytest
import random
import shutil
import subprocess
import sys
from pathlib import Path

cbor2 = pytest.importorskip("cbor2")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from palimpsests.audit.pala import scitt  # noqa: E402

INTEROP = Path(__file__).resolve().parent.parent / "docs" / "interop"
VECTOR = INTEROP / "scitt-statement-identity-vectors.json"
INPUTS = ("scitt-statement-vector.json", "scitt-statement-vector-v3.json",
          "scitt-statement-vector-alg19.json")


def _load(name):
    return json.loads((INTEROP / name).read_text(encoding="utf-8"))


V2, V3, A19 = (_load(n) for n in INPUTS)
SEED = bytes.fromhex(V2["key"]["private_seed_hex"])
KEY = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
PUB = KEY.public_key()
PUBLISHED = {
    "v2": (bytes.fromhex(V2["expected"]["statement_hex"]),
           bytes.fromhex(V2["subject_chain"]["chain_head_hex"])),
    "v3": (bytes.fromhex(V3["statements"]["later"]["expected"]["statement_hex"]),
           bytes.fromhex(V3["statements"]["later"]["inputs"]["chain_head_hex"])),
    "v2-alg19": (bytes.fromhex(A19["statements"]["v2"]["expected"]["statement_hex"]),
                 bytes.fromhex(A19["statements"]["v2"]["inputs"]["chain_head_hex"])),
}


def _code(message, head, key=PUB):
    with pytest.raises(scitt.StatementRefused) as info:
        scitt.verify_statement(message, key, head)
    return info.value.code


def _bstr_forms(data: bytes) -> list[bytes]:
    """Every way tried here to write one byte string: the shortest first."""
    n = len(data)
    forms = [cbor2.dumps(data)]
    for lead, width in ((0x58, 1), (0x59, 2), (0x5A, 4), (0x5B, 8)):
        form = bytes([lead]) + n.to_bytes(width, "big") + data
        if form not in forms and n < 1 << (8 * width):
            forms.append(form)
    half = n // 2
    forms.append(b"\x5f" + cbor2.dumps(data[:half]) + cbor2.dumps(data[half:]) + b"\xff")
    return forms


TAGS = [b"\xd2", b"\xd8\x12", b"\xd9\x00\x12", b"\xda\x00\x00\x00\x12",
        b"\xdb" + (18).to_bytes(8, "big")]
ARRAYS = [(b"\x84", b""), (b"\x98\x04", b""), (b"\x99\x00\x04", b""),
          (b"\x9a\x00\x00\x00\x04", b""), (b"\x9f", b"\xff")]
#: An empty map written four ways. Only the first is accepted as a
#: header: the next two write its count longer than it needs, the last
#: gives it no count at all.
EMPTY_MAPS = [b"\xa0", b"\xb8\x00", b"\xb9\x00\x00", b"\xbf\xff"]
NOT_MAPS = [b"\x07", b"\x80", b"\x40", b"\x60", b"\xf6", b"\xf5", b"\xc1\x00"]
HEADERS = EMPTY_MAPS + NOT_MAPS


# -- the published statements and their ids ------------------------------------

@pytest.mark.parametrize("name", PUBLISHED)
def test_a_published_statement_verifies_and_its_id_is_the_hash_of_its_bytes(name):
    statement, head = PUBLISHED[name]
    check = scitt.verify_statement(statement, PUB, head)
    assert check.statement_id == hashlib.sha256(statement).digest()
    assert len(check.statement_id) == 32 and check.payload_encoding == "deterministic"


def test_what_the_package_builds_is_the_one_encoding():
    head = b"\x5a" * 32
    for alg in (scitt.ALG_EDDSA, scitt.ALG_ED25519):
        for root in (None, b"\x11" * 32):
            s = scitt.build_signed_statement(head, first_seq=0, last_seq=9, key=KEY,
                                             issuer="i", subject="s", alg=alg, root=root)
            assert scitt.verify_statement(s, PUB, head).statement_id == hashlib.sha256(
                s).digest()
    es = ec.generate_private_key(ec.SECP256R1())
    s = scitt.build_signed_statement(head, first_seq=0, last_seq=9, key=es, issuer="i",
                                     subject="s", alg=scitt.ALG_ES256)
    assert scitt.verify_statement(s, es.public_key(), head).statement_id == hashlib.sha256(
        s).digest()


def test_the_id_names_the_signed_statement_not_its_content():
    """ES256 is not deterministic: the same payload signed twice is two
    statements. That is what the id says, and what the docs say it says."""
    head = b"\x5a" * 32
    es = ec.generate_private_key(ec.SECP256R1())
    a, b = (scitt.build_signed_statement(head, first_seq=0, last_seq=9, key=es, issuer="i",
                                         subject="s", alg=scitt.ALG_ES256) for _ in "ab")
    ia, ib = (scitt.verify_statement(s, es.public_key(), head) for s in (a, b))
    assert ia.payload == ib.payload and ia.statement_id != ib.statement_id


# -- every other writing of the same statement is refused -----------------------

@pytest.mark.parametrize("name", PUBLISHED)
def test_every_re_encoding_that_needs_no_key_is_refused(name):
    """The product of the freedoms a relay has: the tag, the array head,
    each of the three byte-string heads, and the unprotected header. All
    34 375 were accepted before the rule. One is now: the published
    statement."""
    statement, head = PUBLISHED[name]
    protected, _u, payload, sig = cbor2.loads(statement).value
    forms = [_bstr_forms(x) for x in (protected, payload, sig)]
    assert [len(f) for f in forms] == [5, 5, 5]
    accepted, refused, hashes = [], {}, set()
    for tag, (array, end), p, u, pl, s in itertools.product(
            TAGS, ARRAYS, forms[0], HEADERS, forms[1], forms[2]):
        message = tag + array + p + u + pl + s + end
        hashes.add(hashlib.sha256(message).digest())
        try:
            check = scitt.verify_statement(message, PUB, head)
            accepted.append((message, check.statement_id))
        except scitt.StatementRefused as e:
            refused[e.code] = refused.get(e.code, 0) + 1
    total = 5 * 5 * 5 * len(HEADERS) * 5 * 5
    assert len(hashes) == total == 34_375  # every one a different byte string
    prefix, suffix = statement[:2 + len(forms[0][0])], statement[3 + len(forms[0][0]):]
    assert prefix + EMPTY_MAPS[0] + suffix == statement
    assert accepted == [(statement, hashlib.sha256(statement).digest())]
    assert set(refused) == {"non_deterministic_encoding", "unprotected_header_malformed"}
    assert sum(refused.values()) == total - 1
    # the header is judged first: 8 of its 11 forms are refused by name
    assert refused["unprotected_header_malformed"] == total // 11 * 8


@pytest.mark.parametrize("name", PUBLISHED)
def test_every_re_encoding_was_accepted_by_a_lenient_decoder(name):
    """What makes the rule necessary: a stock CBOR decoder reads every one
    of these as the same four members and repairs the difference silently."""
    statement, _head = PUBLISHED[name]
    members = cbor2.loads(statement).value
    protected, _u, payload, sig = members
    for tag, (array, end) in itertools.product(TAGS, ARRAYS):
        message = (tag + array + _bstr_forms(protected)[-1] + b"\xbf\xff"
                   + _bstr_forms(payload)[1] + _bstr_forms(sig)[-1] + end)
        decoded = cbor2.loads(message)
        assert decoded.tag == 18 and list(decoded.value) == list(members)


def _resigned(protected: bytes, payload: bytes) -> bytes:
    sig = KEY.sign(scitt._sig_structure(protected, payload))
    return b"\xd2\x84" + cbor2.dumps(protected) + b"\xa0" + cbor2.dumps(payload) + cbor2.dumps(sig)


@pytest.mark.parametrize("name", PUBLISHED)
def test_an_issuers_own_other_encoding_is_refused_too(name):
    statement, head = PUBLISHED[name]
    protected, _u, payload, _sig = cbor2.loads(statement).value
    assert _resigned(protected, payload) == statement  # Ed25519: the same bytes again
    for part in ("protected", "payload"):
        original = protected if part == "protected" else payload
        values = cbor2.loads(original)
        reordered = cbor2.dumps(dict(reversed(list(values.items()))))
        longer_key = original[:1] + b"\x18" + original[1:]  # the first key in two bytes
        assert cbor2.loads(longer_key) == values and reordered != original
        for other in (reordered, longer_key):
            message = (_resigned(other, payload) if part == "protected"
                       else _resigned(protected, other))
            assert _code(message, head) == "non_deterministic_encoding", part


def test_a_check_that_names_what_is_wrong_is_reached_first():
    """A repeated key and an indefinite-length map are also not the
    deterministic encoding. They keep the codes they had."""
    statement, head = PUBLISHED["v2"]
    protected, _u, payload, _sig = cbor2.loads(statement).value
    repeated = b"\xa5" + payload[1:] + cbor2.dumps(1) + cbor2.dumps(head)
    assert _code(_resigned(protected, repeated), head) == "repeated_key"
    indefinite = b"\xbf" + payload[1:] + b"\xff"
    assert _code(_resigned(protected, indefinite), head) == "indefinite_length_map"
    assert _code(_resigned(b"\xbf" + protected[1:] + b"\xff", payload),
                 head) == "indefinite_length_map"
    assert _code(statement + b"\x00", head) == "trailing_bytes"
    assert _code(b"\xd8\x11" + statement[1:], head) == "not_cose_sign1"  # tag 17


def test_a_wrong_signature_in_another_encoding_is_refused_for_the_encoding():
    """The encoding of the envelope is judged before the signature, so the
    code depends on the bytes alone, not on which key the verifier holds."""
    statement, head = PUBLISHED["v2"]
    other = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x07" * 32).public_key()
    assert _code(b"\xd8\x12" + statement[1:], head, other) == "non_deterministic_encoding"
    assert _code(statement, head, other) == "signature_invalid"


def test_a_fourth_member_that_is_not_a_byte_string_is_left_to_the_signature_check():
    statement, head = PUBLISHED["v2"]
    protected, _u, payload, _sig = cbor2.loads(statement).value
    for sig in (b"\x07", b"\x80", b"\x60", b"\xf6"):
        message = b"\xd2\x84" + cbor2.dumps(protected) + b"\xa0" + cbor2.dumps(payload) + sig
        assert _code(message, head) == "signature_invalid"


# -- the unprotected header ----------------------------------------------------

def _carrying(statement: bytes, header) -> bytes:
    protected, _u, payload, sig = cbor2.loads(statement).value
    encoded = header if isinstance(header, bytes) else cbor2.dumps(header)
    return (b"\xd2\x84" + cbor2.dumps(protected) + encoded + cbor2.dumps(payload)
            + cbor2.dumps(sig))


@pytest.mark.parametrize("header", [
    {394: [b"a receipt"]}, {394: [b"one", b"two"]}, {4: b"kid"}, {99: "note"},
    {1: -8}, {394: [b"r"], 4: b"k", "text label": [1, {2: 3}]},
    {7: 1.5, 8: None, 9: True, 10: -1000000, 11: 2 ** 40},
    {12: cbor2.CBORTag(1, 1700000000)},  # a tag a decoder would turn into a date
    {13: cbor2.CBORTag(2, b"\x01" * 9)},  # ... and into a big integer
    # however another party's encoder wrote it:
    b"\xa2\x18\x63\x61x\x04\x41k",  # labels 99 then 4: not in bytewise order
    b"\xa2\x20\x00\x19\x01\x8a\x80",  # -1 then 394: length-first order (RFC 7049)
    b"\xa1\x18\x04\x41k",  # label 4 written in two bytes
    b"\xa1\x04\x58\x01k",  # its value with a longer length
    b"\xa1\x04\x5f\x41k\xff",  # its value in chunks
    b"\xa1\x19\x01\x8a\x9f\x41r\xff",  # receipts in an indefinite array
    b"\xa1\x04\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00",  # 1.5 as a double
])
def test_anything_may_ride_in_the_unprotected_header_and_the_id_does_not_move(header):
    for statement, head in PUBLISHED.values():
        carried = _carrying(statement, header)
        check = scitt.verify_statement(carried, PUB, head)
        assert carried != statement
        assert check.statement_id == hashlib.sha256(statement).digest()
        assert check.statement_id != hashlib.sha256(carried).digest()


@pytest.mark.parametrize("raw_header", [
    *NOT_MAPS,
    b"\x66header",  # text
    b"\xbf\xff",  # an indefinite map, empty
    b"\xbf\x04\x41k\xff",  # ... and with content: its labels cannot be counted
    b"\xa2\x18\x63\x61x\x18\x63\x61y",  # the same label twice
    b"\xa2\x04\x41a\x18\x04\x41b",  # ... once in one byte and once in two
])
def test_an_unprotected_header_that_is_not_one_map_read_one_way_is_refused(raw_header):
    statement, head = PUBLISHED["v2"]
    protected, _u, payload, sig = cbor2.loads(statement).value
    message = (b"\xd2\x84" + cbor2.dumps(protected) + raw_header + cbor2.dumps(payload)
               + cbor2.dumps(sig))
    cbor2.loads(message)  # well-formed: a lenient decoder reads it
    assert _code(message, head) == "unprotected_header_malformed"


@pytest.mark.parametrize("raw_header", [
    b"\xb8\x00",  # empty, its count in two bytes
    b"\xb9\x00\x00",  # ... in three
    b"\xb8\x01\x04\x41k",  # one entry, its count in two bytes
    b"\xba\x00\x00\x00\x01\x19\x01\x8a\x81\x41r",  # a receipt under 394, count in five
])
def test_the_headers_own_count_is_part_of_the_envelope(raw_header):
    """The one byte of the header this construction holds to a form. What
    is inside is another party's; how many entries there are is written
    once, the short way — so a statement with an empty header is one
    sequence of bytes, and its hash is its id."""
    for statement, head in PUBLISHED.values():
        protected, _u, payload, sig = cbor2.loads(statement).value
        message = (b"\xd2\x84" + cbor2.dumps(protected) + raw_header + cbor2.dumps(payload)
                   + cbor2.dumps(sig))
        assert cbor2.loads(message).tag == 18  # a decoder reads it without a word
        assert _code(message, head) == "non_deterministic_encoding"


def test_a_statement_with_an_empty_header_has_one_sequence_of_bytes():
    for statement, head in PUBLISHED.values():
        check = scitt.verify_statement(statement, PUB, head)
        assert check.statement_id == hashlib.sha256(statement).digest()
        protected, unprotected, payload, sig = cbor2.loads(statement).value
        assert not unprotected
        assert statement == (b"\xd2\x84" + cbor2.dumps(protected) + b"\xa0"
                             + cbor2.dumps(payload) + cbor2.dumps(sig))


def test_an_unprotected_header_nested_past_reason_is_refused_not_a_crash():
    statement, head = PUBLISHED["v2"]
    protected, _u, payload, sig = cbor2.loads(statement).value
    for depth in (40, 400, 100_000):
        deep = b"\xa1\x04" + b"\x81" * depth + b"\x00"
        message = (b"\xd2\x84" + cbor2.dumps(protected) + deep + cbor2.dumps(payload)
                   + cbor2.dumps(sig))
        assert _code(message, head) in ("unprotected_header_malformed", "not_cose_sign1")
    shallow = b"\xa1\x04" + b"\x81" * 20 + b"\x00"
    message = (b"\xd2\x84" + cbor2.dumps(protected) + shallow + cbor2.dumps(payload)
               + cbor2.dumps(sig))
    assert scitt.verify_statement(message, PUB, head).statement_id == hashlib.sha256(
        statement).digest()


# -- the byte walk against a real encoder --------------------------------------

def _random_value(rng, depth=0):
    kind = rng.randrange(9 if depth < 4 else 6)
    if kind == 0:
        return rng.choice([0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 32, 2 ** 63, -1, -25,
                           -257, -(2 ** 33)])
    if kind == 1:
        return rng.randbytes(rng.choice([0, 1, 23, 24, 300]))
    if kind == 2:
        return "".join(rng.choice("aé漢z ") for _ in range(rng.choice([0, 3, 30])))
    if kind == 3:
        return rng.choice([True, False, None])
    if kind == 4:
        return rng.choice([0.0, 1.5, -2.25, 1e10, 1.1, 3.4028234663852886e38, 5e-324,
                           float("inf")])
    if kind == 5:
        return cbor2.CBORTag(rng.choice([1, 24, 37, 1000, 70000]), rng.randrange(100))
    if kind == 6:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    # Keys whose encodings are all one byte long: the encoder used as the
    # reference sorts by length first (RFC 7049), RFC 8949 section 4.2.1
    # bytewise, and the two agree only there. Where they differ is stated
    # case by case in the table below.
    return {rng.randrange(-24, 24): _random_value(rng, depth + 1)
            for _ in range(rng.randrange(5))}


def test_the_walk_agrees_with_a_canonical_encoder_on_ten_thousand_values():
    """The walk reads bytes and never builds values. An encoder that
    writes the deterministic form is the independent check: everything it
    writes is accepted, and its ordinary form is accepted exactly when the
    two forms are the same bytes."""
    rng = random.Random(8949)
    differing = 0
    for _ in range(10_000):
        value = _random_value(rng)
        canonical = cbor2.dumps(value, canonical=True)
        plain = cbor2.dumps(value)
        assert scitt._is_deterministic(canonical), canonical.hex()
        assert scitt._scan(canonical)[0] == len(canonical)
        assert scitt._scan(plain)[0] == len(plain)
        assert scitt._is_deterministic(plain) == (plain == canonical), plain.hex()
        differing += plain != canonical
    assert differing > 500  # the comparison is not vacuous


@pytest.mark.parametrize("raw, deterministic", [
    (b"\x17", True), (b"\x18\x17", False), (b"\x18\x18", True), (b"\x19\x00\xff", False),
    (b"\x19\x01\x00", True), (b"\x1a\x00\x00\xff\xff", False), (b"\x1a\x00\x01\x00\x00", True),
    (b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff", False),
    (b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00", True),
    (b"\x38\x17", False), (b"\x38\x18", True),
    (b"\x40", True), (b"\x58\x00", False), (b"\x5f\xff", False), (b"\x7f\x61a\xff", False),
    (b"\x80", True), (b"\x98\x00", False), (b"\x9f\xff", False),
    (b"\xa0", True), (b"\xb8\x00", False), (b"\xbf\xff", False),
    (b"\xa2\x01\x00\x02\x00", True), (b"\xa2\x02\x00\x01\x00", False),
    (b"\xa2\x01\x00\x01\x00", False),  # the same key twice
    (b"\xa2\x0a\x00\x18\x64\x00", True),  # 10 before 100: shorter encodings first
    (b"\xa2\x18\x64\x00\x20\x00", True),  # 100 before -1: bytewise, not by value
    (b"\xa2\x20\x00\x18\x64\x00", False),
    (b"\xc1\x00", True), (b"\xd8\x01\x00", False), (b"\xd8\x18\x00", True),
    (b"\xf4", True), (b"\xf6", True), (b"\xf8\x20", True),
    (b"\xf9\x3e\x00", True), (b"\xfa\x3f\xc0\x00\x00", False),
    (b"\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00", False),
    (b"\xfb\x3f\xf1\x99\x99\x99\x99\x99\x9a", True),  # 1.1 needs the double
    (b"\xf9\x7e\x00", True), (b"\xfa\x7f\xc0\x00\x00", False),
    (b"\xfb\x7f\xf8\x00\x00\x00\x00\x00\x00", False),
    (b"\xf9\x7c\x00", True), (b"\xfa\x7f\x80\x00\x00", False),  # infinity
])
def test_the_walk_on_the_cases_of_rfc_8949_section_4_2_1(raw, deterministic):
    cbor2.loads(raw)  # each is well-formed
    assert scitt._is_deterministic(raw) is deterministic


# -- the vectors ---------------------------------------------------------------

def test_the_identity_vectors_hold_and_regenerate(tmp_path):
    doc = _load(VECTOR.name)
    key = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(doc["key"]["public_key_hex"]))
    assert {p["base"] for p in doc["published"]} == set(PUBLISHED)
    for p in doc["published"]:
        statement, head = PUBLISHED[p["base"]]
        assert p["statement_id"] == p["statement_sha256"] == hashlib.sha256(
            statement).hexdigest()
        assert bytes.fromhex(p["expected_head_hex"]) == head
    ids = {p["base"]: p["statement_id"] for p in doc["published"]}
    assert len(doc["carrying_an_unprotected_header"]) == 6
    for c in doc["carrying_an_unprotected_header"]:
        message = bytes.fromhex(c["statement_hex"])
        assert hashlib.sha256(message).hexdigest() == c["statement_sha256"]
        check = scitt.verify_statement(message, key, bytes.fromhex(c["expected_head_hex"]))
        assert check.statement_id.hex() == c["statement_id"] == ids[c["base"]]
        assert c["statement_id"] != c["statement_sha256"] and c["verifies"] is True
        assert message[:2] == b"\xd2\x84"

    work = tmp_path / "docs" / "interop"
    work.mkdir(parents=True)
    for name in (*INPUTS, "gen_scitt_statement_identity_vectors.py"):
        shutil.copy(INTEROP / name, work / name)
    proc = subprocess.run(
        [sys.executable, str(work / "gen_scitt_statement_identity_vectors.py")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (work / VECTOR.name).read_bytes() == VECTOR.read_bytes()
    assert all((work / n).read_bytes() == (INTEROP / n).read_bytes() for n in INPUTS)
