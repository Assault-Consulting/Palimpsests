# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Every refusal of a statement is one exception with a code.

``verify_statement`` reads bytes someone else produced. Before 0.15 it
promised ``ValueError`` and, for malformed input, raised four other types
(``CBORDecodeEOF``, ``CBORDecodeError``, ``TypeError``, ``AttributeError``);
its refusals carried a sentence and no code; and a statement followed by
stray bytes verified.
"""
from __future__ import annotations

import pytest
import random
import warnings

cbor2 = pytest.importorskip("cbor2")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from palimpsests.audit.pala import scitt  # noqa: E402
from palimpsests.audit.pala.scitt import (  # noqa: E402
    STATEMENT_REFUSAL_CODES,
    StatementCheck,
    StatementRefused,
    verify_statement,
)
from palimpsests.audit.pala_writer import PalaWriter  # noqa: E402
from palimpsests.audit.reader import AuditReader  # noqa: E402

HEAD = b"\x11" * 32
ROOT = b"\x22" * 32
KEY = ed25519.Ed25519PrivateKey.generate()
PUB = KEY.public_key()


def _statement(**kw):
    args = {"first_seq": 0, "last_seq": 5, "key": KEY, "issuer": "i", "subject": "s",
            "alg": scitt.ALG_EDDSA}
    args.update(kw)
    return scitt.build_signed_statement(HEAD, **args)


def _parts(message):
    protected, unprotected, payload, sig = cbor2.loads(message).value
    return protected, unprotected, payload, sig


def _message(protected, unprotected, payload, sig):
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, sig]))


def _signed(protected: bytes, payload: bytes) -> bytes:
    """A COSE_Sign1 over exactly these bytes, signed with the test key — so
    a case fails on the check it is about and not on the signature."""
    return _message(protected, {}, payload, KEY.sign(scitt._sig_structure(protected, payload)))


def _with_payload(change) -> bytes:
    protected, _u, payload, _s = _parts(_statement())
    decoded = cbor2.loads(payload)
    change(decoded)
    return _signed(protected, cbor2.dumps(decoded, canonical=True))


def _with_protected(change, message=None) -> bytes:
    protected, _u, payload, _s = _parts(message or _statement())
    header = cbor2.loads(protected)
    change(header)
    return _signed(cbor2.dumps(header, canonical=True), payload)


def _chain(tmp_path, records=6):
    path = tmp_path / "c.pala"
    with PalaWriter(path) as w:
        w.genesis()
        for _ in range(records - 1):
            w.prefix_warm()
        root = w.chain_root()
        head = w.head
    return path, head, root


V3 = _statement(root=ROOT)
P, U, PL, SIG = _parts(_statement())

#: code -> a statement refused with it (verified against HEAD under PUB).
CASES = {
    "not_cose_sign1": [
        b"", b"hello", _statement()[:20], cbor2.dumps(5), cbor2.dumps([P, U, PL, SIG]),
        cbor2.dumps(cbor2.CBORTag(18, 5)), cbor2.dumps(cbor2.CBORTag(18, [P, U, PL])),
        cbor2.dumps(cbor2.CBORTag(17, [P, U, PL, SIG])), "a string", None,
    ],
    "trailing_bytes": [_statement() + b"\x00", _statement() + _statement()],
    "protected_header_malformed": [
        _message(5, U, PL, SIG), _message(b"\xff\xff", U, PL, SIG), _message(b"", U, PL, SIG),
        _message(cbor2.dumps([1]), U, PL, SIG), _signed(P + b"\x00", PL),
    ],
    "detached_payload": [_message(P, U, None, SIG)],
    "payload_malformed": [
        _signed(P, b"\xff\xff\xff"), _signed(P, b""), _signed(P, cbor2.dumps([1, 2])),
        _signed(P, PL + b"\x00"), _message(P, U, 7, SIG),
    ],
    "repeated_key": [
        _signed(P, b"\xa5" + PL[1:] + cbor2.dumps(1) + cbor2.dumps(HEAD)),
        _signed(b"\xa5" + P[1:] + cbor2.dumps(1) + cbor2.dumps(-8), PL),
    ],
    "indefinite_length_map": [_signed(P, b"\xbf" + PL[1:] + b"\xff")],
    "unsupported_alg": [
        _with_protected(lambda h: h.__setitem__(1, -35)),
        _with_protected(lambda h: h.__setitem__(1, "EdDSA")),
        _with_protected(lambda h: h.pop(1)),
        _with_protected(lambda h: h.__setitem__(1, True)),
    ],
    "signature_invalid": [
        _message(P, U, PL, SIG[:-1] + bytes([SIG[-1] ^ 1])), _message(P, U, PL, SIG[:10]),
        _message(P, U, PL, 7), _message(P, U, PL[:-1] + bytes([PL[-1] ^ 1]), SIG),
    ],
    "head_mismatch": [_with_payload(lambda d: d.__setitem__(1, b"\x33" * 32))],
    "format_id_mismatch": [_with_payload(lambda d: d.__setitem__(4, "pala-1/v9"))],
    "range_invalid": [
        _with_payload(lambda d: d.__setitem__(2, 9)),
        _with_payload(lambda d: d.__setitem__(2, -1)),
        _with_payload(lambda d: d.__setitem__(3, "5")),
        _with_payload(lambda d: d.__setitem__(3, True)),
    ],
    "content_type_unknown": [
        _with_protected(lambda h: h.__setitem__(3, "application/x-other")),
        _with_protected(lambda h: h.pop(3)),
    ],
    "payload_keys_mismatch": [
        _with_payload(lambda d: d.__setitem__(5, ROOT)),  # a root under the v2 type
        _with_payload(lambda d: d.__setitem__("note", 1)),
        _with_protected(lambda h: h.__setitem__(3, scitt.CONTENT_TYPE_V3)),  # v3, no root
    ],
    "protected_labels_mismatch": [
        _with_protected(lambda h: h.__setitem__(33, b"x5chain")),
        _with_protected(lambda h: h.pop(4)),
        _with_protected(lambda h: h.__setitem__(33, b"x"), V3),
        _with_protected(lambda h: h.__setitem__("x5t", b"x")),  # a text label among integers
    ],
    "root_malformed": [
        _signed(_parts(V3)[0], cbor2.dumps({**cbor2.loads(_parts(V3)[2]), 5: b"short"},
                                           canonical=True)),
        _signed(_parts(V3)[0], cbor2.dumps({**cbor2.loads(_parts(V3)[2]), 5: "text"},
                                           canonical=True)),
    ],
}


def _refused(message, *, key=PUB, head=HEAD, reader=None) -> StatementRefused:
    with pytest.raises(StatementRefused) as info:
        verify_statement(message, key, head, reader=reader)
    return info.value


@pytest.mark.parametrize(
    ("code", "n"), [(code, n) for code, cases in CASES.items() for n in range(len(cases))])
def test_each_refusal_has_its_code(code, n):
    exc = _refused(CASES[code][n])
    assert exc.code == code, str(exc)
    assert isinstance(exc, ValueError) and str(exc)  # what callers caught before 0.15


def test_the_two_refusals_that_need_a_chain(tmp_path):
    path, head, root = _chain(tmp_path)
    good = scitt.build_signed_statement(
        head, first_seq=0, last_seq=5, key=KEY, issuer="i", subject="s",
        alg=scitt.ALG_EDDSA, root=root)
    with AuditReader.open(path) as r:
        assert verify_statement(good, PUB, head, reader=r).root_status == "recomputed"
        wrong = scitt.build_signed_statement(
            head, first_seq=0, last_seq=5, key=KEY, issuer="i", subject="s",
            alg=scitt.ALG_EDDSA, root=ROOT)
        assert _refused(wrong, head=head, reader=r).code == "root_mismatch"
        beyond = scitt.build_signed_statement(
            head, first_seq=0, last_seq=50, key=KEY, issuer="i", subject="s",
            alg=scitt.ALG_EDDSA, root=root)
        assert _refused(beyond, head=head, reader=r).code == "chain_too_short"


def test_every_declared_code_is_produced_and_no_other():
    produced = set(CASES) | {"root_mismatch", "chain_too_short"}
    assert produced == set(STATEMENT_REFUSAL_CODES)


def test_a_key_that_cannot_verify_is_a_refusal_not_a_crash():
    """A wrong key, a key of another type, no key: the verifier cannot tell
    them from an altered message, and reports one thing."""
    message = _statement()
    for key in (ed25519.Ed25519PrivateKey.generate().public_key(),
                ec.generate_private_key(ec.SECP256R1()).public_key(), KEY, None, "key"):
        assert _refused(message, key=key).code == "signature_invalid"
    es = ec.generate_private_key(ec.SECP256R1())
    es_message = _statement(key=es, alg=scitt.ALG_ES256)
    assert verify_statement(es_message, es.public_key(), HEAD).version == "v2"
    assert _refused(es_message, key=PUB).code == "signature_invalid"


def test_an_expected_head_of_the_wrong_kind_is_a_mismatch():
    for head in ("abc", None, HEAD.hex(), b""):
        assert _refused(_statement(), head=head).code == "head_mismatch"


def test_stray_bytes_after_a_statement_are_not_part_of_it():
    """It verified before 0.15: the decoder read one item and ignored the
    rest. An artifact that is a statement plus something else is not the
    statement — and its bytes are not the registered bytes."""
    message = _statement()
    assert verify_statement(message, PUB, HEAD).version == "v2"
    for extra in (b"\x00", b"\xff", b"anything", message):
        assert _refused(message + extra).code == "trailing_bytes"


def test_no_mutation_of_a_statement_escapes_as_another_exception():
    """A statement with one byte changed, removed or inserted, 6000 times,
    v2 and v3: the verifier answers — accepted or refused — and never
    raises anything else. A mutant that is accepted differs from the
    original only where the signature does not reach: the unprotected
    bucket, which the module's notes name as outside it."""
    rng = random.Random(20261115)
    for original in (_statement(), V3):
        signed = (_parts(original)[0], _parts(original)[2], _parts(original)[3])
        accepted = 0
        for _ in range(3000):
            data = bytearray(original)
            at = rng.randrange(len(data))
            op = rng.randrange(3)
            if op == 0:
                data[at] ^= 1 << rng.randrange(8)
            elif op == 1:
                del data[at]
            else:
                data.insert(at, rng.randrange(256))
            mutant = bytes(data)
            try:
                result = verify_statement(mutant, PUB, HEAD)
            except StatementRefused as exc:
                assert exc.code in STATEMENT_REFUSAL_CODES
                continue
            assert isinstance(result, StatementCheck)
            if mutant != original:
                accepted += 1
                p, _u, pl, sig = _parts(mutant)
                assert (p, pl, sig) == signed  # everything the signature covers is intact
        assert accepted < 30  # the unprotected bucket is one byte of ~200


def test_the_old_verifier_warns_and_gives_the_same_answer():
    message = _statement()
    with pytest.warns(DeprecationWarning, match="verify_statement"):
        payload = scitt.check_statement_against_head(message, PUB, HEAD)
    assert payload == verify_statement(message, PUB, HEAD).payload
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(StatementRefused) as info:
            scitt.check_statement_against_head(message + b"\x00", PUB, HEAD)
    assert info.value.code == "trailing_bytes"


def test_the_builders_own_errors_stay_plain_value_errors():
    """A refusal is about a statement someone handed over. A caller who asks
    the builder for something it does not build has made a mistake of their
    own, and gets a ValueError that is not a StatementRefused."""
    for call in (
        lambda: scitt.head_payload(b"short", 0, 1),
        lambda: scitt.head_payload(HEAD, 5, 4),
        lambda: _statement(alg=-99),
        lambda: _statement(root=b"short"),
    ):
        with pytest.raises(ValueError) as info:
            call()
        assert not isinstance(info.value, StatementRefused)
