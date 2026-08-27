# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""SCITT bridge, statement side (B.1): a chain head as a Signed Statement.

The bridge in one sentence: where a deployment permits an external
witness, the producer publishes ONE digest — the chain head — as a
COSE_Sign1 (RFC 9052) Signed Statement suitable for registration with a
SCITT transparency service (RFC 9943); the envelope cost is paid once
per published head, never per record, and nothing here touches the
write path or the frozen wire format.

Two boundaries, stated up front:

- This module is tooling beside the format, not part of it.
  Registration is never a precondition of a trail's validity; a trail
  that is never witnessed remains verifiable for internal consistency
  and completeness, and simply does not claim existence-in-time.
- The overclaim rule applies: a verifier that has not checked a
  statement (or its receipt) against a key it trusts reports the range
  as *reported, not verified*. ``check_statement_against_head`` is the
  *verified* path.

COSE is implemented minimally here (sign1/verify1 over an ES256 or
Ed25519 key) rather than through a COSE library, for the same reason
the codec is byte-exact everywhere else: full control of the exact
bytes in the Sig_structure, and no transitive dependency surface. This
is not a general COSE implementation and takes no configuration.

Dependencies (``cbor2``, ``cryptography``) are imported lazily via the
``[scitt]`` extra, mirroring ``bodies.py``: a bare install keeps full
header-only verification; only the bridge needs the packages.
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "FORMAT_ID",
    "ScittUnavailable",
    "build_signed_statement",
    "check_statement_against_head",
    "head_payload",
]

ALG_ES256 = -7
ALG_EDDSA = -8
_HDR_ALG = 1
_HDR_CWT_CLAIMS = 15  # RFC 9597: CWT claims in COSE headers
_CWT_ISS = 1
_CWT_SUB = 2

_PAYLOAD_HEAD = 1
_PAYLOAD_FIRST_SEQ = 2
_PAYLOAD_LAST_SEQ = 3
_PAYLOAD_FORMAT = 4
FORMAT_ID = "pala-1/v1.0"

_HEAD_LEN = 32


class ScittUnavailable(RuntimeError):
    """Raised when the SCITT bridge is used without the [scitt] extra."""


def _cbor2():
    try:
        import cbor2
    except ImportError as e:  # pragma: no cover - import guard
        raise ScittUnavailable(
            "the SCITT bridge needs 'cbor2' and 'cryptography'; "
            "install the [scitt] extra. Chain verification does not."
        ) from e
    return cbor2


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as e:  # pragma: no cover - import guard
        raise ScittUnavailable(
            "the SCITT bridge needs 'cbor2' and 'cryptography'; "
            "install the [scitt] extra. Chain verification does not."
        ) from e
    return hashes, ec, decode_dss_signature, encode_dss_signature


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    # RFC 9052 §4.4: ["Signature1", body_protected, external_aad, payload]
    return _cbor2().dumps(["Signature1", protected, b"", payload])


def _cose_sign1(payload: bytes, key: Any, *, alg: int, claims: dict | None = None) -> bytes:
    cbor2 = _cbor2()
    hashes, ec, decode_dss, _ = _crypto()
    phdr: dict = {_HDR_ALG: alg}
    if claims:
        phdr[_HDR_CWT_CLAIMS] = claims
    protected = cbor2.dumps(phdr)
    tbs = _sig_structure(protected, payload)
    if alg == ALG_ES256:
        r, s = decode_dss(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == ALG_EDDSA:
        sig = key.sign(tbs)
    else:
        raise ValueError(f"unsupported COSE alg {alg}; this bridge takes -7 or -8")
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig]))


def _cose_verify1(message: bytes, public_key: Any) -> bytes:
    """Verify a COSE_Sign1; return its payload, or raise ``ValueError``."""
    cbor2 = _cbor2()
    hashes, ec, _, encode_dss = _crypto()
    tag = cbor2.loads(message)
    if not isinstance(tag, cbor2.CBORTag) or tag.tag != 18 or len(tag.value) != 4:
        raise ValueError("not a COSE_Sign1 message")
    protected, _unprotected, payload, sig = tag.value
    alg = cbor2.loads(protected).get(_HDR_ALG)
    tbs = _sig_structure(protected, payload)
    try:
        if alg == ALG_ES256:
            if len(sig) != 64:
                raise ValueError("ES256 signature must be 64 bytes (P-1363)")
            der = encode_dss(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            public_key.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_EDDSA:
            public_key.verify(sig, tbs)
        else:
            raise ValueError(f"unsupported COSE alg {alg}")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError("COSE_Sign1 signature verification failed") from e
    return payload


def head_payload(head: bytes, first_seq: int, last_seq: int) -> bytes:
    """The statement payload: a self-describing commitment to one head.

    Attached rather than detached, deliberately: the statement must be
    readable offline, without the transparency service, because the
    deployments this format serves may only export evidence long after
    the fact.
    """
    if len(head) != _HEAD_LEN:
        raise ValueError(f"chain head must be {_HEAD_LEN} bytes")
    if first_seq < 0 or last_seq < first_seq:
        raise ValueError("sequence range must satisfy 0 <= first_seq <= last_seq")
    return _cbor2().dumps(
        {
            _PAYLOAD_HEAD: head,
            _PAYLOAD_FIRST_SEQ: first_seq,
            _PAYLOAD_LAST_SEQ: last_seq,
            _PAYLOAD_FORMAT: FORMAT_ID,
        }
    )


def build_signed_statement(
    head: bytes,
    *,
    first_seq: int,
    last_seq: int,
    key: Any,
    issuer: str,
    subject: str,
    alg: int = ALG_ES256,
) -> bytes:
    """One COSE_Sign1 committing to a chain head — the whole export.

    ``issuer``/``subject`` land as CWT claims in the protected header,
    the shape a SCITT transparency service registers. What leaves the
    device is this message: one digest and a range, no record body, no
    model output.
    """
    payload = head_payload(head, first_seq, last_seq)
    claims = {_CWT_ISS: issuer, _CWT_SUB: subject}
    return _cose_sign1(payload, key, alg=alg, claims=claims)


def check_statement_against_head(
    message: bytes, public_key: Any, expected_head: bytes
) -> dict[int, Any]:
    """Verify signature AND commitment; the *verified* side of overclaim.

    Returns the decoded payload map on success. Raises ``ValueError`` on
    any mismatch. A caller that has not run this (with a key it trusts)
    reports the statement as *reported, not verified* — never as
    witnessed.
    """
    payload = _cose_verify1(message, public_key)
    decoded = _cbor2().loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("statement payload is not a CBOR map")
    if decoded.get(_PAYLOAD_HEAD) != expected_head:
        raise ValueError("statement does not commit to the expected chain head")
    if decoded.get(_PAYLOAD_FORMAT) != FORMAT_ID:
        raise ValueError(f"statement format id is not {FORMAT_ID!r}")
    return decoded
