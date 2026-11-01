# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""SCITT bridge, statement side (B.1): a chain head as a Signed Statement.

The bridge in one sentence: where a deployment permits an external
witness, the producer publishes ONE digest — the chain head — as a
COSE_Sign1 (RFC 9052) Signed Statement suitable for registration with a
SCITT transparency service (RFC 9943); the envelope cost is paid once
per published head, never per record, and nothing here touches the
write path or the frozen wire format.

Construction v3 adds a second digest beside the head: the derived root
over every record up to it (payload key 5, its own content type). The
head answers "is this the chain I anchored?"; the root answers "does this
later state extend that earlier one?" — two v3 statements and a
``pala-consistency-proof/1`` decide it without the chain. v2 stays valid
and byte-identical; :func:`verify_statement` reads both.

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

Byte stability, stated precisely (bridge run B1 plus a cross-library
measurement) — four ways "the same statement" can honestly differ in
bytes, and what this module does about each:

1. **Signature determinism.** Byte-for-byte reproduction is promised
   only under EdDSA: RFC 8032 makes the signature deterministic by
   construction. ES256 has no such guarantee from the standard —
   RFC 6979 derandomisation is a per-library choice (one common COSE
   stack applies it, a common raw-ECDSA stack does not), so two
   conforming implementations legitimately emit different signature
   bytes over identical input. An ES256 vector may claim "verifies",
   never "reproduces". The published vector uses EdDSA for exactly
   this reason.
2. **The unprotected bucket is outside the signature.** Anything
   placed or moved there changes the artifact's bytes while the
   signature keeps verifying — "the signature is valid" and "these are
   the published bytes" are two different claims and must be checked
   separately. This module emits an empty unprotected map and keeps
   every meaningful parameter protected.
3. **Tag 18 is one byte that libraries disagree on.** This module
   emits and requires the *tagged* COSE_Sign1 form (first byte 0xd2);
   an untagged re-encoding of the same content is a different
   artifact, accepted by some parsers and not others.
4. **The Sig_structure is assembled, not extracted.** What is signed
   is the separately constructed CBOR array ["Signature1", protected,
   external_aad, payload] (RFC 9052 §4.4) — two implementations must
   build those bytes identically for signatures over identical inputs
   to agree, which is why deterministic CBOR encoding is used here for
   everything that is hashed or signed.
5. **Signature uniqueness (Ed25519 S + L).** Adding the group order L
   to the scalar S yields a second, distinct 64-byte signature over
   the identical Sig_structure — rejected by a verifier enforcing
   RFC 8032 §5.1.7's ``0 <= S < L`` range check, accepted by one that
   omits it; both behaviours exist in the wild (bridge run B2, F-2).
   Not a forgery — a uniqueness failure, which matters wherever
   registrations are deduplicated or indexed by signature bytes. This
   module's verify path rejects the non-canonical form (its backend
   enforces the range check; pinned by test).
6. **A detached payload is a different artifact.** Setting the payload
   to nil and supplying it externally leaves the signature verifying
   over a shorter message — a fifth identity/validity split (B2, F-3).
   This bridge always emits the attached form.

Dependencies (``cbor2``, ``cryptography``) are imported lazily via the
``[scitt]`` extra, mirroring ``bodies.py``: a bare install keeps full
header-only verification; only the bridge needs the packages.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "CONTENT_TYPE",
    "CONTENT_TYPE_V3",
    "FORMAT_ID",
    "ScittUnavailable",
    "StatementCheck",
    "build_signed_statement",
    "check_statement_against_head",
    "head_payload",
    "verify_statement",
]

ALG_ES256 = -7
ALG_EDDSA = -8
_HDR_ALG = 1
_HDR_CONTENT_TYPE = 3  # RFC 9052 §3.1: what the payload is (B1 finding F2)
_HDR_KID = 4  # RFC 9052 §3.1; required by RFC 9943 §6 absent x5t/x5chain (B1 F1)
_HDR_CWT_CLAIMS = 15  # RFC 9597: CWT claims in COSE headers
# This construction's protected header, exactly. RFC 9052 allows other labels
# in general; a statement carrying any is not this construction and is
# refused (outside reading of v3, L. Lemonnier, ambiguity 1).
_PROTECTED_LABELS = frozenset({_HDR_ALG, _HDR_CONTENT_TYPE, _HDR_KID, _HDR_CWT_CLAIMS})

# The payload's media type, vendor tree (unregistered), naming the
# {1,2,3,4} map below. Declared in the *protected* header so a verifier
# never has to guess whether the payload is a CWT Claims Set — it is not
# (bridge run B1, finding F2: without this, RFC 9597 §2 invites a reading
# that must then be rejected).
CONTENT_TYPE = "application/vnd.palimpsests.pala1-head+cbor"
#: Statement construction v3: the payload also carries the derived root
#: (key 5). A separate content type, not a payload member, so the
#: construction is named in the *signed* header and a v2 verifier — which
#: checks for exactly keys 1–4 — rejects a v3 statement by its type instead
#: of misreading it.
CONTENT_TYPE_V3 = "application/vnd.palimpsests.pala1-head-v3+cbor"
_CWT_ISS = 1
_CWT_SUB = 2

_PAYLOAD_HEAD = 1
_PAYLOAD_FIRST_SEQ = 2
_PAYLOAD_LAST_SEQ = 3
_PAYLOAD_FORMAT = 4
_PAYLOAD_ROOT = 5  # v3: derived root over records 0..last_seq
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


def _cose_key_thumbprint(public_key: Any, alg: int) -> bytes:
    """RFC 9679 COSE Key Thumbprint (SHA-256) — the default ``kid``.

    Deterministically encodes the required COSE_Key fields for the
    algorithm's key type and hashes them; two parties holding the same
    key derive the same identifier with no registry between them.
    """
    import hashlib

    cbor2 = _cbor2()
    if alg == ALG_EDDSA:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        x = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        cose_key = {1: 1, -1: 6, -2: x}  # OKP / Ed25519 / x
    elif alg == ALG_ES256:
        nums = public_key.public_numbers()
        cose_key = {
            1: 2,  # EC2
            -1: 1,  # P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }
    else:
        raise ValueError(f"unsupported COSE alg {alg}; this bridge takes -7 or -8")
    return hashlib.sha256(cbor2.dumps(cose_key, canonical=True)).digest()


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    # RFC 9052 §4.4: ["Signature1", body_protected, external_aad, payload]
    return _cbor2().dumps(["Signature1", protected, b"", payload])


def _cose_sign1(
    payload: bytes,
    key: Any,
    *,
    alg: int,
    claims: dict | None = None,
    kid: bytes | None = None,
    content_type: str = CONTENT_TYPE,
) -> bytes:
    cbor2 = _cbor2()
    hashes, ec, decode_dss, _ = _crypto()
    public_key = key.public_key() if hasattr(key, "public_key") else key
    if kid is None:
        kid = _cose_key_thumbprint(public_key, alg)
    # Labels inserted in ascending order (1, 3, 4, 15) so the encoded map
    # is already in RFC 8949 §4.2.1 deterministic form — a strict decoder
    # (bridge run B1 used one) accepts it without reordering. kid and the
    # content type sit in the *protected* bucket on purpose: unprotected
    # copies are unauthenticated (B1 adversarial case A10).
    phdr: dict = {_HDR_ALG: alg, _HDR_CONTENT_TYPE: content_type, _HDR_KID: kid}
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
    """Verify a COSE_Sign1; return its payload, or raise ``ValueError``.

    Ed25519 verification here rejects a non-canonical scalar (S >= L,
    RFC 8032 §5.1.7) through its backend — the S + L variant of a valid
    signature does not verify; a test pins that behaviour.
    """
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


def head_payload(
    head: bytes, first_seq: int, last_seq: int, *, root: bytes | None = None
) -> bytes:
    """The statement payload: a self-describing commitment to one head.

    Attached rather than detached, deliberately: the statement must be
    readable offline, without the transparency service, because the
    deployments this format serves may only export evidence long after
    the fact.

    With ``root`` (construction v3), key 5 carries the derived root over
    records ``0..last_seq`` — the §4.3 tree over their record hashes,
    ``consistency-proof.md`` §1. **Always from record 0, whatever
    ``first_seq`` says**: a prefix-consistency proof connects roots of
    prefixes of one tree, so a root over ``first_seq..last_seq`` would
    connect to nothing. ``first_seq`` keeps its v2 meaning — the range
    this publication reports — and the root does not depend on it.
    """
    if len(head) != _HEAD_LEN:
        raise ValueError(f"chain head must be {_HEAD_LEN} bytes")
    if first_seq < 0 or last_seq < first_seq:
        raise ValueError("sequence range must satisfy 0 <= first_seq <= last_seq")
    payload: dict = {
        _PAYLOAD_HEAD: head,
        _PAYLOAD_FIRST_SEQ: first_seq,
        _PAYLOAD_LAST_SEQ: last_seq,
        _PAYLOAD_FORMAT: FORMAT_ID,
    }
    if root is not None:
        if len(root) != _HEAD_LEN:
            raise ValueError(f"derived root must be {_HEAD_LEN} bytes")
        payload[_PAYLOAD_ROOT] = root
    return _cbor2().dumps(payload)


def build_signed_statement(
    head: bytes,
    *,
    first_seq: int,
    last_seq: int,
    key: Any,
    issuer: str,
    subject: str,
    alg: int = ALG_ES256,
    kid: bytes | None = None,
    root: bytes | None = None,
) -> bytes:
    """One COSE_Sign1 committing to a chain head — the whole export.

    With ``root`` the statement is construction **v3**: content type
    ``CONTENT_TYPE_V3`` and the derived root over records ``0..last_seq``
    in payload key 5 (see :func:`head_payload`). Two v3 statements of one
    chain can then be connected by a ``pala-consistency-proof/1`` without
    the chain — the use their roots exist for. A writer states that root
    as ``PalaWriter.chain_root()``, including after earlier segments were
    deleted; a reader holding the chain, as ``chain_root(reader,
    last_seq + 1)``. Without ``root`` the statement is v2, byte-identical
    to what this function built before v3 existed.

    ``issuer``/``subject`` land as CWT claims in the protected header,
    the shape a SCITT transparency service registers. What leaves the
    device is this message: one digest and a range, no record body, no
    model output.

    The protected header also carries ``kid`` (RFC 9679 COSE Key
    Thumbprint of the verification key by default — pass ``kid`` to
    override) and the payload's content type; both are required or
    invited by RFC 9943 §6, and both were absent before bridge run B1
    reported it (findings F1, F2). Put the FULL chain head in
    ``subject``: a truncated head collides across chains at the
    truncation's birthday bound, and a transparency service indexes by
    this value (B1, finding F4).
    """
    payload = head_payload(head, first_seq, last_seq, root=root)
    claims = {_CWT_ISS: issuer, _CWT_SUB: subject}
    content_type = CONTENT_TYPE if root is None else CONTENT_TYPE_V3
    return _cose_sign1(
        payload, key, alg=alg, claims=claims, kid=kid, content_type=content_type
    )


@dataclass(frozen=True)
class StatementCheck:
    """What :func:`verify_statement` established — and what it did not.

    ``root_status`` keeps the overclaim line for the v3 root:
    ``"absent"`` (a v2 statement carries none), ``"recomputed"`` (the
    root was recomputed from the chain and matched), or ``"carried, not
    recomputed"`` (the statement carries a root, the signature covers it,
    and no chain was at hand to recompute it — so it is reported, never
    called verified).

    ``payload_encoding`` is reported apart from the values:
    ``"deterministic"`` when the signed payload bytes are the RFC 8949
    §4.2.1 deterministic encoding of the map they decode to, ``"not
    deterministic"`` otherwise. The construction requires deterministic
    encoding; a signed map with correct values in another encoding is a
    finding about the bytes, not a refusal of the values.
    """

    version: str  # "v2" | "v3"
    payload: dict
    root: bytes | None
    root_status: str
    payload_encoding: str  # "deterministic" | "not deterministic"


def _distinct_keys(raw: bytes, decoded: dict, what: str) -> None:
    """Refuse a map that repeats a key. A decoder keeps one of the values —
    cbor2 the last — and another reader may keep the other, so the same
    signed bytes would read two ways (RFC 8949 §5.6: such a map is not
    valid). Counted from the map's declared length; an indefinite-length map
    cannot be counted and is not the deterministic encoding either."""
    major, ai = raw[0] >> 5, raw[0] & 0x1F
    if major != 5:
        raise ValueError(f"{what} is not a CBOR map")
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        n = int.from_bytes(raw[1 : 1 + width], "big")
    else:
        raise ValueError(f"{what} is an indefinite-length map; its keys cannot be counted")
    if n != len(decoded):
        raise ValueError(f"{what} repeats a key ({n} entries, {len(decoded)} distinct keys)")


def _protected_header(message: bytes) -> dict:
    tag = _cbor2().loads(message)
    if not hasattr(tag, "value") or len(tag.value) != 4:
        raise ValueError("not a COSE_Sign1 message")
    phdr = _cbor2().loads(tag.value[0])
    if not isinstance(phdr, dict):
        raise ValueError("protected header is not a CBOR map")
    _distinct_keys(tag.value[0], phdr, "the protected header")
    return phdr


def _check_protected_labels(phdr: dict) -> None:
    if set(phdr) != _PROTECTED_LABELS:
        raise ValueError(
            "this construction's protected header carries exactly labels 1, 3, 4 "
            f"and 15 (alg, content type, kid, CWT claims); this one carries {sorted(phdr)}"
        )


def verify_statement(
    message: bytes, public_key: Any, expected_head: bytes, *, reader: Any = None
) -> StatementCheck:
    """Verify signature AND commitment, v2 or v3, by the signed content type.

    The construction is read from the *protected* content type, never
    guessed from the payload: a v2 statement must carry exactly keys 1–4,
    a v3 statement must also carry a 32-byte root in key 5. A root under
    the v2 type, or a v3 type without one, is refused — a statement that
    disagrees with its own signed description is not read either way.
    The protected header must carry exactly labels 1, 3, 4 and 15 (alg,
    content type, kid, CWT claims); any other label is refused, and so is
    a repeated key in either map. A payload whose bytes are otherwise not
    the deterministic encoding is reported in ``payload_encoding``, not
    refused.

    ``reader`` (an ``AuditReader`` over the chain) lets the v3 root be
    *recomputed* — the derived root over records ``0..last_seq`` — and
    compared; without it the root is reported as carried, not
    recomputed. Raises ``ValueError`` on any mismatch.
    """
    payload = _cose_verify1(message, public_key)
    decoded = _cbor2().loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("statement payload is not a CBOR map")
    _distinct_keys(payload, decoded, "the statement payload")
    if decoded.get(_PAYLOAD_HEAD) != expected_head:
        raise ValueError("statement does not commit to the expected chain head")
    if decoded.get(_PAYLOAD_FORMAT) != FORMAT_ID:
        raise ValueError(f"statement format id is not {FORMAT_ID!r}")
    first, last = decoded.get(_PAYLOAD_FIRST_SEQ), decoded.get(_PAYLOAD_LAST_SEQ)
    if not (
        type(first) is int and type(last) is int and 0 <= first <= last
    ):
        # The builder refuses an inverted range; a verifier must too. The root
        # depends only on last_seq, so an inverted statement would otherwise
        # verify with a root correct for its last_seq (bridge run B3, F4).
        raise ValueError("a statement's range must satisfy 0 <= first_seq <= last_seq")
    phdr = _protected_header(message)
    ctype = phdr.get(_HDR_CONTENT_TYPE)
    encoding = (
        "deterministic"
        if _cbor2().dumps(decoded, canonical=True) == payload
        else "not deterministic"
    )
    v2_keys = {_PAYLOAD_HEAD, _PAYLOAD_FIRST_SEQ, _PAYLOAD_LAST_SEQ, _PAYLOAD_FORMAT}
    if ctype == CONTENT_TYPE:
        if set(decoded) != v2_keys:
            raise ValueError(
                "a v2 statement carries exactly payload keys 1-4; this one carries "
                f"{sorted(decoded)} (a root under the v2 content type is not read)"
            )
        _check_protected_labels(phdr)
        return StatementCheck("v2", decoded, None, "absent", encoding)
    if ctype != CONTENT_TYPE_V3:
        raise ValueError(f"unknown statement content type {ctype!r}")
    if set(decoded) != v2_keys | {_PAYLOAD_ROOT}:
        raise ValueError(
            f"a v3 statement carries payload keys 1-5; this one carries {sorted(decoded)}"
        )
    root = decoded[_PAYLOAD_ROOT]
    if not isinstance(root, bytes) or len(root) != _HEAD_LEN:
        raise ValueError(f"a v3 root is {_HEAD_LEN} bytes")
    _check_protected_labels(phdr)
    if reader is None:
        return StatementCheck("v3", decoded, root, "carried, not recomputed", encoding)
    from palimpsests.audit.pala.proofs import chain_root

    last_seq = decoded[_PAYLOAD_LAST_SEQ]
    try:
        expected_root = chain_root(reader, last_seq + 1)
    except IndexError as e:
        raise ValueError(
            f"the chain at hand has fewer than {last_seq + 1} records; the root "
            "cannot be recomputed from it"
        ) from e
    if root != expected_root:
        raise ValueError(
            "the statement's root is not the derived root over records "
            f"0..{last_seq} of this chain"
        )
    return StatementCheck("v3", decoded, root, "recomputed", encoding)


def check_statement_against_head(
    message: bytes, public_key: Any, expected_head: bytes
) -> dict[int, Any]:
    """Verify signature AND commitment; the *verified* side of overclaim.

    Returns the decoded payload map on success. Raises ``ValueError`` on
    any mismatch. A caller that has not run this (with a key it trusts)
    reports the statement as *reported, not verified* — never as
    witnessed. Accepts v2 and v3 (see :func:`verify_statement`, which
    also says what was established about a v3 root).
    """
    return verify_statement(message, public_key, expected_head).payload
