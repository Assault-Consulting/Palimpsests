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
  as *reported, not verified*. :func:`verify_statement` is the *verified*
  path — and the only one: it refuses with :class:`StatementRefused`,
  whose ``code`` names the check that failed.

What this module is, as an API (``docs/INTEGRATION-SURFACE.md``, channel
8): it needs the ``[scitt]`` extra and raises :class:`ScittUnavailable`
without it; a key is a ``cryptography`` public (or, to sign, private) key
object, loaded by the caller; and it verifies **statements**, never
receipts — whether a transparency service registered a statement is that
service's protocol to check, not this module's.

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
    "ALG_ED25519",
    "ALG_EDDSA",
    "ALG_ES256",
    "CONTENT_TYPE",
    "CONTENT_TYPE_V3",
    "FORMAT_ID",
    "STATEMENT_REFUSAL_CODES",
    "ScittUnavailable",
    "StatementCheck",
    "StatementRefused",
    "build_signed_statement",
    "check_statement_against_head",
    "head_payload",
    "verify_statement",
]

ALG_ES256 = -7
ALG_EDDSA = -8
#: RFC 9864: the fully-specified identifier for Ed25519. ``-8`` ("EdDSA")
#: names a family and leaves the curve to the key; ``-19`` names the curve.
#: Here both mean Ed25519 and nothing else — an Ed448 key is refused under
#: either — so the two identifiers differ in one signed byte of the
#: protected header and in nothing a verifier computes. Admitted in both
#: constructions (v2 and v3) since 0.15; the default a builder uses is
#: unchanged, because a service has to accept ``-19`` before a deployment
#: can register with it.
ALG_ED25519 = -19
_ALGS_ED25519 = (ALG_EDDSA, ALG_ED25519)
_ALGS = (ALG_ES256, *_ALGS_ED25519)
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


#: Every reason :func:`verify_statement` refuses a statement, as codes. The
#: code is what a caller branches on; the message beside it is a sentence
#: and may be reworded in any release. Open vocabulary: a release may add a
#: code, never rename one or give it another meaning.
STATEMENT_REFUSAL_CODES = frozenset({
    # the bytes are not this kind of message
    "not_cose_sign1",  # not one tagged COSE_Sign1 with four members
    "trailing_bytes",  # a COSE_Sign1, followed by bytes that are not part of it
    "protected_header_malformed",  # the protected bucket is not an encoded CBOR map
    "detached_payload",  # payload nil: this construction is attached, always
    "payload_malformed",  # the signed payload is not an encoded CBOR map
    "repeated_key",  # a map that repeats a key reads two ways
    "indefinite_length_map",  # its keys cannot be counted
    # the signature
    "unsupported_alg",  # not ES256 (-7), EdDSA (-8) or Ed25519 (-19)
    "key_type_mismatch",  # not a key of the one type the alg means here
    "signature_invalid",  # does not verify under the key given
    # what was signed is not what was expected
    "head_mismatch",  # commits to another chain head
    "format_id_mismatch",
    "range_invalid",  # not 0 <= first_seq <= last_seq
    "content_type_unknown",
    "payload_keys_mismatch",  # the keys its own content type does not allow
    "protected_labels_mismatch",  # other than alg, content type, kid, CWT claims
    "root_malformed",  # a v3 root that is not 32 bytes
    # against the chain at hand
    "chain_too_short",  # fewer records than the statement's range
    "root_mismatch",  # not the derived root of this chain
})


_KEY_TYPE_MESSAGE = (
    "the key is not of the type COSE alg {alg} means in this construction: "
    "-7 is ECDSA on P-256, -8 and -19 are Ed25519 (not Ed448)"
)


class StatementRefused(ValueError):
    """:func:`verify_statement` did not accept the statement.

    ``code`` is one of :data:`STATEMENT_REFUSAL_CODES` and is the contract;
    ``str(exc)`` is a sentence for a person. A subclass of ``ValueError``,
    which is what the verifier raised before 0.15 — ``except ValueError``
    keeps working.

    A refusal says the statement is not *this construction, verified under
    this key, committing to this head*. It does not say why: a statement
    for another chain, a corrupted download and a forgery are all refused,
    and the code names the check that failed, not a cause.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _decode_one(raw: Any, code: str, what: str) -> Any:
    """Decode exactly one CBOR item from ``raw``, or refuse with ``code``.

    cbor2 raises several exception types of its own on malformed input and
    silently ignores bytes after the first item; a verifier fed someone
    else's bytes needs one exception, and must not accept an artifact that
    is a statement plus something else.
    """
    import io

    cbor2 = _cbor2()
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise StatementRefused(code, f"{what} is not bytes")
    stream = io.BytesIO(bytes(raw))
    try:
        item = cbor2.CBORDecoder(stream).decode()
    except Exception as e:  # cbor2's decode errors do not share one base with ValueError
        raise StatementRefused(code, f"{what} is not well-formed CBOR") from e
    rest = len(stream.getbuffer()) - stream.tell()
    if rest:
        raise StatementRefused(
            "trailing_bytes" if code == "not_cose_sign1" else code,
            f"{what} is followed by {rest} byte(s) that are not part of it",
        )
    return item


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


def _key_fits_alg(public_key: Any, alg: int) -> bool:
    """Is this a key of the one type ``alg`` means in this construction?

    ES256 is ECDSA on P-256, and no other curve; ``-8`` and ``-19`` are
    Ed25519, and not Ed448. ``-8`` alone would let the key decide the curve
    — the ambiguity RFC 9864 removes — and before 0.15 this module went
    along: it signed and verified with an Ed448 key under ``-8`` while the
    ``kid`` it derived named Ed25519.
    """
    _hashes, ec, _decode, _encode = _crypto()
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if alg == ALG_ES256:
        return isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve, ec.SECP256R1)
    if alg in _ALGS_ED25519:
        return isinstance(public_key, ed25519.Ed25519PublicKey)
    return False


def _cose_key_thumbprint(public_key: Any, alg: int) -> bytes:
    """RFC 9679 COSE Key Thumbprint (SHA-256) — the default ``kid``.

    Deterministically encodes the required COSE_Key fields for the
    algorithm's key type and hashes them; two parties holding the same
    key derive the same identifier with no registry between them.
    """
    import hashlib

    cbor2 = _cbor2()
    if alg not in _ALGS:
        raise ValueError(f"unsupported COSE alg {alg}; this bridge takes -7, -8 or -19")
    if not _key_fits_alg(public_key, alg):
        raise ValueError(_KEY_TYPE_MESSAGE.format(alg=alg))
    # The thumbprint is of the key, not of the algorithm: the same Ed25519
    # key has the same kid under -8 and under -19, so a signer that moves
    # from one identifier to the other does not become someone else.
    if alg in _ALGS_ED25519:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        x = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        cose_key = {1: 1, -1: 6, -2: x}  # OKP / Ed25519 / x
    else:
        nums = public_key.public_numbers()
        cose_key = {
            1: 2,  # EC2
            -1: 1,  # P-256
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }
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
    if alg not in _ALGS:
        raise ValueError(f"unsupported COSE alg {alg}; this bridge takes -7, -8 or -19")
    if not _key_fits_alg(public_key, alg):
        raise ValueError(_KEY_TYPE_MESSAGE.format(alg=alg))
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
    else:
        sig = key.sign(tbs)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig]))


def _cose_parts(message: Any) -> tuple[bytes, dict, bytes, Any]:
    """(protected bytes, protected map, payload bytes, signature) of one
    tagged COSE_Sign1 — or a refusal that says which part is not one."""
    cbor2 = _cbor2()
    tag = _decode_one(message, "not_cose_sign1", "the message")
    if (
        not isinstance(tag, cbor2.CBORTag)
        or tag.tag != 18
        or not isinstance(tag.value, (list, tuple))
        or len(tag.value) != 4
    ):
        raise StatementRefused("not_cose_sign1", "not a COSE_Sign1 message")
    protected, _unprotected, payload, sig = tag.value
    if not isinstance(protected, bytes):
        raise StatementRefused(
            "protected_header_malformed", "the protected header is not a byte string")
    phdr = _decode_one(protected, "protected_header_malformed", "the protected header")
    if not isinstance(phdr, dict):
        raise StatementRefused(
            "protected_header_malformed", "the protected header is not a CBOR map")
    _distinct_keys(protected, phdr, "the protected header", "protected_header_malformed")
    if payload is None:
        raise StatementRefused(
            "detached_payload",
            "the payload is detached (nil); this construction always carries it")
    if not isinstance(payload, bytes):
        raise StatementRefused("payload_malformed", "the payload is not a byte string")
    return protected, phdr, payload, sig


def _cose_verify1(message: bytes, public_key: Any) -> bytes:
    """Verify a COSE_Sign1; return its payload, or raise :class:`StatementRefused`.

    Ed25519 verification here rejects a non-canonical scalar (S >= L,
    RFC 8032 §5.1.7) through its backend — the S + L variant of a valid
    signature does not verify; a test pins that behaviour.
    """
    hashes, ec, _, encode_dss = _crypto()
    protected, phdr, payload, sig = _cose_parts(message)
    alg = phdr.get(_HDR_ALG)
    if type(alg) is not int or alg not in _ALGS:
        raise StatementRefused("unsupported_alg", f"unsupported COSE alg {alg!r}")
    if not _key_fits_alg(public_key, alg):
        # Knowable before any signature is checked, and so said apart from
        # signature_invalid: the key handed in is not a key this algorithm
        # can mean here. A key of the right type that is the wrong key is
        # not knowable, and stays signature_invalid.
        raise StatementRefused("key_type_mismatch", _KEY_TYPE_MESSAGE.format(alg=alg))
    tbs = _sig_structure(protected, payload)
    try:
        if alg == ALG_ES256:
            if not isinstance(sig, bytes) or len(sig) != 64:
                raise ValueError("ES256 signature must be 64 bytes (P-1363)")
            der = encode_dss(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            public_key.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(sig, tbs)
    except Exception as e:
        # One code for every way a signature does not verify under a key of
        # the right type — the wrong key, an altered message, a malformed
        # signature: the verifier cannot tell them apart, and does not
        # pretend to.
        raise StatementRefused(
            "signature_invalid", "COSE_Sign1 signature verification failed") from e
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

    ``alg`` is ``ALG_ES256`` (the default), ``ALG_EDDSA`` or, since 0.15,
    ``ALG_ED25519`` (``-19``, RFC 9864). The last two sign identically; a
    statement under ``-19`` is refused by a verifier older than 0.15 and by
    any transparency service that has not adopted RFC 9864 — which is why
    it is a choice and not the default.

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


def _distinct_keys(raw: bytes, decoded: dict, what: str, malformed: str) -> None:
    """Refuse a map that repeats a key. A decoder keeps one of the values —
    cbor2 the last — and another reader may keep the other, so the same
    signed bytes would read two ways (RFC 8949 §5.6: such a map is not
    valid). Counted from the map's declared length; an indefinite-length map
    cannot be counted and is not the deterministic encoding either."""
    major, ai = raw[0] >> 5, raw[0] & 0x1F
    if major != 5:
        raise StatementRefused(malformed, f"{what} is not a CBOR map")
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        n = int.from_bytes(raw[1 : 1 + width], "big")
    else:
        raise StatementRefused(
            "indefinite_length_map",
            f"{what} is an indefinite-length map; its keys cannot be counted")
    if n != len(decoded):
        raise StatementRefused(
            "repeated_key",
            f"{what} repeats a key ({n} entries, {len(decoded)} distinct keys)")


def _check_protected_labels(phdr: dict) -> None:
    if set(phdr) != _PROTECTED_LABELS:
        raise StatementRefused(
            "protected_labels_mismatch",
            "this construction's protected header carries exactly labels 1, 3, 4 "
            f"and 15 (alg, content type, kid, CWT claims); this one carries {_keys(phdr)}"
        )


def _keys(decoded: dict) -> list:
    """A map's keys for a message — sorted where they can be, as they are
    where they cannot (a signed map may mix integers and text)."""
    try:
        return sorted(decoded)
    except TypeError:
        return list(decoded)


def _decode_payload(payload: bytes) -> dict:
    decoded = _decode_one(payload, "payload_malformed", "the statement payload")
    if not isinstance(decoded, dict):
        raise StatementRefused("payload_malformed", "statement payload is not a CBOR map")
    _distinct_keys(payload, decoded, "the statement payload", "payload_malformed")
    return decoded


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
    recomputed.

    Raises :class:`StatementRefused` — a ``ValueError`` — for every
    statement it does not accept, malformed bytes included; ``.code`` is
    one of :data:`STATEMENT_REFUSAL_CODES`. A message, a protected header
    or a payload that is one CBOR item *followed by further bytes* is
    refused: bytes outside the item are outside the signature's meaning,
    and an artifact that is a statement plus something else is not the
    statement.
    """
    payload = _cose_verify1(message, public_key)
    decoded = _decode_payload(payload)
    if decoded.get(_PAYLOAD_HEAD) != expected_head:
        raise StatementRefused(
            "head_mismatch", "statement does not commit to the expected chain head")
    if decoded.get(_PAYLOAD_FORMAT) != FORMAT_ID:
        raise StatementRefused(
            "format_id_mismatch", f"statement format id is not {FORMAT_ID!r}")
    first, last = decoded.get(_PAYLOAD_FIRST_SEQ), decoded.get(_PAYLOAD_LAST_SEQ)
    if not (
        type(first) is int and type(last) is int and 0 <= first <= last
    ):
        # The builder refuses an inverted range; a verifier must too. The root
        # depends only on last_seq, so an inverted statement would otherwise
        # verify with a root correct for its last_seq (bridge run B3, F4).
        raise StatementRefused(
            "range_invalid", "a statement's range must satisfy 0 <= first_seq <= last_seq")
    _protected, phdr, _payload, _sig = _cose_parts(message)
    ctype = phdr.get(_HDR_CONTENT_TYPE)
    encoding = (
        "deterministic"
        if _cbor2().dumps(decoded, canonical=True) == payload
        else "not deterministic"
    )
    v2_keys = {_PAYLOAD_HEAD, _PAYLOAD_FIRST_SEQ, _PAYLOAD_LAST_SEQ, _PAYLOAD_FORMAT}
    if ctype == CONTENT_TYPE:
        if set(decoded) != v2_keys:
            raise StatementRefused(
                "payload_keys_mismatch",
                "a v2 statement carries exactly payload keys 1-4; this one carries "
                f"{_keys(decoded)} (a root under the v2 content type is not read)"
            )
        _check_protected_labels(phdr)
        return StatementCheck("v2", decoded, None, "absent", encoding)
    if ctype != CONTENT_TYPE_V3:
        raise StatementRefused(
            "content_type_unknown", f"unknown statement content type {ctype!r}")
    if set(decoded) != v2_keys | {_PAYLOAD_ROOT}:
        raise StatementRefused(
            "payload_keys_mismatch",
            f"a v3 statement carries payload keys 1-5; this one carries {_keys(decoded)}",
        )
    root = decoded[_PAYLOAD_ROOT]
    if not isinstance(root, bytes) or len(root) != _HEAD_LEN:
        raise StatementRefused("root_malformed", f"a v3 root is {_HEAD_LEN} bytes")
    _check_protected_labels(phdr)
    if reader is None:
        return StatementCheck("v3", decoded, root, "carried, not recomputed", encoding)
    from palimpsests.audit.pala.proofs import chain_root

    last_seq = decoded[_PAYLOAD_LAST_SEQ]
    try:
        expected_root = chain_root(reader, last_seq + 1)
    except IndexError as e:
        raise StatementRefused(
            "chain_too_short",
            f"the chain at hand has fewer than {last_seq + 1} records; the root "
            "cannot be recomputed from it"
        ) from e
    if root != expected_root:
        raise StatementRefused(
            "root_mismatch",
            "the statement's root is not the derived root over records "
            f"0..{last_seq} of this chain"
        )
    return StatementCheck("v3", decoded, root, "recomputed", encoding)


def check_statement_against_head(
    message: bytes, public_key: Any, expected_head: bytes
) -> dict[int, Any]:
    """Deprecated since 0.15: use :func:`verify_statement`.

    The same verification, returning only the payload map — and so unable
    to say what was established about a v3 root, or how the payload was
    encoded. There is one verifier; this name remains until 1.0 and emits
    a ``DeprecationWarning``.
    """
    import warnings

    warnings.warn(
        "check_statement_against_head is deprecated since 0.15 and will be removed "
        "in 1.0; use verify_statement(...), whose result carries .payload",
        DeprecationWarning,
        stacklevel=2,
    )
    return verify_statement(message, public_key, expected_head).payload
