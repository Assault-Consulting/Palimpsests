"""An RFC 3161 time-stamp token checked as anchoring 0.2.0 lists it ("An independent timestamp", checks 1 to 7).

Only asn1crypto (parsing, keeping the bytes it parsed) and cryptography (signatures, certificates) are used.
"""
import datetime as _dt
import hashlib
import re

from asn1crypto import cms, tsp as a1tsp, x509 as a1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .common import b64_strict, parse_utc

OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_RSA = "1.2.840.113549.1.1.1"
SUPPORTED = {OID_ECDSA_SHA256: "ecdsa", OID_SHA256_RSA: "rsa"}


def _gen_time(raw):
    """genTime 'is in UTC (it ends in Z)'. GeneralizedTime YYYYMMDDHHMMSS[.f]Z."""
    m = re.fullmatch(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(\.[0-9]+)?Z", raw)
    if not m:
        return None
    y, mo, d, h, mi, s, frac = m.groups()
    micro = int(((frac[1:] if frac else b"") + b"000000")[:6]) if frac else 0
    try:
        return _dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


def parse_token(der):
    """Check 1, token. Returns (parsed dict, finding). parsed has signed_data, signer, tst, tst_bytes, gen, T."""
    try:
        ci = cms.ContentInfo.load(der, strict=True)
        if ci["content_type"].dotted != OID_SIGNED_DATA:
            return None, "not a ContentInfo carrying SignedData"
        sd = ci["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].dotted != OID_TSTINFO:
            return None, "encapsulated content is not of type id-ct-TSTInfo"
        sis = sd["signer_infos"]
        if len(sis) != 1:
            return None, "the token has %d signers, not exactly one" % len(sis)
        content = eci["content"]
        tst_bytes = content.contents if hasattr(content, "contents") else None
        if tst_bytes is None:
            return None, "no encapsulated TSTInfo"
        tst = a1tsp.TSTInfo.load(tst_bytes, strict=True)
        tst.native  # force a full parse
        sd["signer_infos"].native
        if int(tst["version"]) != 1:
            return None, "TSTInfo version is not 1"
        gen = _gen_time(tst["gen_time"].contents)
        if gen is None:
            return None, "genTime is not a UTC GeneralizedTime ending in Z"
        T = gen
        acc = tst["accuracy"]
        if acc.native is not None:
            sec = acc["seconds"].native
            mil = acc["millis"].native
            mic = acc["micros"].native
            if sec is not None and sec < 0:
                return None, "accuracy seconds negative"
            if mil is not None and not (1 <= mil <= 999):
                return None, "accuracy millis outside 1 to 999"
            if mic is not None and not (1 <= mic <= 999):
                return None, "accuracy micros outside 1 to 999"
            try:
                T = gen + _dt.timedelta(seconds=sec or 0, milliseconds=mil or 0, microseconds=mic or 0)
            except OverflowError:
                return None, "genTime plus the accuracy is not a time the report can write"
            if T.year > 9999:
                return None, "genTime plus the accuracy is past the year 9999"
        return {"sd": sd, "signer": sis[0], "tst": tst, "tst_bytes": tst_bytes, "gen": gen, "T": T}, None
    except OverflowError:
        return None, "genTime plus the accuracy is not a time the report can write"
    except Exception as e:  # any parse failure is 'not a token'
        return None, "not a time-stamp token (%s)" % type(e).__name__


def _attrs(signer):
    sa = signer["signed_attrs"]
    if sa.native is None:
        return None, []
    out = []
    for a in sa:
        out.append((a["type"].dotted, a["values"]))
    return sa, out


def check_imprint(p, subject_value):
    mi = p["tst"]["message_imprint"]
    alg = mi["hash_algorithm"]["algorithm"].dotted
    if alg != OID_SHA256:
        return "failed", "messageImprint is not made with SHA-256 (%s)" % alg
    if mi["hashed_message"].native != hashlib.sha256(subject_value).digest():
        return "failed", "messageImprint is not the SHA-256 of the subject's bytes"
    return "verified", None


def check_message_digest(p):
    sa, attrs = _attrs(p["signer"])
    if sa is None:
        return "failed", "no signed attributes"
    ct = [v for t, v in attrs if t == OID_CONTENT_TYPE]
    md = [v for t, v in attrs if t == OID_MESSAGE_DIGEST]
    if len(ct) != 1 or len(ct[0]) != 1 or ct[0][0].dotted != OID_TSTINFO:
        return "failed", "not one signed content-type attribute of id-ct-TSTInfo"
    if len(md) != 1 or len(md[0]) != 1 or md[0][0].native != hashlib.sha256(p["tst_bytes"]).digest():
        return "failed", "the signed messageDigest is not the SHA-256 of the TSTInfo bytes"
    return "verified", None


def load_pinned(entry):
    der = b64_strict(entry.get("certificate_b64"))
    if der is None:
        return None
    try:
        c = x509.load_der_x509_certificate(der)
        a = a1x509.Certificate.load(der, strict=True)
        a.native
        c.public_key()
        return der, c, a
    except Exception:
        return None


def check_signature(p, pinned):
    der, cert, acert = pinned
    signer = p["signer"]
    sid = signer["sid"]
    if sid.name == "issuer_and_serial_number":
        ias = sid.chosen
        ok = (ias["issuer"].dump() == acert["tbs_certificate"]["issuer"].dump()
              and ias["serial_number"].native == acert.serial_number)
    else:
        ok = sid.chosen.native == acert.key_identifier
    if not ok:
        return "failed", "the signer identifier does not name the pinned certificate"
    alg = signer["signature_algorithm"]["algorithm"].dotted
    dig = signer["digest_algorithm"]["algorithm"].dotted
    kind = SUPPORTED.get(alg)
    if alg == OID_RSA and dig == OID_SHA256:
        kind = "rsa"
    if kind is None or dig != OID_SHA256:
        return "not_supported", "signature algorithm %s with digest %s is not supported by this check" % (alg, dig)
    pub = cert.public_key()
    sa = signer["signed_attrs"]
    if sa.native is None:
        return "failed", "no signed attributes to verify"
    data = b"\x31" + sa.dump()[1:]  # their DER encoding as a SET OF (RFC 5652 5.4)
    sig = signer["signature"].native
    try:
        if kind == "ecdsa":
            if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
                return "failed", "an ECDSA P-256 signature does not fit the pinned certificate's key"
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            if not isinstance(pub, rsa.RSAPublicKey):
                return "failed", "an RSA signature does not fit the pinned certificate's key"
            pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return "failed", "the signature over the signed attributes does not verify with the pinned key"
    return "verified", None


def check_signer_certificate(p, pinned):
    sa, attrs = _attrs(p["signer"])
    vals = [v for t, v in attrs if t == OID_SIGNING_CERT_V2]
    if not vals:
        return "not_checked", "no signingCertificateV2: identified by its signer identifier alone"
    if len(vals) != 1 or len(vals[0]) != 1:
        return "failed", "signingCertificateV2 is not one attribute with one value"
    try:
        scv2 = vals[0][0]
        certs = scv2["certs"]
        first = certs[0]
        halg = first["hash_algorithm"]["algorithm"].dotted if first["hash_algorithm"].native else OID_SHA256
        if halg != OID_SHA256:
            return "not_checked", "the first ESSCertIDv2 is made with another hash: read as if there were none"
        if first["cert_hash"].native != hashlib.sha256(pinned[0]).digest():
            return "failed", "the ESSCertIDv2 hash is not that of the pinned certificate"
        return "verified", None
    except Exception as e:
        return "failed", "signingCertificateV2 cannot be read (%s)" % type(e).__name__


def check_tsa_state(entry, gen):
    nb, na = parse_utc(entry.get("not_before")), parse_utc(entry.get("not_after"))
    has_rev = "revoked_at" in entry
    ra = parse_utc(entry.get("revoked_at")) if has_rev else None
    if nb is None or na is None or (has_rev and ra is None):
        return "failed", "a time in the policy's entry for the authority is not a real UTC time"
    if gen < nb or gen > na:
        return "failed", "genTime is outside the policy's window for the authority"
    if has_rev:
        if entry.get("revocation_reason") == "compromised":
            return "failed", "the authority was revoked as compromised: none of its tokens counts"
        if gen >= ra:
            return "failed", "genTime is not before the authority was superseded"
    return "verified", None
