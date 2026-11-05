"""The trust policy and key states (anchoring 0.2.0, "The trust policy and key states")."""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from asn1crypto import keys as a1keys

from .common import hex_lenient, parse_utc, fmt_instant


def _norm_key(raw):
    """'The comparison is of the key bytes, whatever each entry labels its algorithm, and however the bytes
    are written: an Ed25519 key is its 32 raw bytes; a P-256 key is its point, written compressed or
    uncompressed; an RSA key is its modulus and exponent, written in DER as an RSAPublicKey (RFC 8017)
    or a SubjectPublicKeyInfo (RFC 5280).'"""
    if raw is None:
        return None
    if len(raw) in (33, 65) and raw[0] in (2, 3, 4):
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
            n = pk.public_numbers()
            return ("p256", n.x, n.y)
        except Exception:
            pass
    if raw[:1] == b"\x30":
        try:
            spki = serialization.load_der_public_key(raw)
            from cryptography.hazmat.primitives.asymmetric import rsa
            if isinstance(spki, rsa.RSAPublicKey):
                n = spki.public_numbers()
                return ("rsa", n.n, n.e)
            if isinstance(spki, ec.EllipticCurvePublicKey):
                n = spki.public_numbers()
                return ("p256", n.x, n.y)
        except Exception:
            pass
        try:
            k = a1keys.RSAPublicKey.load(raw, strict=True)
            return ("rsa", int(k["modulus"].native), int(k["public_exponent"].native))
        except Exception:
            pass
    return ("raw", bytes(raw))


def accept(policy):
    """Return (accepted, reason). 'A verifier MUST refuse a policy that lists one public key twice, under two
    references, two holders or two roles, or that gives one reference to two entries.' The duplicate check
    'keeps the lenient read'. References are compared within each list (A07)."""
    if not isinstance(policy, dict):
        return False, "the trust policy is not an object"
    for list_name, ref in (("tsas", "tsa_ref"), ("keys", "key_ref"), ("checkpoint_sources", "source_ref"),
                           ("bitcoin_header_sources", "source_ref")):
        seen = set()
        for e in policy.get(list_name, []) or []:
            r = e.get(ref) if isinstance(e, dict) else None
            if r in seen:
                return False, "one reference names two entries (%s %r)" % (list_name, r)
            seen.add(r)
    seen = {}
    for e in policy.get("keys", []) or []:
        nk = _norm_key(hex_lenient(e.get("public_key_hex")))
        if nk is None:
            continue
        if nk in seen:
            return False, "one public key is listed twice (%s and %s)" % (seen[nk], e.get("key_ref"))
        seen[nk] = e.get("key_ref")
    return True, None


def key(policy, key_ref):
    for e in policy.get("keys", []) or []:
        if e.get("key_ref") == key_ref:
            return e
    return None


def source(policy, source_ref):
    for e in policy.get("checkpoint_sources", []) or []:
        if e.get("source_ref") == source_ref:
            return e
    return None


def tsa(policy, tsa_ref):
    for e in policy.get("tsas", []) or []:
        if e.get("tsa_ref") == tsa_ref:
            return e
    return None


def is_scitt(src):
    return src.get("kind") == "transparency_log" and src.get("format") == "scitt"


def is_witness_src(src):
    return src.get("kind") == "witness"


def key_listings(policy, key_ref):
    """Where the policy lists a key: (for a witness source, for a SCITT source as witness key)."""
    w = s = False
    for src in policy.get("checkpoint_sources", []) or []:
        if key_ref in (src.get("key_refs") or []):
            if is_witness_src(src):
                w = True
            elif is_scitt(src):
                s = True
    return w, s


def key_state(policy, key_ref, stated, covering):
    """The key's state when it signed (README, last bullets of "The trust policy and key states").

    stated: the signer's stated time (text). covering: list of (T datetime, timestamp_index) of verified
    independent timestamps over the signature value; the earliest is used. Returns a result dict.
    """
    k = key(policy, key_ref)
    res = {"key_ref": key_ref}
    if k is None:
        res.update(status="failed", findings=["the key is not in the trust policy"])
        return res
    reason = k.get("revocation_reason")
    if reason is not None:
        res["revocation_reason"] = reason
    nb, na = parse_utc(k.get("not_before")), parse_utc(k.get("not_after"))
    ra = parse_utc(k.get("revoked_at")) if "revoked_at" in k else None
    if nb is None or na is None or ("revoked_at" in k and ra is None):
        res.update(status="failed", findings=["a time in the policy's entry for the key is not a real UTC time"])
        return res
    st = parse_utc(stated)
    if st is None:
        res.update(status="failed", findings=["the stated time %r is not a real UTC time, so the key's state cannot be read" % (stated,)])
        return res
    ts = sorted(covering, key=lambda x: x[0])
    if ts:
        t, idx = ts[0]
        res.update(time_basis="independent_timestamp", time=fmt_instant(t), timestamp_index=idx)
    else:
        t = st
        res.update(time_basis="stated_time", time=fmt_instant(st))
    # 'Only the stated time can show that a signature was made after not_before'
    if st < nb:
        res.update(status="failed", findings=["made before the key's not_before (stated time)"])
        return res
    if t > na:
        res.update(status="failed", findings=["made after the key's not_after"])
        return res
    if reason == "compromised":
        if not ts:
            res.update(status="unavailable", findings=["key compromised; no independent timestamp covers the signature, so the time cannot be established"])
            return res
        if t >= ra:
            res.update(status="failed", findings=["key compromised; the earliest independent timestamp is not earlier than revoked_at"])
            return res
    elif reason == "superseded":
        if t >= ra:
            res.update(status="failed", findings=["key superseded; the signature's time is not before revoked_at"])
            return res
        if not ts:
            res.setdefault("findings", []).append("superseded key: the time is the signer's statement, not independent time")
    res["status"] = "verified"
    return res
