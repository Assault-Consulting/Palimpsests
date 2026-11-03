"""Trust policy, key states and RFC 3161 timestamps, written from anchoring 0.2.0 ("Signed bytes",
"An independent timestamp", "The trust policy and key states") and signatures 0.2.0 ("The trust
policy and key states", "Independent timestamps over signature values")."""
import base64, hashlib, re
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from asn1crypto import cms, tsp, keys as akeys, core as acore
from dps_common import real_utc, utc_text, sha256_hex

REFUSED = "not checked: the trust policy is refused (%s)"


# ---- the policy ---------------------------------------------------------------------------
def _canon_key(hexstr):
    """The lenient read used for the refusal: whitespace stripped, decoded; Ed25519 raw, P-256 point
    (either encoding), RSA by modulus and exponent (SPKI or PKCS#1)."""
    h = re.sub(r"\s", "", hexstr or "")
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return ("raw", h)
    if len(b) in (33, 65) and b[0] in (2, 3, 4):
        try:
            pt = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b)
            return ("p256", pt.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        except Exception:
            pass
    try:
        k = serialization.load_der_public_key(b)
        if isinstance(k, rsa.RSAPublicKey):
            n = k.public_numbers()
            return ("rsa", (n.n, n.e))
        if isinstance(k, ec.EllipticCurvePublicKey):
            return ("p256", k.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        if isinstance(k, ed25519.Ed25519PublicKey):
            return ("raw", k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    except Exception:
        pass
    try:
        rk = akeys.RSAPublicKey.load(b, strict=True)
        return ("rsa", (int(rk["modulus"]), int(rk["public_exponent"])))
    except Exception:
        pass
    return ("raw", b)


def policy_refusal(policy):
    """None if accepted, else the reason. Anchoring: one public key, one reference, one holder,
    one role; one reference, one entry."""
    keys = policy.get("keys", [])
    seen_ref = {}
    for coll, field in (("keys", "key_ref"), ("tsas", "tsa_ref"), ("checkpoint_sources", "source_ref"),
                        ("bitcoin_header_sources", "source_ref")):
        names = {}
        for e in policy.get(coll, []) or []:
            r = e.get(field)
            if r in names:
                return "the reference %r names two entries" % r
            names[r] = 1
    by_key = {}
    for e in keys:
        ck = _canon_key(e.get("public_key_hex"))
        if ck in by_key:
            f = by_key[ck]
            diffs = []
            for m in ("key_ref", "holder", "role"):
                if f.get(m) != e.get(m):
                    diffs.append("%s %r and %r" % (m, f.get(m), e.get(m)))
            if f.get("algorithm") != e.get("algorithm"):
                diffs.append("labels %r and %r" % (f.get("algorithm"), e.get("algorithm")))
            lf, le = len(re.sub(r"\s", "", f.get("public_key_hex", ""))) // 2, len(re.sub(r"\s", "", e.get("public_key_hex", ""))) // 2
            if lf != le:
                diffs.append("lengths %d and %d bytes" % (lf, le))
            return "one public key listed twice: %s" % ("; ".join(diffs) or "two entries")
        by_key[ck] = e
    return None


def find_key(policy, key_ref):
    for e in policy.get("keys", []):
        if e.get("key_ref") == key_ref:
            return e
    return None


def strict_key_bytes(e):
    h = e.get("public_key_hex")
    if not isinstance(h, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", h):
        return None, "public_key_hex is not lowercase hex pairs and nothing else"
    return bytes.fromhex(h), None


def ed25519_verify(e, data, sig):
    kb, why = strict_key_bytes(e)
    if kb is None:
        return False, why
    if len(kb) != 32:
        return False, "an Ed25519 key is 32 bytes"
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(kb).verify(sig, data)
        return True, None
    except InvalidSignature:
        return False, "the signature does not verify over the signed bytes built"
    except Exception as ex:
        return False, "cannot verify: %s" % ex


def certificate_holds(e, kb):
    """signatures: the certificate the policy pins for the key holds it. Returns status, reason."""
    cb = e.get("certificate_b64")
    if cb is None:
        return "not_checked", "no certificate is pinned"
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(cb, validate=True))
        pk = cert.public_key()
        raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) \
            if isinstance(pk, ed25519.Ed25519PublicKey) else None
    except Exception as ex:
        return "failed", "the pinned certificate cannot be read: %s" % ex
    if raw != kb:
        return "failed", "the pinned certificate does not hold the key"
    return "verified", None


# ---- key states (anchoring "The trust policy and key states") -----------------------------
def key_state(e, stated, ts_times, refused=None):
    """ts_times: list of (T, index) for verified timestamps over the signature value.
    Returns dict with status, key_ref, time_basis, time, timestamp_index, revocation_reason, findings."""
    out = {"status": "verified", "key_ref": e.get("key_ref") if e else None}
    if refused:
        return {"status": "failed", "key_ref": out["key_ref"], "findings": [REFUSED % refused]}
    nb, r1 = real_utc(e.get("not_before"))
    na, r2 = real_utc(e.get("not_after"))
    ra = None
    if "revoked_at" in e:
        ra, r3 = real_utc(e.get("revoked_at"))
        if ra is None:
            return {"status": "failed", "key_ref": out["key_ref"], "findings": ["policy time: %s" % r3]}
    if nb is None or na is None:
        return {"status": "failed", "key_ref": out["key_ref"], "findings": ["policy time: %s" % (r1 or r2)]}
    st, rs = real_utc(stated)
    if st is None:
        return {"status": "failed", "key_ref": out["key_ref"], "findings": ["the stated time cannot be read: %s" % rs]}
    reason = e.get("revocation_reason")
    if reason:
        out["revocation_reason"] = reason
    if ts_times:
        T, idx = min(ts_times, key=lambda x: (x[0], x[1]))
        out.update(time_basis="independent_timestamp", time=utc_text(T), timestamp_index=idx)
        when = T
    else:
        out.update(time_basis="stated_time", time=stated)
        when = st
    f = []
    if st < nb:
        f.append("the stated time is before the key's not_before")
    if when > na:
        f.append("after the key's not_after")
    if reason == "compromised":
        if not ts_times:
            return {"status": "unavailable", "key_ref": out["key_ref"], "revocation_reason": reason,
                    "findings": ["the key is compromised and no independent timestamp covers the signature: the time cannot be established"]}
        if when >= ra:
            f.append("the earliest independent timestamp is at or after the compromise")
    elif reason == "superseded":
        if when >= ra:
            f.append("the key was superseded at or before that time")
    if f:
        out["status"] = "failed"
        out["findings"] = f
    return out


# ---- RFC 3161 tokens ----------------------------------------------------------------------
def _gen_text(tst):
    return tst["gen_time"].contents.decode("ascii", "replace")


def check_token(token_b64, subject_bytes, subject_check, tsa_ref, policy, refused=None):
    """anchoring's seven checks. subject_check: (status, finding) for subject_bytes.
    Returns dict of checks, status, T (Fraction) when verified."""
    from fractions import Fraction
    import datetime as dt
    C = {}
    T = None
    info = None
    try:
        der = base64.b64decode(token_b64, validate=True)
        ci = cms.ContentInfo.load(der, strict=True)
        if ci["content_type"].native != "signed_data":
            raise ValueError("not SignedData")
        sd = ci["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            raise ValueError("encapsulated content is not id-ct-TSTInfo")
        if len(sd["signer_infos"]) != 1:
            raise ValueError("not exactly one signer")
        tst_der = eci["content"].contents
        tst = tsp.TSTInfo.load(tst_der, strict=True)
        if tst["version"].native != "v1":
            raise ValueError("TSTInfo version is not 1")
        g = _gen_text(tst)
        if not g.endswith("Z"):
            raise ValueError("genTime is not in UTC: %s" % g)
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z", g)
        if not m:
            raise ValueError("genTime cannot be read: %s" % g)
        y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
        base = Fraction(dt.date(y, mo, d).toordinal() * 86400 + h * 3600 + mi * 60 + s)
        if m.group(7):
            base += Fraction(m.group(7)[1:]) / 10 ** (len(m.group(7)) - 1)
        acc = Fraction(0)
        a = tst["accuracy"]
        if a.native is not None:
            sec = a["seconds"].native or 0
            mil = a["millis"].native
            mic = a["micros"].native
            if sec < 0:
                raise ValueError("accuracy seconds negative")
            if mil is not None and not (1 <= mil <= 999):
                raise ValueError("accuracy millis outside 1..999")
            if mic is not None and not (1 <= mic <= 999):
                raise ValueError("accuracy micros outside 1..999")
            acc = Fraction(sec) + Fraction(mil or 0, 1000) + Fraction(mic or 0, 1000000)
        Tc = base + acc
        if Tc >= Fraction(dt.date(9999, 12, 31).toordinal() * 86400 + 86400):
            raise ValueError("genTime plus accuracy is not before the year 10000")
        C["token"] = {"status": "verified"}
        info = (sd, tst, tst_der, base, Tc)
    except Exception as ex:
        C["token"] = {"status": "failed", "findings": ["%s" % ex]}
    if info is None:
        for k in ("message_imprint", "message_digest", "tsa_signature", "signer_certificate", "tsa_state"):
            C[k] = {"status": "not_checked", "findings": ["the token cannot be read"]}
        C["subject_bytes"] = {"status": subject_check[0]} if subject_check[0] else {"status": "not_checked"}
        return {"status": "failed", "checks": C}
    sd, tst, tst_der, base, Tc = info
    mi_ = tst["message_imprint"]
    if mi_["hash_algorithm"]["algorithm"].native != "sha256":
        C["message_imprint"] = {"status": "failed", "findings": ["not made with SHA-256"]}
    elif subject_bytes is None or mi_["hashed_message"].native != hashlib.sha256(subject_bytes).digest():
        C["message_imprint"] = {"status": "failed", "findings": ["the imprint is not the SHA-256 of the subject's bytes"]}
    else:
        C["message_imprint"] = {"status": "verified"}
    C["subject_bytes"] = {"status": subject_check[0]}
    if subject_check[1]:
        C["subject_bytes"]["findings"] = [subject_check[1]]
    si = sd["signer_infos"][0]
    sa = si["signed_attrs"]
    try:
        cts = [x for x in sa if x["type"].native == "content_type"]
        mds = [x for x in sa if x["type"].native == "message_digest"]
        ok = (len(cts) == 1 and len(cts[0]["values"]) == 1 and cts[0]["values"][0].native == "tst_info"
              and len(mds) == 1 and len(mds[0]["values"]) == 1
              and mds[0]["values"][0].native == hashlib.sha256(tst_der).digest())
        C["message_digest"] = {"status": "verified"} if ok else {"status": "failed", "findings": ["the signed content-type or messageDigest attribute is not as required"]}
    except Exception as ex:
        C["message_digest"] = {"status": "failed", "findings": [str(ex)]}
    tsa = next((t for t in policy.get("tsas", []) if t.get("tsa_ref") == tsa_ref), None)
    cert = None
    if refused:
        C["tsa_signature"] = {"status": "failed", "findings": [REFUSED % refused]}
        C["tsa_state"] = {"status": "failed", "findings": [REFUSED % refused]}
    elif tsa is None:
        C["tsa_signature"] = {"status": "failed", "findings": ["the policy lists no authority %r" % tsa_ref]}
        C["tsa_state"] = {"status": "not_checked", "findings": ["the policy lists no authority %r: no window to compare with" % tsa_ref]}
    else:
        try:
            cder = base64.b64decode(tsa["certificate_b64"], validate=True)
            cert = x509.load_der_x509_certificate(cder)
            acert = x509_asn1 = __import__("asn1crypto.x509", fromlist=["Certificate"]).Certificate.load(cder)
        except Exception as ex:
            C["tsa_signature"] = {"status": "failed", "findings": ["the pinned certificate cannot be read: %s" % ex]}
            cert = None
        if cert is not None:
            C["tsa_signature"] = _tsa_sig(si, sa, cert, acert)
            # signer_certificate
            scs = [x for x in sa if x["type"].dotted == "1.2.840.113549.1.9.16.2.47"]
            if not scs:
                C["signer_certificate"] = {"status": "not_checked", "findings": ["no ESSCertIDv2: identified by the signer identifier alone"]}
            elif len(scs) != 1 or len(scs[0]["values"]) != 1:
                C["signer_certificate"] = {"status": "failed", "findings": ["signingCertificateV2 is not one attribute with one value"]}
            else:
                try:
                    v = scs[0]["values"][0]
                    certs = v["certs"] if hasattr(v, "__getitem__") and not isinstance(v, acore.Any) else None
                    if certs is None:
                        v = tsp.SigningCertificateV2.load(scs[0]["values"][0].dump())
                        certs = v["certs"]
                    first = certs[0]
                    halg = first["hash_algorithm"]["algorithm"].native
                    if halg != "sha256":
                        C["signer_certificate"] = {"status": "not_checked", "findings": ["the first ESSCertIDv2 is made with %s: read as if there were none" % halg]}
                    elif first["cert_hash"].native != hashlib.sha256(cder).digest():
                        C["signer_certificate"] = {"status": "failed", "findings": ["ESSCertIDv2 names another certificate"]}
                    else:
                        C["signer_certificate"] = {"status": "verified"}
                except Exception as ex:
                    C["signer_certificate"] = {"status": "failed", "findings": ["signingCertificateV2 cannot be read: %s" % ex]}
        # tsa_state
        nb, r1 = real_utc(tsa.get("not_before"))
        na, r2 = real_utc(tsa.get("not_after"))
        ra, r3 = (real_utc(tsa["revoked_at"]) if "revoked_at" in tsa else (None, None))
        if nb is None or na is None or ("revoked_at" in tsa and ra is None):
            C["tsa_state"] = {"status": "failed", "findings": ["policy time: %s" % (r1 or r2 or r3)]}
        elif base < nb or base > na:
            C["tsa_state"] = {"status": "failed", "findings": ["genTime outside the authority's window"]}
        elif tsa.get("revocation_reason") == "compromised":
            C["tsa_state"] = {"status": "failed", "findings": ["the authority is revoked as compromised"]}
        elif tsa.get("revocation_reason") == "superseded" and base >= ra:
            C["tsa_state"] = {"status": "failed", "findings": ["genTime at or after the authority was superseded"]}
        else:
            C["tsa_state"] = {"status": "verified"}
    C.setdefault("signer_certificate", {"status": "not_checked", "findings": ["no pinned certificate read"]})
    statuses = [C[k]["status"] for k in C if k != "signer_certificate"]
    if C["signer_certificate"]["status"] == "failed":
        statuses.append("failed")
    if all(s == "verified" for s in statuses):
        status = "verified"
    elif "failed" in statuses:
        status = "failed"
    elif "not_supported" in statuses:
        status = "not_supported"
    else:
        status = "not_checked"
    out = {"status": status, "checks": C, "gen_time": utc_text(base)}
    if status == "verified":
        out["T"] = Tc
    return out


def _tsa_sig(si, sa, cert, acert):
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        ok = (sid.chosen["serial_number"].native == acert.serial_number and
              sid.chosen["issuer"].dump() == acert.issuer.dump())
    else:
        ok = sid.chosen.native == acert.key_identifier
    if not ok:
        return {"status": "failed", "findings": ["the signer identifier does not name the pinned certificate"]}
    salg = si["signature_algorithm"]["algorithm"].native
    dalg = si["digest_algorithm"]["algorithm"].native
    pk = cert.public_key()
    if salg in ("sha256_ecdsa",) or (salg == "ecdsa" and dalg == "sha256"):
        fam = "ec"
    elif salg in ("sha256_rsa",) or (salg == "rsassa_pkcs1v15" and dalg == "sha256"):
        fam = "rsa"
    else:
        return {"status": "not_supported", "findings": ["signature algorithm %s with %s is not supported" % (salg, dalg)]}
    if dalg != "sha256":
        return {"status": "not_supported", "findings": ["digest algorithm %s is not supported" % dalg]}
    data = b"\x31" + sa.dump()[1:]
    sig = si["signature"].native
    try:
        if fam == "ec":
            if not isinstance(pk, ec.EllipticCurvePublicKey):
                return {"status": "failed", "findings": ["an ECDSA signature does not fit the pinned key"]}
            pk.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            if not isinstance(pk, rsa.RSAPublicKey):
                return {"status": "failed", "findings": ["an RSA signature does not fit the pinned key"]}
            pk.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return {"status": "verified"}
    except InvalidSignature:
        return {"status": "failed", "findings": ["the authority's signature does not verify"]}
    except Exception as ex:
        return {"status": "failed", "findings": ["cannot verify: %s" % ex]}
