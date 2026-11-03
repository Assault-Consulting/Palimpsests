"""Signatures 0.2.0: the person's signature, the organisation's seal, timestamps over
signature values, the trust policy's refusal and the key states, written from the
signatures README (and, where it restates them, anchoring 0.2.0's rules; anchoring's own
text was outside this reading's inputs)."""
import base64, binascii, hashlib, json, re, struct
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from strictjson import loads, Unreadable
from times import instant, utc_signed_time_ok, utc_text
import jsonspan

PROFILE, VERSION = "dps-signatures", "0.2.0"
COPY_REF = "dps-signatures 0.2.0 organisation_seal"
PERSON_ALGS = ("Ed25519", "WebAuthn-ES256")
SEAL_ALGS = ("Ed25519",)

class Enc(Exception):
    pass

def _hex32(h):
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h):
        raise Enc("not a digest of 64 lowercase hex characters")
    return bytes.fromhex(h)

def _text(s):
    if not isinstance(s, str):
        raise Enc("not text")
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        raise Enc("a text with no UTF-8 encoding")

def _time(s):
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", s):
        raise Enc("a time not of the form YYYY-MM-DDTHH:MM:SSZ")
    return s.encode("ascii")

def signed_bytes(fields):
    """fields: list of (kind, value): 't' text, 'd' digest, 'T' time, 'o' optional digest."""
    out = b"DPS-SIG\x00"
    for k, v in fields:
        if k == "t":
            b = _text(v)
        elif k == "d":
            b = _hex32(v)
        elif k == "o":
            b = b"" if v is None else _hex32(v)
        elif k == "T":
            b = _time(v)
        out += struct.pack(">I", len(b)) + b
    return out

def person_fields(a, key_ref):
    t = a.get("assertion")
    base = [("t", PROFILE), ("t", VERSION), ("t", t), ("t", key_ref), ("t", a.get("decision_id"))]
    if t == "person_approval":
        return base + [("t", a.get("stage_id")), ("t", a.get("outcome")), ("d", a.get("shown_spec_digest")),
                       ("o", a.get("shown_view_digest")), ("d", a.get("approved_spec_digest")), ("T", a.get("signed_at"))]
    if t == "person_review":
        return base + [("t", a.get("stage_id")), ("t", a.get("outcome")), ("d", a.get("shown_spec_digest")),
                       ("o", a.get("shown_view_digest")), ("T", a.get("signed_at"))]
    if t == "person_standing_approval":
        return base + [("t", a.get("stage_id")), ("d", a.get("bounds_digest")), ("o", a.get("shown_view_digest")),
                       ("T", a.get("signed_at"))]
    if t == "person_affirmation":
        return base + [("d", a.get("affirmed_digest")), ("T", a.get("signed_at"))]
    raise Enc("an assertion type this check does not know")

def seal_fields(key_ref, kind, sid, digest, sealed_at):
    return [("t", PROFILE), ("t", VERSION), ("t", "organisation_seal"), ("t", key_ref), ("t", kind),
            ("t", sid), ("d", digest), ("T", sealed_at)]

def b64(s):
    if not isinstance(s, str):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None

def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# ---------------------------------------------------------------- the trust policy

def _key_identity(hexstr):
    """Lenient read for the refusal (a final newline still the same key): the decoded
    public key, whatever its label: Ed25519 32 bytes; a P-256 point compressed or not;
    an RSA key by modulus and exponent, as SPKI or as PKCS#1 RSAPublicKey."""
    if not isinstance(hexstr, str):
        return None
    h = hexstr.strip().lower()
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return ("unparsed", hexstr)
    if len(raw) == 32:
        return ("raw32", raw)
    if len(raw) in (33, 65) and raw[0] in (2, 3, 4):
        try:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
            return ("p256", pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
        except Exception:
            pass
    for loader in (serialization.load_der_public_key,):
        try:
            pk = loader(raw)
            if isinstance(pk, rsa.RSAPublicKey):
                n = pk.public_numbers(); return ("rsa", n.n, n.e)
            if isinstance(pk, ec.EllipticCurvePublicKey):
                return ("p256", pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
            if isinstance(pk, ed25519.Ed25519PublicKey):
                return ("raw32", pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        except Exception:
            pass
    try:
        from asn1crypto import keys as ak
        k = ak.RSAPublicKey.load(raw, strict=True)
        return ("rsa", int(k["modulus"]), int(k["public_exponent"]))
    except Exception:
        pass
    return ("raw", raw)

def check_policy(policy):
    """Returns (accepted: bool, reason or None)."""
    reasons = []
    keys = policy.get("keys", []) or []
    seen = {}
    for e in keys:
        kid = _key_identity(e.get("public_key_hex"))
        if kid is None:
            continue
        seen.setdefault(kid, []).append(e)
    for kid, es in seen.items():
        if len(es) > 1:
            refs = sorted({str(e.get("key_ref")) for e in es})
            holders = sorted({str(e.get("holder")) for e in es})
            roles = sorted({str(e.get("role")) for e in es})
            labels = sorted({str(e.get("algorithm")) for e in es})
            lens = sorted({len(str(e.get("public_key_hex")).strip()) // 2 for e in es})
            what = []
            if len(refs) > 1: what.append("references %s" % refs)
            if len(holders) > 1: what.append("holders %s" % holders)
            if len(roles) > 1: what.append("roles %s" % roles)
            if not what: what.append("the same entry twice under %s" % refs)
            extra = ""
            if len(labels) > 1: extra += ", labels %s" % labels
            if len(lens) > 1: extra += ", lengths %s" % lens
            reasons.append("one public key is listed under " + " and ".join(what) + extra)
    for lst, field in ((keys, "key_ref"), (policy.get("tsas", []) or [], "tsa_ref"),
                       (policy.get("checkpoint_sources", []) or [], "source_ref")):
        refs = [e.get(field) for e in lst]
        for r in sorted({x for x in refs if refs.count(x) > 1}, key=str):
            reasons.append("one %s (%s) names two entries" % (field, r))
    if reasons:
        return False, "; ".join(reasons)
    return True, None

def find_key(policy, key_ref):
    for e in policy.get("keys", []) or []:
        if e.get("key_ref") == key_ref:
            return e
    return None

def strict_key_bytes(e):
    h = e.get("public_key_hex")
    if not isinstance(h, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", h):
        return None
    return bytes.fromhex(h)

# ---------------------------------------------------------------- key states

def key_state(entry, stated, ts_times, policy_ok, policy_reason):
    """Anchoring 0.2.0's key states as the signatures text restates them.
    ts_times: list of (T_us, index) of verified independent timestamps over the value."""
    if not policy_ok:
        return {"status": "failed", "findings": ["not checked: the trust policy is refused (%s)" % policy_reason]}
    ks = {"key_ref": entry.get("key_ref")}
    if entry.get("revocation_reason"):
        ks["revocation_reason"] = entry["revocation_reason"]
    if not utc_signed_time_ok(stated):
        ks.update(status="failed", findings=["the stated time cannot be read as a real UTC time (%s)" % stated])
        return ks
    st = instant(stated)
    nb = instant(entry.get("not_before"))
    na = instant(entry.get("not_after"))
    ra = entry.get("revoked_at")
    ra_i = instant(ra) if ra is not None else None
    if nb is None or na is None or (ra is not None and ra_i is None):
        ks.update(status="failed", findings=["a time in the policy's entry for the key cannot be read"])
        return ks
    ts = min(ts_times) if ts_times else None
    if st < nb:
        ks.update(status="failed", findings=["the stated time is before the key's not_before"])
        return ks
    if ts is not None:
        t, basis = ts[0], "independent_timestamp"
    else:
        t, basis = st, "stated_time"
    if t > na:
        ks.update(status="failed", findings=["the key was used after its not_after"])
        return ks
    if ra is not None:
        if entry.get("revocation_reason") == "compromised":
            if ts is None:
                ks.update(status="unavailable", findings=["the key is compromised and no independent timestamp covers the signature: the time cannot be established"])
                return ks
            if ts[0] >= ra_i:
                ks.update(status="failed", findings=["the key is compromised and the earliest independent timestamp is not earlier than revoked_at"])
                return ks
        else:
            if t >= ra_i:
                ks.update(status="failed", findings=["the key was superseded at or before the time the signature rests on"])
                return ks
    ks.update(status="verified", time_basis=basis, time=utc_text(t))
    if basis == "independent_timestamp":
        ks["timestamp_index"] = ts[1]
    return ks

# ---------------------------------------------------------------- timestamps

OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA = "1.2.840.113549.1.1.1"
OID_PSS = "1.2.840.113549.1.1.10"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

def _parse_token(token_bytes):
    from asn1crypto import cms, tsp, core
    ci = cms.ContentInfo.load(token_bytes, strict=True)
    if ci["content_type"].native != "signed_data":
        raise ValueError("not SignedData")
    sd = ci["content"]
    eci = sd["encap_content_info"]
    if eci["content_type"].native != "tst_info":
        raise ValueError("not TSTInfo")
    econtent = eci["content"].contents if hasattr(eci["content"], "contents") else None
    raw_tst = eci["content"].parsed.dump() if hasattr(eci["content"], "parsed") else None
    tst = tsp.TSTInfo.load(econtent, strict=True)
    gt = tst["gen_time"]
    gt_raw = gt.contents.decode("ascii")
    if not gt_raw.endswith("Z"):
        raise ValueError("genTime is not in UTC")
    m = re.fullmatch(r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(\.[0-9]+)?Z", gt_raw)
    if not m:
        raise ValueError("genTime cannot be read")
    gtxt = "%s-%s-%sT%s:%s:%s%sZ" % (m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7) or "")
    g = instant(gtxt)
    if g is None:
        raise ValueError("genTime is not a real time")
    acc_us = 0
    acc = tst["accuracy"]
    if acc.native is not None:
        s = acc["seconds"].native if acc["seconds"].native is not None else 0
        ms = acc["millis"].native
        us = acc["micros"].native
        if s < 0:
            raise ValueError("a negative accuracy")
        if ms is not None and not (1 <= ms <= 999):
            raise ValueError("accuracy millis outside 1..999")
        if us is not None and not (1 <= us <= 999):
            raise ValueError("accuracy micros outside 1..999")
        acc_us = s * 1_000_000 + (ms or 0) * 1000 + (us or 0)
    T = g + acc_us
    if T >= instant("9999-12-31T23:59:59Z") + 1_000_000:
        raise ValueError("genTime plus accuracy is past the year 9999")
    return {"ci": ci, "sd": sd, "tst": tst, "econtent": econtent, "gen": g, "T": T}

def check_timestamp(ts, held, policy, policy_ok, policy_reason):
    """ts: a timestamp assertion; held: list of (type_kind, assertion) in the attachment.
    Returns a result dict with the dimensions the cases name."""
    r = {"tsa_ref": ts.get("tsa_ref")}
    dims = {}
    tok = b64(ts.get("token_b64"))
    parsed = None
    try:
        if tok is None:
            raise ValueError("not base64")
        if ts.get("hash_algorithm") != "SHA-256":
            raise ValueError("hash_algorithm is not SHA-256")
        parsed = _parse_token(tok)
        dims["token"] = "verified"
    except Exception as e:
        dims["token"] = "failed"; r["token_finding"] = str(e)
    subj = ts.get("subject") or {}
    value = b64(subj.get("value_b64"))
    # subject_bytes
    holder_match = [h for h in held if (h[1].get("signature") or {}).get("value_b64") == subj.get("value_b64")]
    named = None
    if subj.get("kind") != "signature":
        dims["subject_bytes"] = "failed"
    elif not holder_match:
        dims["subject_bytes"] = "not_checked"
    else:
        of = subj.get("of") or {}
        for kind_, a in holder_match:
            ok = of.get("assertion") == a.get("assertion") and of.get("key_ref") == (a.get("signature") or {}).get("key_ref")
            if "profile" in of and of["profile"] != PROFILE:
                ok = False
            if a.get("assertion") == "organisation_seal":
                ok = ok and of.get("sealed_kind") == (a.get("sealed") or {}).get("kind") and of.get("sealed_id") == (a.get("sealed") or {}).get("id")
                ok = ok and not ({"decision_id", "stage_id"} & set(of))
            else:
                ok = ok and of.get("decision_id") == a.get("decision_id")
                if a.get("assertion") in ("person_approval", "person_review", "person_standing_approval"):
                    ok = ok and of.get("stage_id") == a.get("stage_id")
                else:
                    ok = ok and "stage_id" not in of
            if ok:
                named = a
        dims["subject_bytes"] = "verified" if named is not None else "failed"
    tsa = None
    for e in policy.get("tsas", []) or []:
        if e.get("tsa_ref") == ts.get("tsa_ref"):
            tsa = e
    cert = None; cert_ok = None
    if tsa is not None:
        try:
            cert = x509.load_der_x509_certificate(b64(tsa.get("certificate_b64")) or b"")
            cert_ok = True
        except Exception:
            cert_ok = False
    if parsed is None:
        for k in ("message_imprint", "message_digest", "tsa_signature", "signer_certificate", "tsa_state"):
            dims[k] = "not_checked"
    else:
        from asn1crypto import cms
        tst = parsed["tst"]; sd = parsed["sd"]
        mi = tst["message_imprint"]
        if mi["hash_algorithm"]["algorithm"].native == "sha256" and value is not None and mi["hashed_message"].native == hashlib.sha256(value).digest():
            dims["message_imprint"] = "verified"
        else:
            dims["message_imprint"] = "failed"
        sis = sd["signer_infos"]
        si = sis[0] if len(sis) == 1 else None
        # message digest
        md_ok = False
        attrs = {}
        if si is not None and si["signed_attrs"].native is not None:
            for at in si["signed_attrs"]:
                attrs.setdefault(at["type"].dotted, []).append(at)
            mds = attrs.get(OID_MESSAGE_DIGEST, [])
            if len(mds) == 1 and len(mds[0]["values"]) == 1 and si["digest_algorithm"]["algorithm"].native == "sha256":
                md_ok = mds[0]["values"][0].native == hashlib.sha256(parsed["econtent"]).digest()
        dims["message_digest"] = "verified" if md_ok else "failed"
        # tsa signature
        if not policy_ok:
            dims["tsa_signature"] = "failed"; r["tsa_finding"] = "not checked: the trust policy is refused (%s)" % policy_reason
        elif tsa is None:
            dims["tsa_signature"] = "failed"; r["tsa_finding"] = "an authority the policy does not list"
        elif not cert_ok:
            dims["tsa_signature"] = "failed"; r["tsa_finding"] = "the pinned certificate cannot be read"
        elif si is None:
            dims["tsa_signature"] = "failed"
        else:
            dims["tsa_signature"] = _tsa_sig(si, cert)
        # signer certificate
        if not policy_ok or tsa is None or not cert_ok:
            dims["signer_certificate"] = "not_checked"
        else:
            sc = attrs.get(OID_SIGNING_CERT_V2, [])
            if not sc:
                dims["signer_certificate"] = "not_checked"
            else:
                try:
                    vals = sc[0]["values"]
                    if len(sc) != 1 or len(vals) != 1:
                        raise ValueError("no single value")
                    v = vals[0]
                    certs = v["certs"]
                    if len(certs) < 1:
                        raise ValueError("no ESSCertIDv2")
                    cid = certs[0]
                    ha = cid["hash_algorithm"]["algorithm"].native
                    if ha != "sha256":
                        dims["signer_certificate"] = "not_checked"
                    else:
                        der = cert.public_bytes(serialization.Encoding.DER)
                        dims["signer_certificate"] = "verified" if cid["cert_hash"].native == hashlib.sha256(der).digest() else "failed"
                except Exception as e:
                    dims["signer_certificate"] = "failed"; r["cert_finding"] = str(e)
        # tsa state
        if not policy_ok:
            dims["tsa_state"] = "failed"
        elif tsa is None:
            dims["tsa_state"] = "not_checked"
        else:
            dims["tsa_state"] = _tsa_state(tsa, parsed["gen"])
    core = [dims[k] for k in ("token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "tsa_state")]
    sc_ok = dims["signer_certificate"] in ("verified", "not_checked")
    if all(x == "verified" for x in core) and sc_ok:
        status = "verified"
    else:
        allv = core + ([] if sc_ok else [dims["signer_certificate"]])
        status = next(s for s in ("failed", "not_supported", "unavailable", "not_checked") if s in allv)
    r["status"] = status
    r.update(dims)
    if parsed is not None:
        r["gen_time"] = utc_text(parsed["gen"])
        r["existed_no_later_than"] = utc_text(parsed["T"])
        r["T"] = parsed["T"]
    # signer time
    if status != "verified" or named is None:
        r["signer_time"] = "not_checked"
    else:
        stated = named.get("signed_at") if named.get("assertion") != "organisation_seal" else named.get("sealed_at")
        if not utc_signed_time_ok(stated):
            r["signer_time"] = "not_checked"
        elif instant(stated) > parsed["T"]:
            r["signer_time"] = "failed"; r["consistency"] = "inconsistent"
        else:
            r["signer_time"] = "verified"; r["consistency"] = "consistent"
    r["covers_value"] = subj.get("value_b64")
    return r

def _tsa_sig(si, cert):
    from asn1crypto import cms
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        ias = sid.chosen
        if ias["serial_number"].native != cert.serial_number or ias["issuer"].dump() != cert.issuer.public_bytes():
            return "failed"
    else:
        try:
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except Exception:
            return "failed"
        if sid.chosen.native != ski:
            return "failed"
    alg = si["signature_algorithm"]["algorithm"].dotted
    pk = cert.public_key()
    data = si["signed_attrs"].untag().dump()
    data = b"\x31" + data[1:]
    sig = si["signature"].native
    if alg == OID_ECDSA_SHA256:
        if not isinstance(pk, ec.EllipticCurvePublicKey):
            return "failed"
        try:
            pk.verify(sig, data, ec.ECDSA(hashes.SHA256())); return "verified"
        except InvalidSignature:
            return "failed"
    if alg in (OID_RSA_SHA256, OID_RSA):
        if alg == OID_RSA and si["digest_algorithm"]["algorithm"].native != "sha256":
            return "not_supported"
        if not isinstance(pk, rsa.RSAPublicKey):
            return "failed"
        try:
            pk.verify(sig, data, padding.PKCS1v15(), hashes.SHA256()); return "verified"
        except InvalidSignature:
            return "failed"
    return "not_supported"

def _tsa_state(tsa, gen):
    nb = instant(tsa.get("not_before")); na = instant(tsa.get("not_after"))
    ra = tsa.get("revoked_at")
    ra_i = instant(ra) if ra is not None else None
    if nb is None or na is None or (ra is not None and ra_i is None):
        return "failed"
    if not (nb <= gen <= na):
        return "failed"
    if ra is not None:
        if tsa.get("revocation_reason") == "compromised":
            return "failed"
        if gen >= ra_i:
            return "failed"
    return "verified"

def covering_times(sig_value_b64, assertion, timestamps, held, policy, policy_ok, policy_reason):
    """Verified timestamps whose subject is this assertion's signature value and names it."""
    out = []
    for i, ts in enumerate(timestamps):
        if (ts.get("subject") or {}).get("value_b64") != sig_value_b64:
            continue
        r = check_timestamp(ts, held, policy, policy_ok, policy_reason)
        if r["status"] == "verified" and r.get("subject_bytes") == "verified":
            out.append((r["T"], i))
    return out

# ---------------------------------------------------------------- the person's signature

def _verify_ed25519(pub, sig, msg):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False

def person_signature_dim(a, entry, policy_ok, policy_reason):
    """Returns (status, findings, facts)."""
    sig = a.get("signature") or {}
    facts = {}
    if not policy_ok:
        return "failed", ["not checked: the trust policy is refused (%s)" % policy_reason], facts
    if entry is None:
        return "failed", ["a key the trust policy does not list"], facts
    if entry.get("role") != "person":
        return "failed", ["the key is not in role person"], facts
    alg = sig.get("algorithm")
    if alg not in PERSON_ALGS:
        return "not_supported", ["an algorithm this check does not support (%s)" % alg], facts
    if entry.get("algorithm") != alg:
        return "failed", ["the signature's label (%s) is not its entry's (%s)" % (alg, entry.get("algorithm"))], facts
    pub = strict_key_bytes(entry)
    if pub is None:
        return "failed", ["the policy's public_key_hex is not lowercase hex pairs and nothing else"], facts
    try:
        msg = signed_bytes(person_fields(a, sig.get("key_ref")))
    except Enc as e:
        return "failed", ["the signed bytes cannot be built: %s" % e], facts
    val = b64(sig.get("value_b64"))
    if val is None:
        return "failed", ["the signature value is not base64"], facts
    if alg == "Ed25519":
        if len(pub) != 32:
            return "failed", ["not an Ed25519 public key"], facts
        return ("verified", [], facts) if _verify_ed25519(pub, val, msg) else ("failed", ["the signature does not verify"], facts)
    # WebAuthn-ES256
    wa = entry.get("webauthn")
    if not isinstance(wa, dict) or not wa.get("rp_id") or not wa.get("origins"):
        return "failed", ["the policy's entry names no relying party identifier and origins"], facts
    if len(pub) != 65 or pub[0] != 4:
        return "failed", ["the policy's key is not a 65-byte uncompressed point"], facts
    try:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
    except Exception:
        return "failed", ["the policy's key is not a point"], facts
    cdj = b64(sig.get("client_data_json_b64"))
    ad = b64(sig.get("authenticator_data_b64"))
    if cdj is None or ad is None:
        return "failed", ["no client data or authenticator data"], facts
    try:
        cd = loads(cdj)
        if not isinstance(cd, dict):
            raise Unreadable("not an object")
    except Unreadable as e:
        return "failed", ["the client data is not read (%s)" % e], facts
    if len(ad) < 37:
        return "failed", ["the authenticator data is too short"], facts
    flags = ad[32]
    facts["user_present"] = bool(flags & 0x01)
    facts["user_verified"] = bool(flags & 0x04)
    facts["cross_origin"] = cd["crossOrigin"] if type(cd.get("crossOrigin")) is bool else None
    if "topOrigin" in cd:
        facts["top_origin"] = cd["topOrigin"]
    f = []
    if cd.get("type") != "webauthn.get":
        f.append("the client data's type is not webauthn.get")
    if cd.get("challenge") != b64url_nopad(hashlib.sha256(msg).digest()):
        f.append("the challenge is not the SHA-256 of the signed bytes")
    if cd.get("origin") not in wa.get("origins"):
        f.append("an origin the policy does not allow for the key")
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        f.append("the client data states crossOrigin other than false")
    if "topOrigin" in cd:
        f.append("the client data states a topOrigin")
    if ad[:32] != hashlib.sha256(_text(wa["rp_id"])).digest():
        f.append("the authenticator data is not for the policy's relying party")
    if not flags & 0x01:
        f.append("the UP flag is absent")
    try:
        pk.verify(val, ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        f.append("the ES256 signature does not verify")
    return ("failed", f, facts) if f else ("verified", [], facts)

def read_ab(ab_docs, decision_id):
    """ab_docs: {decision_id: (bytes or None, document)}. Returns (attachment or None, reason)."""
    if decision_id not in ab_docs:
        return None, "not_held"
    raw, doc = ab_docs[decision_id]
    if raw is None:
        return doc, None
    try:
        return loads(raw), None
    except Unreadable:
        return None, "not_read"

def find_export_entry(export, decision_id):
    if export is None:
        return None
    for e in export.get("entries", []) or []:
        if e.get("decision_id") == decision_id:
            return e
    return None

def person_subject(a, ab_docs, export):
    """Returns (status, findings, actor, actor_reason, extra)."""
    t = a.get("assertion")
    extra = {}
    if t in ("person_approval", "person_review", "person_standing_approval"):
        att, why = read_ab(ab_docs, a.get("decision_id"))
        if att is None:
            return ("not_checked", ["the action-binding attachment of the record is %s" % ("not held" if why == "not_held" else "not read")], None, why, extra)
        stages = att.get("stages", [])
        by = {}
        for s in stages:
            by.setdefault(s.get("stage_id"), s)
        st = by.get(a.get("stage_id"))
        want = "standing_approval" if t == "person_standing_approval" else "outcome"
        if st is None or st.get("kind") != want:
            return ("failed", ["stage %s is not a %s stage of the attachment" % (a.get("stage_id"), want)], None, "no_actor", extra)
        actor = st.get("actor_ref")
        f = []
        rv = by.get(st.get("review_ref"))
        if rv is None or rv.get("kind") != "review":
            f.append("the review the stage answers is not in the attachment")
        if t == "person_standing_approval":
            if st.get("bounds_digest") != a.get("bounds_digest"):
                f.append("the stage's bounds_digest is not the signed one")
            if rv is not None and rv.get("kind") == "review":
                if rv.get("shown_bounds_digest") != a.get("bounds_digest"):
                    f.append("the review was not shown the signed bounds digest")
                if rv.get("shown_view_digest") != a.get("shown_view_digest"):
                    f.append("the view digest is not the review's")
        else:
            if st.get("outcome") != a.get("outcome"):
                f.append("the stage records another outcome (%s)" % st.get("outcome"))
            if rv is not None and rv.get("kind") == "review":
                if "shown_bounds_digest" in rv:
                    f.append("the review was shown bounds: no person type in this version answers it")
                elif rv.get("shown_spec_digest") != a.get("shown_spec_digest"):
                    f.append("the review showed another specification digest")
                if rv.get("shown_view_digest") != a.get("shown_view_digest"):
                    f.append("the view digest is not the review's")
            if t == "person_approval" and st.get("approved_spec_digest") != a.get("approved_spec_digest"):
                f.append("the outcome's approved digest is not the signed one")
        return ("failed" if f else "verified", f, actor, None if actor else "no_actor", extra)
    if t == "person_affirmation":
        e = find_export_entry(export, a.get("decision_id"))
        if e is None:
            return ("not_checked", ["the record is not in the export held"], None, "not_held", extra)
        seal = e.get("seal") or {}
        extra["covers_affirmation_record"] = seal.get("affirmation_record_covered")
        c = e.get("content") or {}
        f = []
        if seal.get("seal_hash") != a.get("affirmed_digest"):
            f.append("affirmed_digest is not the entry's seal")
        if c.get("availability") != "available":
            return ("failed" if f else "unavailable", f + ["the record's covered bytes are unavailable"], None, "none_read", extra)
        cb = b64(c.get("covered_bytes_b64"))
        if cb is None or hashlib.sha256(cb).hexdigest() != seal.get("seal_hash"):
            return ("failed", f + ["the covered bytes do not hash to the seal"], None, "no_actor", extra)
        # identity reads the actor from covered bytes that match the seal (README, the person's signature, item 4)
        try:
            rec = loads(cb)
            actor = ((rec.get("affirmation_record") or {}) if isinstance(rec, dict) else {}).get("actor_identity")
            return ("failed" if f else "verified", f, actor, None if actor else "none_read", extra)
        except Unreadable:
            return ("failed" if f else "verified", f, None, "not_read", extra)
    return ("failed", ["an assertion type this check does not know"], None, "no_actor", extra)

def check_person(a, policy, ab_docs, export, timestamps, held):
    ok, reason = check_policy(policy)
    sig = a.get("signature") or {}
    entry = find_key(policy, sig.get("key_ref"))
    s_status, s_find, facts = person_signature_dim(a, entry, ok, reason)
    subj, subj_f, actor, actor_reason, extra = person_subject(a, ab_docs, export)
    if not ok:
        ks = {"status": "failed", "findings": ["not checked: the trust policy is refused (%s)" % reason]}
    elif s_status != "verified" or entry is None:
        ks = {"status": "not_checked", "findings": ["the signature is not verified"]}
    else:
        times = covering_times(sig.get("value_b64"), a, timestamps, held, policy, ok, reason)
        ks = key_state(entry, a.get("signed_at"), times, ok, reason)
    # identity
    idn = {"basis": "trust_policy"}
    if not ok:
        idn.update(status="failed", findings=["not checked: the trust policy is refused (%s)" % reason])
    elif entry is not None and entry.get("role") != "person":
        idn.update(status="failed", findings=["the key is not a person's key in the policy"])
    elif entry is None:
        idn.update(status="not_checked", findings=["the policy does not list the key"])
    elif s_status != "verified":
        idn.update(status="not_checked", findings=["the signature is not verified"])
    elif actor is None:
        idn.update(status="not_checked", reason=actor_reason, findings=["no actor is read (%s)" % actor_reason])
    else:
        idn["holder"] = entry.get("holder"); idn["issuer_named"] = actor
        if ks["status"] != "verified":
            if actor != entry.get("holder"):
                idn.update(status="failed", consistency="inconsistent")
            else:
                idn.update(status="not_checked", findings=["the key's state when it signed is not verified"])
        elif not entry.get("identity_source_ref"):
            idn.update(status="failed", findings=["the policy names no identity source for the key"])
        elif actor == entry.get("holder"):
            idn.update(status="verified", consistency="consistent", source_ref=entry["identity_source_ref"])
        else:
            idn.update(status="failed", consistency="inconsistent", source_ref=entry["identity_source_ref"])
    three = [s_status, subj, ks["status"]]
    status = "verified" if all(x == "verified" for x in three) else next(x for x in ("failed", "not_supported", "unavailable", "not_checked") if x in three)
    out = {"status": status, "signature": s_status, "signature_findings": s_find, "subject": subj,
           "subject_findings": subj_f, "key_state": ks["status"], "key_state_detail": ks,
           "identity": idn["status"], "identity_detail": idn, "policy": "verified" if ok else "failed"}
    if "time_basis" in ks:
        out["time_basis"] = ks["time_basis"]
    if idn.get("consistency"):
        out["consistency"] = idn["consistency"]
    if idn.get("reason"):
        out["identity_reason"] = idn["reason"]
    out.update(facts)
    out.update(extra)
    return out

# ---------------------------------------------------------------- the organisation's seal

def attachment_sealed_digest(att_bytes):
    """SHA-256 of the attachment's bytes with every character of issuer_signature.value_b64
    replaced by 'A'; None if there are no bytes as issued or no copy."""
    try:
        text = att_bytes.decode("utf-8")
    except Exception:
        return None
    rep = jsonspan.replace_value_with_A(text, ["issuer_signature", "value_b64"])
    if rep is None:
        return hashlib.sha256(att_bytes).hexdigest()
    return hashlib.sha256(rep.encode("utf-8")).hexdigest()

def seal_signature_dim(a, entry, policy_ok, policy_reason, kind, sid, digest):
    sig = a.get("signature") or {}
    if not policy_ok:
        return "failed", ["not checked: the trust policy is refused (%s)" % policy_reason], "not_checked"
    if entry is None:
        return "failed", ["a key the trust policy does not list"], "not_checked"
    if entry.get("role") != "organisation":
        return "failed", ["the key is not in role organisation"], "not_checked"
    alg = sig.get("algorithm")
    if alg not in SEAL_ALGS:
        return "not_supported", ["an algorithm this check does not support (%s)" % alg], "not_checked"
    if entry.get("algorithm") != alg:
        return "failed", ["the signature's label is not its entry's"], "not_checked"
    pub = strict_key_bytes(entry)
    if pub is None or len(pub) != 32:
        return "failed", ["the policy's public key is not read strictly as an Ed25519 key"], "not_checked"
    cert_status = "not_checked"
    if entry.get("certificate_b64") is not None:
        try:
            c = x509.load_der_x509_certificate(b64(entry["certificate_b64"]) or b"")
            cpk = c.public_key()
            raw = cpk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) if isinstance(cpk, ed25519.Ed25519PublicKey) else None
            cert_status = "verified" if raw == pub else "failed"
        except Exception:
            return "failed", ["the pinned certificate cannot be read"], "failed"
        if cert_status == "failed":
            return "failed", ["the pinned certificate does not hold the key"], "failed"
    try:
        msg = signed_bytes(seal_fields(sig.get("key_ref"), kind, sid, digest, a.get("sealed_at")))
    except Enc as e:
        return "failed", ["the signed bytes cannot be built: %s" % e], cert_status
    val = b64(sig.get("value_b64"))
    if val is None or not _verify_ed25519(pub, val, msg):
        return "failed", ["the signature does not verify"], cert_status
    return "verified", [], cert_status

def check_seal(a, policy, ab_docs, export, export_bytes, timestamps, held):
    ok, reason = check_policy(policy)
    sig = a.get("signature") or {}
    sealed = a.get("sealed") or {}
    kind, sid, dig = sealed.get("kind"), sealed.get("id"), sealed.get("digest")
    entry = find_key(policy, sig.get("key_ref"))
    s_status, s_find, cert = seal_signature_dim(a, entry, ok, reason, kind, sid, dig)
    # subject
    copy = "not_checked"; copy_f = []
    if kind == "attachment":
        if sid not in ab_docs:
            subj, subj_f = "not_checked", ["the attachment is not held"]
        else:
            raw, doc = ab_docs[sid]
            if raw is None:
                subj, subj_f = "failed", ["the attachment has no bytes as issued"]
                copy, copy_f = embedded_copy(doc, a)
            else:
                try:
                    att = loads(raw)
                except Unreadable as e:
                    att = None
                if att is None:
                    subj, subj_f = "failed", ["the attachment is not read"]
                else:
                    d = attachment_sealed_digest(raw)
                    subj = "verified" if d == dig else "failed"
                    subj_f = [] if subj == "verified" else ["the sealed digest is not the attachment's (with the copy's value replaced by A)"]
                    copy, copy_f = embedded_copy(att, a)
    elif kind == "record":
        e = find_export_entry(export, sid)
        if e is None:
            subj, subj_f = "not_checked", ["the record is not in the export held"]
        else:
            seal = e.get("seal") or {}
            if seal.get("seal_hash") != dig:
                subj, subj_f = "failed", ["the sealed digest is not the record's seal"]
            elif (e.get("content") or {}).get("availability") != "available":
                subj, subj_f = "unavailable", ["the record's covered bytes are unavailable"]
            else:
                cb = b64((e.get("content") or {}).get("covered_bytes_b64"))
                if cb is not None and hashlib.sha256(cb).hexdigest() == dig:
                    subj, subj_f = "verified", []
                else:
                    subj, subj_f = "failed", ["the covered bytes do not hash to the seal"]
    elif kind == "export":
        if export_bytes is None:
            subj, subj_f = "not_checked", ["the export is not held"]
        else:
            subj = "verified" if hashlib.sha256(export_bytes).hexdigest() == dig else "failed"
            subj_f = []
    else:
        subj, subj_f = "failed", ["a kind this check does not know"]
    if not ok:
        ks = {"status": "failed", "findings": ["not checked: the trust policy is refused (%s)" % reason]}
    elif s_status != "verified" or entry is None:
        ks = {"status": "not_checked"}
    else:
        times = covering_times(sig.get("value_b64"), a, timestamps, held, policy, ok, reason)
        ks = key_state(entry, a.get("sealed_at"), times, ok, reason)
    three = [s_status, subj, ks["status"]]
    status = "verified" if all(x == "verified" for x in three) else next(x for x in ("failed", "not_supported", "unavailable", "not_checked") if x in three)
    out = {"status": status, "signature": s_status, "signature_findings": s_find, "subject": subj, "subject_findings": subj_f,
           "key_state": ks["status"], "key_state_detail": ks, "certificate": cert, "embedded_copy": copy,
           "embedded_copy_findings": copy_f, "policy": "verified" if ok else "failed"}
    if "time_basis" in ks:
        out["time_basis"] = ks["time_basis"]
    return out

def embedded_copy(att, seal):
    if "issuer_signature" not in att:
        return "not_checked", ["the attachment carries no copy"]
    v = att.get("profile_version")
    if v == "0.3.0":
        members = {"algorithm", "key_ref", "signed_bytes_ref", "sealed_at", "value_b64"}
    elif v == "0.2.0":
        members = {"algorithm", "key_ref", "signed_bytes_ref", "value_b64"}
    else:
        return "not_checked", ["an attachment of a version this check does not know"]
    c = att["issuer_signature"]
    sig = seal.get("signature") or {}
    f = []
    if not isinstance(c, dict) or set(c) != members:
        f.append("the copy does not have exactly the members its version names")
    else:
        if c.get("algorithm") != sig.get("algorithm"): f.append("algorithm differs")
        if c.get("key_ref") != sig.get("key_ref"): f.append("key_ref differs")
        if c.get("signed_bytes_ref") != COPY_REF: f.append("signed_bytes_ref is not the seal's text")
        if c.get("value_b64") != sig.get("value_b64"): f.append("value differs")
        if "sealed_at" in members and c.get("sealed_at") != seal.get("sealed_at"): f.append("sealed_at differs")
    return ("failed", f) if f else ("verified", [])
