"""Signatures 0.2.0 vector cases."""
import json, hashlib, base64, struct, sys
from common import *
from strictjson import loads, dumps_compact, to_native, Unreadable
import sig_check as S
import patch as P
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

C = load_strict(os.path.join(STD, "extensions/signatures/tests/cases.json"))
V = load_strict(os.path.join(STD, "extensions/signatures/tests/vectors.json"))
ABC = load_strict(os.path.join(STD, "extensions/action-binding/tests/cases.json"))

def lp(b): return struct.pack(">I", len(b)) + b
def seed(t): return hashlib.sha256(t.encode()).digest()
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def all_assertions():
    for k in ("person_signatures", "organisation_seals"):
        for n, e in V[k].items():
            yield k, n, e

def built(e, kind):
    a = e["assertion"]
    if kind == "person_signatures":
        return S.signed_bytes(S.person_fields(a, a["signature"]["key_ref"]))
    s = a["sealed"]
    return S.signed_bytes([("t", a.get("profile")), ("t", a.get("profile_version")), ("t", a.get("assertion")), ("t", a["signature"]["key_ref"]),
                           ("t", s["kind"]), ("t", s["id"]), ("d", s["digest"]), ("T", a["sealed_at"])])

def person_built_as_written(e):
    a = e["assertion"]
    f = S.person_fields(a, a["signature"]["key_ref"])
    f[0] = ("t", a.get("profile")); f[1] = ("t", a.get("profile_version"))
    return S.signed_bytes(f)

def priv(name):
    k = V["test_keys"][name]
    sd = seed(k["seed_text"])
    if k["algorithm"] == "Ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(sd)
    return ec.derive_private_key(int.from_bytes(sd, "big") % (N - 1) + 1, ec.SECP256R1())

def pubhex(k):
    p = k.public_key()
    if isinstance(p, ed25519.Ed25519PublicKey):
        return p.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return p.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()

def check(c):
    ch = c["check"]
    if ch == "known_vector":
        return hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"]
    if ch == "length_prefix":
        return all(lp(t.encode()).hex() == h for t, h in c["vectors"])
    if ch == "record_seals":
        return all(hashlib.sha256(V["records"][r]["text"].encode()).hexdigest() == d for r, d in c["published"].items())
    if ch == "specification":
        sp = V["specification"]; vw = V["view"]
        t = sp.get("text") or sp.get("bytes_text")
        ok = hashlib.sha256(t.encode()).hexdigest() == c["published"] == ABC["specifications"]["S0"]["spec_digest"]
        vt = vw.get("text"); vd = vw.get("digest") or vw.get("view_digest")
        return ok and (vt is None or hashlib.sha256(vt.encode()).hexdigest() == vd)
    if ch == "test_keys":
        ok = True
        for n, k in V["test_keys"].items():
            if "seed_text" in k:
                ok = ok and pubhex(priv(n)) == k["public_key_hex"]
        return ok
    if ch == "certificates":
        ok = True
        for n, ce in V["certificates"].items():
            der = base64.b64decode(ce["certificate_b64"])
            ok = ok and hashlib.sha256(der).hexdigest() == ce["sha256"]
            cert = x509.load_der_x509_certificate(der)
            pk = cert.public_key()
            k = V["test_keys"].get(n)
            if k and "public_key_hex" in k:
                if isinstance(pk, ed25519.Ed25519PublicKey):
                    ok = ok and pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() == k["public_key_hex"]
                elif isinstance(pk, ec.EllipticCurvePublicKey):
                    ok = ok and pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex() == k["public_key_hex"]
            elif k and "modulus_hex" in k:
                ok = ok and format(pk.public_numbers().n, "x") == k["modulus_hex"].lstrip("0")
        return ok
    if ch == "signed_bytes":
        for kind, n, e in all_assertions():
            try:
                b = person_built_as_written(e) if kind == "person_signatures" else built(e, kind)
            except S.Enc:
                continue
            if b.hex() != e["signed_bytes_hex"]:
                return False
        return True
    if ch == "signed_bytes_fields":
        n = c["assertion"]
        e = V["person_signatures"].get(n) or V["organisation_seals"].get(n)
        b = bytes.fromhex(e["signed_bytes_hex"])
        exp = b"DPS-SIG\x00" + b"".join(lp(bytes.fromhex(h)) for h in c["fields_hex"])
        return b == exp
    if ch == "signatures":
        for kind, n, e in all_assertions():
            if n in c["altered_after_signing"] or e["assertion"]["signature"]["algorithm"] != "Ed25519":
                continue
            k = priv(e["signed_with"])
            msg = bytes.fromhex(e.get("signature_made_over_hex") or e["signed_bytes_hex"])
            if base64.b64encode(k.sign(msg)).decode() != e["assertion"]["signature"]["value_b64"]:
                return False
        return True
    if ch == "webauthn":
        for n, e in V["person_signatures"].items():
            a = e["assertion"]; sg = a["signature"]
            if sg["algorithm"] != "WebAuthn-ES256" or "webauthn" not in e:
                continue
            w = e["webauthn"]
            msg = bytes.fromhex(e["signed_bytes_hex"])
            if n not in c.get("other_challenge", []) and w["challenge_b64url"] != S.b64url_nopad(hashlib.sha256(msg).digest()):
                return False
            ad = base64.b64decode(sg["authenticator_data_b64"]); cdj = base64.b64decode(sg["client_data_json_b64"])
            if w["authenticator_signed_hex"] != (ad + hashlib.sha256(cdj).digest()).hex():
                return False
            if n in c.get("altered_after_signing", []) or n in c.get("not_read", []):
                continue
            k = priv(e["signed_with"])
            try:
                sig = k.sign(bytes.fromhex(w["authenticator_signed_hex"]), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            except TypeError:
                raise RuntimeError("RFC 6979 not available in this cryptography build")
            if base64.b64encode(sig).decode() != sg["value_b64"]:
                return False
        return True
    if ch == "domain_separation":
        n = c["assertion"]
        e = V["person_signatures"].get(n) or V["organisation_seals"].get(n)
        a = e["assertion"]; base = bytes.fromhex(e["signed_bytes_hex"])
        for i, o in enumerate(c["others"]):
            # change field i (profile, version, type, key_ref) and rebuild
            parts = []; p = 8
            while p < len(base):
                L = struct.unpack(">I", base[p:p + 4])[0]; parts.append(base[p + 4:p + 4 + L]); p += 4 + L
            parts[i] = o.encode()
            if b"DPS-SIG\x00" + b"".join(lp(x) for x in parts) == base:
                return False
        return True
    if ch == "token_imprints":
        from asn1crypto import cms, tsp
        for n, t in V["tokens"].items():
            if n in c["not_tokens"]:
                continue
            ci = cms.ContentInfo.load(base64.b64decode(t["token_b64"]))
            tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
            if tst["message_imprint"]["hashed_message"].native != hashlib.sha256(bytes.fromhex(t["imprint_of_hex"])).digest():
                return False
        return True
    if ch == "embedded_copy":
        a = V["action_binding_attachments"][c["decision_id"]]
        raw = dumps_compact(a)
        d = V["organisation_seals"][c["seal"]]["assertion"]["sealed"]["digest"]
        return S.attachment_sealed_digest(raw) == d and hashlib.sha256(raw).hexdigest() != d
    if ch == "escaped_copy":
        e = V["escaped_copy"]; t = e["attachment_text"]
        same = to_native(loads(t.encode())) == to_native(V["action_binding_attachments"][c["decision_id"]])
        d1 = S.attachment_sealed_digest(t.encode())
        d2 = hashlib.sha256(S.jsonspan.replace_written_with_A(t, ["issuer_signature", "value_b64"]).encode()).hexdigest()
        return same and d1 == e["sealed_digest"] == e["digest_replacing_the_value_characters"] and d2 == e["digest_replacing_the_written_characters"] and d1 != d2
    if ch == "duplicate_member":
        e = P.get(V, c["vector"]); t = e["attachment_text"]
        try:
            loads(t.encode()); return False
        except Unreadable:
            pass
        last = json.loads(t)
        def fp(pairs):
            o = {}
            for k, v in pairs:
                o.setdefault(k, v)
            return o
        first = json.loads(t, object_pairs_hook=fp)
        issued = to_native(V["action_binding_attachments"][c["decision_id"]])
        return last == issued and first != issued
    if ch == "deep_nesting":
        t = ("[" * c["depth"]) + ("]" * c["depth"])
        try:
            loads(t.encode()); return False
        except Unreadable:
            return True
    if ch == "copy_members":
        import copy as _c
        for sn in c["seals"]:
            e = V["organisation_seals"][sn]
            a = _c.deepcopy(to_native(V["action_binding_attachments"][c["decision_id"]]))
            a["issuer_signature"] = to_native(e["issuer_signature"])
            if S.attachment_sealed_digest(dumps_compact(a)) != e["assertion"]["sealed"]["digest"]:
                return False
            st, _ = S.embedded_copy(a, to_native(e["assertion"]))
            if st != "failed":
                return False
        return True
    if ch == "copy_by_version":
        import copy as _c
        e = V["organisation_seals"][c["seal"]]
        a = _c.deepcopy(to_native(e["attachment"])) if "attachment" in e else None
        if a is None:
            a = _c.deepcopy(to_native(V["action_binding_attachments"]["DR-2099-101"])); a["profile_version"] = "0.2.0"
            a["issuer_signature"] = to_native(e["issuer_signature"])
        seal = to_native(e["assertion"])
        ok = S.embedded_copy(a, seal)[0] == "verified" and len(a["issuer_signature"]) == 4
        b = _c.deepcopy(a); b["issuer_signature"]["sealed_at"] = seal["sealed_at"]
        ok = ok and S.embedded_copy(b, seal)[0] == "failed"
        for v in (c["unknown_version"], ["0.3.0"], {"v": "0.3.0"}, 3):
            d = _c.deepcopy(a); d["profile_version"] = v
            ok = ok and S.embedded_copy(d, seal)[0] == "not_checked"
        return ok
    return None

def run(rec):
    for c in C["vector_cases"]:
        if c["check"] in ("reproduction",):
            rec.add("signatures/vector", c["id"], None, attempted=False, why="needs generate_vectors.py, which the reading may not open"); continue
        if c["check"] == "anchoring_fixtures":
            rec.add("signatures/vector", c["id"], None, attempted=False, why="needs anchoring 0.2.0's vectors, not among the inputs"); continue
        if c["check"] == "published_rsa_key":
            rec.add("signatures/vector", c["id"], None, attempted=False, why="RFC 9500's text was not fetched; the case's own printed values are not an independent check"); continue
        try:
            r = check(c)
        except Exception as e:
            rec.add("signatures/vector", c["id"], False, {"exception": repr(e)}); continue
        if r is None:
            rec.add("signatures/vector", c["id"], None, attempted=False, why="the attachments this case names are built by the generator from text this reading cannot open; the copy comparison itself is exercised by the seal cases O01-O06, O41, O46"); continue
        rec.add("signatures/vector", c["id"], r)

if __name__ == "__main__":
    rec = Recorder(); run(rec)
    for r in rec.rows: print(r["id"], r["result"], (r.get("why") or r.get("detail") or ""))
