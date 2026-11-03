"""Action binding 0.3.0 signature cases and vector cases."""
import sys, json, copy, base64, hashlib
from common import *
from strictjson import loads, dumps_compact
import patch as P
import sig_check as S
import ab_report as AR

CASES = load_strict(os.path.join(STD, "extensions/action-binding/tests/cases.json"))
VEC = load_strict(os.path.join(STD, "extensions/action-binding/tests/vectors.json"))
SVEC = load_strict(os.path.join(STD, "extensions/signatures/tests/vectors.json"))

def doc_bytes(d):
    try:
        return dumps_compact(d)
    except UnicodeEncodeError:
        return None

def run_signature(rec):
    for c in CASES["signature_cases"]:
        try:
            covers = c.get("covers", ["A0", "A1"])
            ap = c.get("attachment_patches", {})
            atts = []
            for n in covers:
                d = P.apply(VEC["attachments"][n], ap.get(n, []), vectors=VEC)
                atts.append((doc_bytes(d), d))
            bname = c.get("attachment", "beside")
            beside_bytes = None
            if bname is not None:
                bd = P.apply(VEC["signatures_attachments"][bname], c.get("beside_patch", []), vectors=VEC)
                beside_bytes = doc_bytes(bd)
            policy = P.apply(VEC["trust_policy"], c.get("policy_patch", []), vectors=VEC)
            rep = AR.build_report(atts, {}, policy, beside_bytes)
            r = rep["results"][c.get("index", 0)]
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("action-binding/signature", c["id"], False, {"exception": repr(e)}); continue
        isig = r["issuer_signature"]; ta = r["time_assurance"]
        got = {"status": isig["status"], "key_state": (isig.get("key_state") or {}).get("status", "not_checked"),
               "time_basis": (isig.get("key_state") or {}).get("time_basis"),
               "time_assurance": ta["status"], "holder": isig.get("holder"), "certificate": isig.get("certificate"),
               "no_later_than": ta.get("no_later_than"), "timestamp_index": ta.get("timestamp_index"),
               "policy": rep["trust_policy"]["status"], "sealed_at_note": isig.get("sealed_at_note"),
               "stage_after_timestamp": ta.get("stage_after_timestamp")}
        exp = c["expected"]
        diffs = {}
        defaults = {"status": "verified", "key_state": "verified", "time_assurance": "not_checked", "policy": "verified"}
        for k, dv in defaults.items():
            if got[k] != exp.get(k, dv):
                diffs[k] = {"expected": exp.get(k, dv), "got": got[k]}
        if got["key_state"] == "verified" and got["time_basis"] != exp.get("time_basis", "stated_time"):
            diffs["time_basis"] = {"expected": exp.get("time_basis", "stated_time"), "got": got["time_basis"]}
        for k in ("holder", "certificate", "no_later_than", "timestamp_index", "sealed_at_note", "stage_after_timestamp"):
            if k in exp and got[k] != exp[k]:
                diffs[k] = {"expected": exp[k], "got": got[k]}
        rec.add("action-binding/signature", c["id"], not diffs, {"diffs": diffs, "isig": isig} if diffs else None)

def seed_key(text):
    return hashlib.sha256(text.encode()).digest()

def pub_from_seed(alg, text):
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec
    from cryptography.hazmat.primitives import serialization
    seed = seed_key(text)
    if alg == "Ed25519":
        k = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(seed, "big") % (n - 1) + 1
    k = ec.derive_private_key(d, ec.SECP256R1())
    return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()

def run_vectors(rec):
    for c in CASES["vector_cases"]:
        cid = c["id"]; ch = c["check"]
        try:
            if ch == "known_vector":
                ok = hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"]
            elif ch == "copies_verify":
                ok = True
                for n in c["attachments"]:
                    a = VEC["attachments"][n]
                    rep = AR.build_report([(doc_bytes(a), a)], {}, VEC["trust_policy"], None)
                    st = rep["results"][0]["issuer_signature"]["status"]
                    ok = ok and st == "verified"
            elif ch == "signatures_vectors_agree":
                ok = (to_cmp(VEC["attachments"]["B0"]) == to_cmp(SVEC["action_binding_attachments"]["DR-2099-101"])
                      and to_cmp(VEC["attachments"]["B1"]) == to_cmp(SVEC["action_binding_attachments"]["DR-2099-102"])
                      and VEC["attachments"]["B0"]["issuer_signature"]["value_b64"] == SVEC["organisation_seals"]["seal_attachment"]["assertion"]["signature"]["value_b64"]
                      and to_cmp(VEC["trust_policy"]) == to_cmp(SVEC["trust_policy"]))
            elif ch == "test_keys":
                ok = True
                for name, k in VEC["test_keys"].items():
                    if "seed_text" not in k:
                        continue
                    alg = "Ed25519" if k["algorithm"] == "Ed25519" else "P256"
                    ok = ok and pub_from_seed(alg, k["seed_text"]) == k["public_key_hex"]
            elif ch == "token_imprints":
                ok = True
                for name, ts in VEC["timestamps"].items():
                    from asn1crypto import cms, tsp
                    ci = cms.ContentInfo.load(base64.b64decode(ts["token_b64"]))
                    tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
                    ok = ok and tst["message_imprint"]["hashed_message"].native == hashlib.sha256(base64.b64decode(ts["subject"]["value_b64"])).digest()
            elif ch == "seal_digests":
                ok = True
                for sname, aname in c["seals"].items():
                    a = VEC["attachments"][aname]
                    ok = ok and S.attachment_sealed_digest(doc_bytes(a)) == VEC["seals"][sname]["assertion"]["sealed"]["digest"]
            elif ch == "base_report":
                ctx = VEC["base_context"]
                atts = [(doc_bytes(VEC["attachments"][n]), VEC["attachments"][n]) for n in ctx["covers"]]
                recs = {}
                for rn in ctx["records"]:
                    t = CASES["records"][rn]; recs[json.loads(t)["decision_id"]] = t.encode()
                bb = doc_bytes(VEC["signatures_attachments"][ctx["attachment"]])
                mine = AR.build_report(atts, recs, VEC["trust_policy"], bb)
                ok, detail = structural_equal(mine, to_native(VEC["base_report"]))
                rec.add("action-binding/vector", cid, ok, {"note": "compared without finding texts", "first_difference": detail} if not ok else {"note": "compared without finding texts; byte-for-byte equality not attempted (finding wording is not fixed by the text)"})
                continue
            elif ch == "reproduction":
                rec.add("action-binding/vector", cid, None, attempted=False, why="needs generate_vectors.py, which the reading may not open"); continue
            elif ch == "duplicate_member":
                t = VEC["texts"][c["text"]]
                text = t["attachment_text"]
                try:
                    loads(text.encode()); strict_refuses = False
                except Exception:
                    strict_refuses = True
                last = json.loads(text)
                def first_pairs(p):
                    o = {}
                    for k, v in p:
                        if k not in o: o[k] = v
                    return o
                first = json.loads(text, object_pairs_hook=first_pairs)
                rl = AR.build_report([(text.encode(), None)], {}, VEC["trust_policy"], None) if False else None
                # last-member reader: rebuild the document's bytes as written and verify the copy
                v_last = verify_copy_lenient(text, last)
                v_first = verify_copy_lenient(text, first)
                d_ok = S.attachment_sealed_digest(text.encode()) == t["sealed_digest"]
                ok = strict_refuses and v_last and not v_first and d_ok
            else:
                rec.add("action-binding/vector", cid, None, attempted=False, why="unknown check"); continue
            rec.add("action-binding/vector", cid, ok)
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("action-binding/vector", cid, False, {"exception": repr(e)})

def verify_copy_lenient(text, doc):
    """A non-strict reader: the bytes as written, the copy as that reader reads it."""
    c = doc.get("issuer_signature") or {}
    entry = S.find_key(VEC["trust_policy"], c.get("key_ref"))
    if entry is None:
        return False
    rep = S.jsonspan.replace_value_with_A
    t2 = rep(text, ["issuer_signature", "value_b64"])
    d = hashlib.sha256((t2 or text).encode()).hexdigest()
    seal = {"sealed_at": c.get("sealed_at"), "signature": {"algorithm": c.get("algorithm"), "key_ref": c.get("key_ref"), "value_b64": c.get("value_b64")}}
    st, _, _ = S.seal_signature_dim(seal, entry, True, None, "attachment", doc.get("decision_id"), d)
    return st == "verified"

from strictjson import to_native
def to_cmp(d):
    return json.dumps(to_native(d), sort_keys=True)

def strip_findings(x):
    if isinstance(x, dict):
        return {k: strip_findings(v) for k, v in x.items() if k not in ("findings",)}
    if isinstance(x, list):
        return [strip_findings(v) for v in x]
    return x

def structural_equal(a, b, path=""):
    a, b = strip_findings(a), strip_findings(b)
    return _first_diff(a, b, "")

def _first_diff(a, b, path):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a: return False, "%s/%s missing in mine" % (path, k)
            if k not in b: return False, "%s/%s extra in mine (%s)" % (path, k, json.dumps(a[k])[:80])
            ok, d = _first_diff(a[k], b[k], path + "/" + k)
            if not ok: return ok, d
        return True, None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b): return False, "%s length %d vs %d" % (path, len(a), len(b))
        for i, (x, y) in enumerate(zip(a, b)):
            ok, d = _first_diff(x, y, "%s/%d" % (path, i))
            if not ok: return ok, d
        return True, None
    return (a == b and type(a) == type(b)), None if a == b else "%s: mine %r, base %r" % (path, a, b)

if __name__ == "__main__":
    rec = Recorder()
    run_signature(rec); run_vectors(rec)
    fails = [r for r in rec.rows if r["result"] is not True]
    print("total", len(rec.rows), "not ok", len(fails))
    for r in rec.rows:
        if r["result"] is not True or r["id"] == "W07":
            print(r["id"], r["result"], json.dumps(r.get("detail") or r.get("why"), ensure_ascii=False)[:900])
