import json, hashlib
from common import *
from strictjson import loads, dumps_compact, to_native
import patch as P
import pairing_ab
import sys
sys.setrecursionlimit(20000)

def run_ab(rec):
    C = load_strict(os.path.join(STD, "extensions/action-binding/tests/cases.json"))
    V = load_strict(os.path.join(STD, "extensions/action-binding/tests/vectors.json"))
    ctx = V["base_context"]
    for c in C["pairing_cases"]:
        try:
            covers = c.get("covers", ctx["covers"])
            ap = c.get("attachment_patches", {})
            atts = []
            for n in covers:
                d = P.apply(V["attachments"][n], ap.get(n, []), vectors=V)
                try:
                    atts.append((dumps_compact(d), d))
                except UnicodeEncodeError:
                    atts.append((None, d))
            def digest_of(x):
                if x == "beside":
                    return hashlib.sha256(dumps_compact(P.apply(V["signatures_attachments"][c.get("attachment", "beside") or "beside"], c.get("beside_patch", []), vectors=V))).hexdigest()
                n = x.split(":", 1)[1]
                return hashlib.sha256(dumps_compact(P.apply(V["attachments"][n], ap.get(n, []), vectors=V))).hexdigest()
            recs = {}
            for rn in c.get("records", ctx["records"]):
                t = C["records"][rn]; recs[json.loads(t)["decision_id"]] = t.encode()
            bn = c.get("attachment", ctx["attachment"])
            bb = None
            if bn is not None:
                bb = dumps_compact(P.apply(V["signatures_attachments"][bn], c.get("beside_patch", []), vectors=V))
            policy = to_native(P.apply(V["trust_policy"], c.get("policy_patch", []), vectors=V))
            if c.get("report") == "reference":
                # 'the reference report' of these inputs: this reading's own check stands in for it
                import ab_report as AR
                base = AR.build_report(atts, recs, policy, bb)
            else:
                base = V["base_report"]
            rep = to_native(P.apply(base, c.get("report_patch", []), vectors=V, digest_of=digest_of))
            ok, why = pairing_ab.check_pairing(rep, atts, recs, policy, bb)
            got = "consistent" if ok else "inconsistent"
            rec.add("action-binding/pairing", c["id"], got == c["expected"], None if got == c["expected"] else {"expected": c["expected"], "got": got, "reason": why, "desc": c["description"][:140]})
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("action-binding/pairing", c["id"], False, {"exception": repr(e)})

if __name__ == "__main__":
    rec = Recorder(); run_ab(rec)
    bad = [r for r in rec.rows if r["result"] is not True]
    print("total", len(rec.rows), "not ok", len(bad))
    for r in bad: print(r["id"], json.dumps(r.get("detail"), ensure_ascii=False)[:600])

def run_sig(rec):
    import pairing_sig
    C = load_strict(os.path.join(STD, "extensions/signatures/tests/cases.json"))
    V = load_strict(os.path.join(STD, "extensions/signatures/tests/vectors.json"))
    ctx = V["base_context"]
    for c in C["pairing_cases"]:
        try:
            att = P.apply(V["base_attachment"], c.get("attachment_patch", []), vectors=V)
            exp_doc = P.apply(V["exports"][c.get("export", ctx["export"])], c.get("export_patch", []), vectors=V)
            abp = c.get("action_binding_patch", {})
            ab_docs = {}
            for did in ctx["action_binding"]:
                d = P.apply(V["action_binding_attachments"][did], abp.get(did, []), vectors=V)
                ab_docs[did] = (dumps_compact(d), d)
            policy = to_native(P.apply(V["trust_policy"], c.get("policy_patch", []), vectors=V))
            att_b = dumps_compact(att); exp_b = dumps_compact(exp_doc)
            def digest_of(x):
                if x == "attachment": return hashlib.sha256(att_b).hexdigest()
                if x == "export": return hashlib.sha256(exp_b).hexdigest()
                return hashlib.sha256(ab_docs[x.split(":", 1)[1]][0]).hexdigest()
            rep = P.apply(V["base_report"], c.get("report_patch", []), vectors=V, digest_of=digest_of)
            if "deep_subject_of" in c:
                deep = {}
                cur = deep
                for _ in range(int(c["deep_subject_of"])):
                    cur["x"] = {}; cur = cur["x"]
                rep["timestamps"][0]["subject"]["of"]["deep"] = deep
            rep = to_native(rep)
            ok, why = pairing_sig.check(rep, loads(att_b), att_b, loads(exp_b), exp_b, ab_docs, policy)
            got = "consistent" if ok else "inconsistent"
            rec.add("signatures/pairing", c["id"], got == c["expected"], None if got == c["expected"] else {"expected": c["expected"], "got": got, "reason": why, "desc": c["description"][:140]})
        except RecursionError as e:
            rec.add("signatures/pairing", c["id"], False, {"exception": "RecursionError"})
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("signatures/pairing", c["id"], False, {"exception": repr(e)})

if __name__ == "__main__":
    rec = Recorder(); run_sig(rec)
    bad = [r for r in rec.rows if r["result"] is not True]
    print("sig pairing total", len(rec.rows), "not ok", len(bad))
    for r in bad: print(r["id"], json.dumps(r.get("detail"), ensure_ascii=False)[:500])
