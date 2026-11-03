"""Runs the action binding 0.3.0 binding and digest cases with ab_check.py."""
import sys, json, base64, hashlib
from common import *
from strictjson import loads, dumps_compact, Unreadable
from ab_check import check_attachment
import patch as P

CASES = load_strict(os.path.join(STD, "extensions/action-binding/tests/cases.json"))
VEC = load_strict(os.path.join(STD, "extensions/action-binding/tests/vectors.json"))

def binding_summary(res):
    s = {}
    s["specification_digests"] = agg([x["digest"]["status"] for x in res["specifications"]])
    s["specification_statements"] = agg([x["statements"]["status"] for x in res["specifications"]])
    for k in ("record_statements", "action_binding", "stage_order", "authorisation_recheck",
              "observed_results", "rationale_provenance"):
        s[k] = res[k]["status"]
    s["execution_state"] = res["observed_results"]["execution_state"]
    s["observed"] = [[a["attempt_stage_id"], a["observed"], a.get("basis")] for a in res["observed_results"]["attempts"]]
    s["executed"] = [[e["spec_index"], e["reached_by"]] for e in res["executed_specifications"]]
    s["reviews"] = [[r["review_stage_id"], r["shown"], r.get("edited_by")] for r in res["reviews"]]
    s["standing"] = [[e["stage_id"], e["bounds"]["status"], e["requests_recorded"], e.get("max_requests"), e["revocation"]]
                     for e in res.get("standing_approvals", [])]
    return s

DIMS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
        "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")

def run_binding(rec, verbose=False):
    for c in CASES["binding_cases"]:
        att = P.apply(VEC["attachments"][c["attachment"]], c["patch"], vectors=VEC)
        raw = dumps_compact(att)
        record = None
        if c["record"] is not None:
            record = CASES["records"][c["record"]].encode("utf-8")
        try:
            res = check_attachment(loads(raw), record)
        except Exception as e:
            rec.add("action-binding/binding", c["id"], False, {"exception": repr(e)})
            continue
        got = binding_summary(res)
        exp = c["expected"]
        diffs = {}
        for k in DIMS:
            e = exp.get(k, "verified")
            if got[k] != e:
                diffs[k] = {"expected": e, "got": got[k]}
        e = exp.get("execution_state", "attempted")
        if got["execution_state"] != e:
            diffs["execution_state"] = {"expected": e, "got": got["execution_state"]}
        for k in ("observed", "executed", "reviews", "standing"):
            if k in exp and got[k] != exp[k]:
                diffs[k] = {"expected": exp[k], "got": got[k]}
        detail = None
        if diffs:
            detail = {"diffs": diffs, "findings": {k: res[k].get("findings") for k in ("action_binding", "record_statements", "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance") if res[k].get("findings")}}
        rec.add("action-binding/binding", c["id"], not diffs, detail)

def spec_bytes(name):
    return CASES["specifications"][name]["text"].encode("utf-8")

def run_digest(rec):
    for c in CASES["digest_cases"]:
        ch = c["check"]; ok = None
        if ch == "known_vector":
            ok = (hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"])
        elif ch == "spec_digests":
            ok = all(hashlib.sha256(spec_bytes(n)).hexdigest() == v["spec_digest"] for n, v in CASES["specifications"].items())
        elif ch == "base_attachments":
            ok = True
            for an, names in c["carries"].items():
                att = VEC["attachments"][an]
                carried = {s["spec_digest"]: base64.b64decode(s["content"]["bytes_b64"]) for s in att["action_specifications"]}
                for n in names:
                    d = CASES["specifications"][n]["spec_digest"]
                    if carried.get(d) != spec_bytes(n):
                        ok = False
        elif ch == "spec":
            b = spec_bytes(c["spec"])
            if "edit" in c:
                b = b.replace(c["edit"]["replace"].encode(), c["edit"]["with"].encode())
            if "reserialise" in c:
                v = json.loads(b)
                b = json.dumps(v, indent=2).encode() if c["reserialise"] == "indent_2" else json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
            d = hashlib.sha256(b).hexdigest()
            target = CASES["specifications"][c["variant"]]["spec_digest"] if "variant" in c else CASES["specifications"][c["spec"]]["spec_digest"]
            ok = (d == target) if c["expected"] == "match" else (d != target)
            rec.add("action-binding/digest", c["id"], ok); continue
        elif ch == "record_seal":
            t = CASES["records"][c["record"]]
            r = json.loads(t)
            z = t.replace(r["seal_hash"], "0" * 64)
            ok = hashlib.sha256(z.encode()).hexdigest() == r["seal_hash"]
        elif ch == "bounds_digests":
            ok = all(hashlib.sha256(v["text"].encode()).hexdigest() == v["bounds_digest"] for v in CASES["bounds"].values())
        elif ch == "bounds_carried":
            st = VEC["attachments"][c["attachment"]]["stages"][c["stage"]]
            bb = CASES["bounds"][c["bounds"]]
            ok = base64.b64decode(st["bounds"]["bytes_b64"]) == bb["text"].encode() and st["bounds_digest"] == bb["bounds_digest"]
        if c["expected"] == "mismatch":
            ok = not ok
        rec.add("action-binding/digest", c["id"], ok)

if __name__ == "__main__":
    rec = Recorder()
    run_digest(rec)
    run_binding(rec)
    fails = [r for r in rec.rows if r["result"] is not True]
    print("total", len(rec.rows), "fail", len(fails))
    for r in fails:
        print(r["id"], json.dumps(r.get("detail"), ensure_ascii=False)[:900])
