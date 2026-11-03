"""Runs the signatures 0.2.0 person, seal and timestamp cases with sig_check.py."""
import sys, json, copy
from common import *
from strictjson import loads, dumps_compact
import patch as P
import sig_check as S

CASES = load_strict(os.path.join(STD, "extensions/signatures/tests/cases.json"))
VEC = load_strict(os.path.join(STD, "extensions/signatures/tests/vectors.json"))

def doc_bytes(d):
    try:
        return dumps_compact(d)
    except UnicodeEncodeError:
        return None

def build_context(c):
    policy = P.apply(VEC["trust_policy"], c.get("policy_patch", []), vectors=VEC)
    exp_name = c.get("export", "full")
    export = P.apply(VEC["exports"][exp_name], c.get("export_patch", []), vectors=VEC)
    held_ids = c.get("action_binding", list(VEC["action_binding_attachments"]))
    abp = c.get("action_binding_patch", {})
    ab_docs = {}
    for did in held_ids:
        d = P.apply(VEC["action_binding_attachments"][did], abp.get(did, []), vectors=VEC)
        ab_docs[did] = (doc_bytes(d), d)
    return policy, loads(doc_bytes(export)), doc_bytes(export), ab_docs

def resolve(spec, kind):
    if isinstance(spec, str):
        return copy.deepcopy(VEC[kind][spec]["assertion"])
    base = copy.deepcopy(VEC[kind][spec["from"]]["assertion"])
    return P.apply(base, spec.get("patch", []), vectors=VEC)

def resolve_ptr(spec):
    if isinstance(spec, str):
        return copy.deepcopy(P.get(VEC, spec))
    return P.apply(P.get(VEC, spec["from"]), spec.get("patch", []), vectors=VEC)

def compare(got, exp, defaults, optional):
    diffs = {}
    for k, dv in defaults.items():
        e = exp.get(k, dv)
        if got.get(k) != e:
            diffs[k] = {"expected": e, "got": got.get(k)}
    for k in optional:
        if k in exp and got.get(k) != exp[k]:
            diffs[k] = {"expected": exp[k], "got": got.get(k)}
    return diffs

def run_person(rec):
    for c in CASES["person_cases"]:
        try:
            a = resolve(c["person"], "person_signatures")
            also = [resolve(x["name"], x["kind"]) for x in c.get("also", [])]
            tss = [resolve_ptr(p) for p in c.get("timestamps", [])]
            policy, export, _, ab_docs = build_context(c)
            held = [("person_signatures", a)] + [("x", x) for x in also]
            got = S.check_person(a, policy, ab_docs, export, tss, held)
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("signatures/person", c["id"], False, {"exception": repr(e)}); continue
        exp = c["expected"]
        defaults = {"status": "verified", "signature": "verified", "subject": "verified", "key_state": "verified",
                    "identity": "verified", "policy": "verified"}
        diffs = compare(got, exp, defaults, ["consistency", "identity_reason", "user_present", "user_verified",
                                             "cross_origin", "top_origin", "covers_affirmation_record"])
        if got["key_state"] == "verified":
            e = exp.get("time_basis", "stated_time")
            if got.get("time_basis") != e:
                diffs["time_basis"] = {"expected": e, "got": got.get("time_basis")}
        elif "time_basis" in exp:
            diffs["time_basis"] = {"expected": exp["time_basis"], "got": None}
        for k in ("cross_origin",):
            if k in exp and exp[k] is None and k not in got:
                diffs.pop(k, None)
        rec.add("signatures/person", c["id"], not diffs, {"diffs": diffs, "got": {k: got.get(k) for k in ("signature_findings", "subject_findings", "key_state_detail", "identity_detail")}} if diffs else None)

def run_seal(rec):
    for c in CASES["seal_cases"]:
        try:
            a = resolve(c["seal"], "organisation_seals")
            tss = [resolve_ptr(p) for p in c.get("timestamps", [])]
            policy, export, export_bytes, ab_docs = build_context(c)
            got = S.check_seal(a, policy, ab_docs, export, export_bytes, tss, [("organisation_seals", a)])
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("signatures/seal", c["id"], False, {"exception": repr(e)}); continue
        exp = c["expected"]
        defaults = {"status": "verified", "signature": "verified", "subject": "verified", "key_state": "verified", "policy": "verified"}
        diffs = compare(got, exp, defaults, ["certificate", "embedded_copy"])
        if got["key_state"] == "verified":
            e = exp.get("time_basis", "stated_time")
            if got.get("time_basis") != e:
                diffs["time_basis"] = {"expected": e, "got": got.get("time_basis")}
        rec.add("signatures/seal", c["id"], not diffs, {"diffs": diffs, "got": {k: got.get(k) for k in ("signature_findings", "subject_findings", "key_state_detail", "embedded_copy_findings")}} if diffs else None)

def run_timestamp(rec):
    for c in CASES["timestamp_cases"]:
        try:
            ts = resolve_ptr(c["timestamp"])
            held = []
            for h in c["held"]:
                spec = h["name"] if "patch" not in h else {"from": h["name"], "patch": h["patch"]}
                held.append((h["kind"], resolve(spec, h["kind"])))
            policy = P.apply(VEC["trust_policy"], c.get("policy_patch", []), vectors=VEC)
            ok, reason = S.check_policy(policy)
            got = S.check_timestamp(ts, held, policy, ok, reason)
        except Exception as e:
            import traceback; traceback.print_exc()
            rec.add("signatures/timestamp", c["id"], False, {"exception": repr(e)}); continue
        exp = c["expected"]
        defaults = {k: "verified" for k in ("status", "token", "message_imprint", "subject_bytes", "message_digest",
                                             "tsa_signature", "signer_certificate", "tsa_state", "signer_time")}
        diffs = compare(got, exp, defaults, ["consistency", "existed_no_later_than", "gen_time"])
        rec.add("signatures/timestamp", c["id"], not diffs, {"diffs": diffs, "got": {k: got.get(k) for k in ("token_finding", "tsa_finding", "cert_finding")}} if diffs else None)

if __name__ == "__main__":
    rec = Recorder()
    run_person(rec); run_seal(rec); run_timestamp(rec)
    fails = [r for r in rec.rows if r["result"] is not True]
    from collections import Counter
    print("total", len(rec.rows), "fail", len(fails), Counter(r["suite"] for r in fails))
    for r in fails:
        print(r["id"], json.dumps(r.get("detail"), ensure_ascii=False)[:700])
