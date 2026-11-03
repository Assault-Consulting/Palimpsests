"""Signatures 0.2.0 pairing: the report read with its documents, by the same rule as
pairing_ab.py: counts, indexes, digests and carried values as found here; a dimension called
verified is verified here; saying less (not_checked) is allowed."""
import hashlib, sys
import jsonschema
import sig_check as S
from run_schema import SIG_REP, REG

def ok_status(r, m):
    return r == m or r == "not_checked"

def check(report, att, att_bytes, export, export_bytes, ab_docs, policy):
    try:
        errs = list(jsonschema.Draft202012Validator(SIG_REP, registry=REG).iter_errors(report))
    except RecursionError:
        return False, "the report cannot be validated (nested too deep)"
    if errs:
        return False, "schema: " + errs[0].message[:150]
    pok, reason = S.check_policy(policy)
    if report.get("trust_policy_ref") != policy.get("policy_ref"):
        return False, "another trust policy"
    if report["trust_policy"]["status"] != ("verified" if pok else "failed"):
        return False, "trust_policy status"
    if att_bytes is None or report.get("attachment_digest") != hashlib.sha256(att_bytes).hexdigest():
        return False, "attachment_digest is not the attachment read"
    want = set()
    if export_bytes is not None:
        want.add(("export", None, hashlib.sha256(export_bytes).hexdigest()))
    for did, (b, d) in ab_docs.items():
        if b is not None:
            want.add(("action_binding_attachment", did, hashlib.sha256(b).hexdigest()))
    got = {(x["kind"], x.get("decision_id"), x["digest"]) for x in report.get("documents", [])}
    if got != want or len(report.get("documents", [])) != len(want):
        return False, "documents are not the documents read, each with its digest"
    ps, os_, ts = att.get("person_signatures", []) or [], att.get("organisation_seals", []) or [], att.get("timestamps", []) or []
    held = [("person_signatures", a) for a in ps] + [("organisation_seals", a) for a in os_]
    for key, cnt, lst, idxk in (("person_signatures", "person_signature_count", ps, "signature_index"),
                                ("organisation_seals", "organisation_seal_count", os_, "seal_index"),
                                ("timestamps", "timestamp_count", ts, "timestamp_index")):
        rl = report.get(key, [])
        if type(report.get(cnt)) is not int or report[cnt] != len(lst) or len(rl) != len(lst):
            return False, "%s: count or results" % key
        idx = [r.get(idxk) for r in rl]
        if any(type(i) is not int for i in idx) or sorted(idx) != list(range(len(lst))):
            return False, "%s: indexes" % key
    for r in report.get("person_signatures", []):
        a = ps[r["signature_index"]]
        m = S.check_person(a, policy, ab_docs, export, ts, held)
        sig = a.get("signature") or {}
        if r.get("assertion") != a.get("assertion") or r.get("decision_id") != a.get("decision_id") or r.get("key_ref") != sig.get("key_ref") or r.get("stage_id") != a.get("stage_id"):
            return False, "person %d: names another assertion" % r["signature_index"]
        for k in ("status",):
            if not ok_status(r[k], m[k]): return False, "person %d status %s, check %s" % (r["signature_index"], r[k], m[k])
        for k in ("signature", "subject", "key_state", "identity"):
            if not ok_status(r[k]["status"], m[k]): return False, "person %d %s %s, check %s" % (r["signature_index"], k, r[k]["status"], m[k])
        rk, mk = r["key_state"], m["key_state_detail"]
        if rk["status"] == "verified":
            for k in ("time_basis", "time", "timestamp_index", "key_ref"):
                if rk.get(k) != mk.get(k): return False, "person %d key_state %s" % (r["signature_index"], k)
        ri, mi = r["identity"], m["identity_detail"]
        for k in ("source_ref", "holder", "issuer_named", "consistency"):
            if k in ri and ri[k] != mi.get(k): return False, "person %d identity %s" % (r["signature_index"], k)
        au = r.get("authenticator")
        if au:
            for k in ("user_present", "user_verified"):
                if k in au and au[k] != m.get(k): return False, "person %d authenticator %s" % (r["signature_index"], k)
        if "covers_affirmation_record" in r["subject"] and r["subject"]["covers_affirmation_record"] != m.get("covers_affirmation_record"):
            return False, "person %d covers_affirmation_record" % r["signature_index"]
    for r in report.get("organisation_seals", []):
        a = os_[r["seal_index"]]
        m = S.check_seal(a, policy, ab_docs, export, export_bytes, ts, held)
        sg = a.get("signature") or {}
        if r.get("key_ref") != sg.get("key_ref") or r.get("sealed", {}).get("kind") != (a.get("sealed") or {}).get("kind") or r.get("sealed", {}).get("id") != (a.get("sealed") or {}).get("id"):
            return False, "seal %d: names another assertion" % r["seal_index"]
        if not ok_status(r["status"], m["status"]): return False, "seal %d status" % r["seal_index"]
        for k in ("signature", "subject", "key_state"):
            if not ok_status(r[k]["status"], m[k]): return False, "seal %d %s %s, check %s" % (r["seal_index"], k, r[k]["status"], m[k])
        if "certificate" in r["signature"] and not ok_status(r["signature"]["certificate"], m["certificate"]):
            return False, "seal %d certificate %s, check %s" % (r["seal_index"], r["signature"]["certificate"], m["certificate"])
        if "embedded_copy" in r["subject"] and not ok_status(r["subject"]["embedded_copy"], m["embedded_copy"]):
            return False, "seal %d embedded_copy %s, check %s" % (r["seal_index"], r["subject"]["embedded_copy"], m["embedded_copy"])
        if r["key_state"]["status"] == "verified":
            for k in ("time_basis", "time", "timestamp_index"):
                if r["key_state"].get(k) != m["key_state_detail"].get(k): return False, "seal %d key_state %s" % (r["seal_index"], k)
    for r in report.get("timestamps", []):
        t = ts[r["timestamp_index"]]
        m = S.check_timestamp(t, held, policy, pok, reason)
        if r.get("tsa_ref") != t.get("tsa_ref"):
            return False, "timestamp %d tsa_ref" % r["timestamp_index"]
        ts_subj = t.get("subject") or {}
        if r.get("subject", {}).get("kind") != ts_subj.get("kind") or r.get("subject", {}).get("of") != ts_subj.get("of"):
            return False, "timestamp %d: the subject is not the attachment's" % r["timestamp_index"]
        if not ok_status(r["status"], m["status"]): return False, "timestamp %d status" % r["timestamp_index"]
        for k, v in (r.get("checks") or {}).items():
            if not ok_status(v, m.get(k)): return False, "timestamp %d %s %s, check %s" % (r["timestamp_index"], k, v, m.get(k))
        for k in ("gen_time", "existed_no_later_than"):
            if k in r and r[k] != m.get(k): return False, "timestamp %d %s" % (r["timestamp_index"], k)
        st = r.get("signer_time")
        if st:
            if not ok_status(st["status"], m["signer_time"]): return False, "timestamp %d signer_time %s, check %s" % (r["timestamp_index"], st["status"], m["signer_time"])
            if "consistency" in st and st["consistency"] != m.get("consistency"): return False, "timestamp %d signer_time consistency" % r["timestamp_index"]
    return True, None
