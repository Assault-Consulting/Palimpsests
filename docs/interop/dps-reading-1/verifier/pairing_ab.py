"""Action binding 0.3.0 pairing: a report read with the documents it covers. The report is
consistent when it is schema-valid, counts, indexes and digests every attachment and
specification once, carries through what the attachment records as recorded, and says no more
than this reading's own check: a dimension it calls verified is verified here, and a value it
carries (holder, times, timestamps, reached_by, editors, observed results) is the one found here.
It may say less: not_checked where this check verifies, or leave optional parts out."""
import hashlib, json
import jsonschema
from strictjson import to_native, loads
import ab_report as AR
from run_schema import AB_REP, REG

DIMS = ("structural_validity", "record_statements", "action_binding", "stage_order", "authorisation_recheck",
        "observed_results", "rationale_provenance", "identity_assurance", "authority_assurance", "legal_signature")

def _status_ok(rep_s, mine_s):
    return rep_s == mine_s or rep_s == "not_checked"

def check_pairing(report, attachments, records, policy, beside_bytes):
    """attachments: list of (bytes or None, doc). Returns (consistent: bool, reason)."""
    if not isinstance(report, dict):
        return False, "not an object"
    errs = list(jsonschema.Draft202012Validator(AB_REP, registry=REG).iter_errors(report))
    if errs:
        return False, "schema: " + errs[0].message[:160]
    mine = AR.build_report(attachments, records, policy, beside_bytes)
    n = len(attachments)
    if type(report["attachment_count"]) is not int or report["attachment_count"] != n:
        return False, "attachment_count is not the number of attachments"
    res = report["results"]
    if len(res) != n:
        return False, "not one result for each attachment"
    idx = [r["attachment_index"] for r in res]
    if any(type(i) is not int for i in idx) or sorted(idx) != list(range(n)):
        return False, "attachment indexes are not 0..n-1 each once"
    dids = [m["decision_id"] for m in mine["results"]]
    if len(set(dids)) != len(dids):
        return False, "two attachments name the same decision_id"
    if report.get("trust_policy_ref") != policy.get("policy_ref"):
        return False, "another trust policy"
    if report["trust_policy"]["status"] != mine["trust_policy"]["status"]:
        return False, "trust_policy status is not the check's"
    if "signatures_attachment_digest" in report:
        if beside_bytes is None or report["signatures_attachment_digest"] != hashlib.sha256(beside_bytes).hexdigest():
            return False, "signatures_attachment_digest is not the digest of the attachment read beside"
    for r in res:
        m = mine["results"][r["attachment_index"]]
        why = _result(r, m)
        if why:
            return False, "result %d: %s" % (r["attachment_index"], why)
    return True, None

def _result(r, m):
    if r["decision_id"] != m["decision_id"]:
        return "decision_id"
    if r["attachment_digest"] != m["attachment_digest"]:
        return "attachment_digest is not the digest of the attachment read"
    if len(r["specifications"]) != len(m["specifications"]):
        return "not one result per specification"
    for rs in r["specifications"]:
        i = rs["spec_index"]
        if type(i) is not int or i >= len(m["specifications"]):
            return "spec_index"
        ms = m["specifications"][i]
        if rs["spec_digest"] != ms["spec_digest"]:
            return "spec_digest of specification %d" % i
        for k in ("digest", "statements"):
            if not _status_ok(rs[k]["status"], ms[k]["status"]):
                return "specification %d %s: %s, check finds %s" % (i, k, rs[k]["status"], ms[k]["status"])
    if sorted(x["spec_index"] for x in r["specifications"]) != list(range(len(m["specifications"]))):
        return "specification indexes"
    for k in DIMS:
        if not _status_ok(r[k]["status"], m[k]["status"]):
            return "%s: %s, check finds %s" % (k, r[k]["status"], m[k]["status"])
    if r["stage_order"]["status"] != m["stage_order"]["status"] and r["stage_order"]["status"] != "not_checked":
        return "stage_order"
    ro, mo = r["observed_results"], m["observed_results"]
    if ro["execution_state"] != mo["execution_state"]:
        return "execution_state not carried through"
    if [(a["attempt_stage_id"], a["observed"], a.get("basis")) for a in ro["attempts"]] != \
       [(a["attempt_stage_id"], a["observed"], a.get("basis")) for a in mo["attempts"]]:
        return "observed results not carried through as recorded"
    if [(e["spec_index"], e["reached_by"]) for e in r["executed_specifications"]] != \
       [(e["spec_index"], e["reached_by"]) for e in m["executed_specifications"]]:
        return "executed specifications"
    if [(v["review_stage_id"], v["shown"], v.get("edited_by")) for v in r["reviews"]] != \
       [(v["review_stage_id"], v["shown"], v.get("edited_by")) for v in m["reviews"]]:
        return "reviews"
    if "standing_approvals" in r:
        ms = {e["stage_id"]: e for e in m.get("standing_approvals", [])}
        for e in r["standing_approvals"]:
            x = ms.get(e["stage_id"])
            if x is None:
                return "a standing approval the attachment does not record"
            if not _status_ok(e["bounds"]["status"], x["bounds"]["status"]) and not (x["bounds"]["status"] in ("unavailable",) and e["bounds"]["status"] == "unavailable"):
                return "standing approval %s bounds" % e["stage_id"]
            if e["requests_recorded"] != x["requests_recorded"] or e["revocation"] != x["revocation"]:
                return "standing approval %s count or revocation" % e["stage_id"]
            for k in ("max_requests", "valid_from", "valid_until"):
                if k in e and e[k] != x.get(k):
                    return "standing approval %s %s" % (e["stage_id"], k)
    ri, mi = r["issuer_signature"], m["issuer_signature"]
    if not _status_ok(ri["status"], mi["status"]):
        return "issuer_signature: %s, check finds %s" % (ri["status"], mi["status"])
    for k in ("key_ref", "algorithm", "holder", "certificate"):
        if k in ri and k in mi and ri[k] != mi[k] and not (k == "certificate" and ri[k] == "not_checked"):
            return "issuer_signature %s" % k
        if k in ri and k not in mi:
            return "issuer_signature %s where the check has none" % k
    rk, mk = ri.get("key_state"), mi.get("key_state") or {}
    if rk:
        if not _status_ok(rk["status"], mk.get("status", "not_checked")):
            return "issuer key_state: %s, check finds %s" % (rk["status"], mk.get("status"))
        if rk["status"] == "verified":
            for k in ("time_basis", "time", "timestamp_index", "key_ref"):
                if rk.get(k) != mk.get(k):
                    return "issuer key_state %s" % k
    rt, mt = r["time_assurance"], m["time_assurance"]
    if not _status_ok(rt["status"], mt["status"]):
        return "time_assurance: %s, check finds %s" % (rt["status"], mt["status"])
    if rt["status"] == "verified":
        for k in ("source_ref", "no_later_than", "timestamp_index"):
            if rt.get(k) != mt.get(k):
                return "time_assurance %s" % k
    return None
