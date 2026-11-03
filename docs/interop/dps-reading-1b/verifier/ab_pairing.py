"""Reading a report with the documents it covers (action binding, "The verifier and its report":
"A report may say less than the reference check ...; it may not say more"; "JSON Schema cannot
compare two documents, so a reader holding both checks this")."""
from dps_common import compact, sha256_hex

LESS = ("not_checked", "unavailable", "not_supported")


def _st(reported, mine, where, out):
    """A reported status may be less than mine, never more or other."""
    if reported in LESS:
        return
    if reported != mine:
        out.append("%s: reported %s, the check finds %s" % (where, reported, mine))


def read(report, mine, att_bytes_list, beside_bytes):
    """Returns the list of inconsistencies (empty: consistent)."""
    out = []
    n = len(att_bytes_list)
    if report.get("attachment_count") != n or isinstance(report.get("attachment_count"), bool):
        out.append("attachment_count is %r; %d attachments" % (report.get("attachment_count"), n))
    res = report.get("results", [])
    idx = [r.get("attachment_index") for r in res]
    if sorted(i for i in idx if isinstance(i, int) and not isinstance(i, bool)) != list(range(n)) or len(idx) != n:
        out.append("results do not give each attachment_index from 0 to %d once: %r" % (n - 1, idx))
    ids = [r.get("decision_id") for r in res]
    if len(set(ids)) != len(ids):
        out.append("two results name the same decision_id")
    mine_ids = [r["decision_id"] for r in mine["results"]]
    if len(set(mine_ids)) != len(mine_ids):
        out.append("two attachments for the same decision record")
    if beside_bytes is None:
        if "signatures_attachment_digest" in report:
            out.append("a signatures_attachment_digest where nothing was read beside")
    elif report.get("signatures_attachment_digest") not in (None, sha256_hex(beside_bytes)):
        out.append("signatures_attachment_digest is not the digest of the attachment beside")
    rp, mp = report.get("trust_policy", {}).get("status"), mine["trust_policy"]["status"]
    if rp != mp:
        out.append("trust_policy reported %s, the check finds %s" % (rp, mp))
    for r in res:
        i = r.get("attachment_index")
        if not isinstance(i, int) or isinstance(i, bool) or not 0 <= i < n:
            continue
        m = mine["results"][i]
        w = "result %d" % i
        if r.get("attachment_digest") != sha256_hex(att_bytes_list[i]):
            out.append("%s: attachment_digest is not the attachment's" % w)
            continue
        if r.get("decision_id") != m["decision_id"]:
            out.append("%s: decision_id %r, the attachment states %r" % (w, r.get("decision_id"), m["decision_id"]))
        rs, ms = r.get("specifications", []), m["specifications"]
        if [(s.get("spec_index"), s.get("spec_digest")) for s in rs] != [(s["spec_index"], s["spec_digest"]) for s in ms]:
            out.append("%s: specification results do not match the attachment's specifications" % w)
        else:
            for a, b in zip(rs, ms):
                _st(a["digest"]["status"], b["digest"]["status"], "%s spec %d digest" % (w, b["spec_index"]), out)
                _st(a["statements"]["status"], b["statements"]["status"], "%s spec %d statements" % (w, b["spec_index"]), out)
        if [(x.get("review_stage_id"), x.get("shown"), x.get("edited_by")) for x in r.get("reviews", [])] != \
                [(x["review_stage_id"], x["shown"], x.get("edited_by")) for x in m["reviews"]]:
            out.append("%s: reviews not carried through as the attachment records them" % w)
        if sorted((x.get("spec_index"), x.get("reached_by")) for x in r.get("executed_specifications", [])) != \
                sorted((x["spec_index"], x["reached_by"]) for x in m["executed_specifications"]):
            out.append("%s: executed_specifications differ from the check's" % w)
        for d in ("record_statements", "action_binding", "stage_order", "authorisation_recheck", "rationale_provenance",
                  "structural_validity"):
            _st(r.get(d, {}).get("status"), m[d]["status"], "%s %s" % (w, d), out)
        ro, mo = r.get("observed_results", {}), m["observed_results"]
        _st(ro.get("status"), mo["status"], "%s observed_results" % w, out)
        if ro.get("execution_state") != mo["execution_state"] or \
                [(a.get("attempt_stage_id"), a.get("observed"), a.get("basis")) for a in ro.get("attempts", [])] != \
                [(a["attempt_stage_id"], a["observed"], a.get("basis")) for a in mo["attempts"]]:
            out.append("%s: observed results or execution state not carried through as recorded" % w)
        if "standing_approvals" in r:
            ms_ = {s["stage_id"]: s for s in m.get("standing_approvals", [])}
            for s in r["standing_approvals"]:
                t = ms_.get(s.get("stage_id"))
                if t is None:
                    out.append("%s: standing approval %r not in the attachment" % (w, s.get("stage_id"))); continue
                _st(s.get("bounds", {}).get("status"), t["bounds"]["status"], "%s standing %s bounds" % (w, t["stage_id"]), out)
                for k in ("requests_recorded", "revocation"):
                    if s.get(k) != t[k]:
                        out.append("%s standing %s: %s reported %r, recorded %r" % (w, t["stage_id"], k, s.get(k), t[k]))
                for k in ("max_requests", "valid_from", "valid_until"):
                    if k in s and s.get(k) != t.get(k):
                        out.append("%s standing %s: %s differs" % (w, t["stage_id"], k))
        for d in ("identity_assurance", "authority_assurance", "legal_signature"):
            if r.get(d, {}).get("status") == "verified":
                out.append("%s: %s verified on no independent source this reader holds" % (w, d))
        ri, mi = r.get("issuer_signature", {}), m["issuer_signature"]
        _st(ri.get("status"), mi["status"], "%s issuer_signature" % w, out)
        if ri.get("status") == "verified":
            for k in ("key_ref", "algorithm", "holder", "reference_source"):
                if ri.get(k) != mi.get(k):
                    out.append("%s issuer_signature: %s %r, the check finds %r" % (w, k, ri.get(k), mi.get(k)))
        if "certificate" in ri:
            _st(ri["certificate"], mi.get("certificate", "not_checked"), "%s certificate" % w, out)
        rk, mk = ri.get("key_state"), mi.get("key_state", {})
        if isinstance(rk, dict):
            _st(rk.get("status"), mk.get("status"), "%s key_state" % w, out)
            if rk.get("status") == "verified":
                for k in ("key_ref", "time_basis", "time", "timestamp_index"):
                    if rk.get(k) != mk.get(k):
                        out.append("%s key_state: %s %r, the check finds %r" % (w, k, rk.get(k), mk.get(k)))
        rt, mt = r.get("time_assurance", {}), m["time_assurance"]
        _st(rt.get("status"), mt["status"], "%s time_assurance" % w, out)
        if rt.get("status") == "verified":
            for k in ("source_ref", "no_later_than", "timestamp_index"):
                if rt.get(k) != mt.get(k):
                    out.append("%s time_assurance: %s %r, the check finds %r" % (w, k, rt.get(k), mt.get(k)))
    return out
