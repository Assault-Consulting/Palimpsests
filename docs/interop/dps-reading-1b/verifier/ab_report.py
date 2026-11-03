"""The action binding 0.3.0 verification report (schemas/verification-report.schema.json), built
from ab_binding and ab_sig."""
import json
from dps_common import compact, sha256_hex
import ab_binding, ab_sig
from jsonschema import Draft202012Validator

NOT_ASSESSED = ["legal_requirements", "conformance_level", "events_not_in_attachment",
                "truth_of_recorded_claims", "what_the_reviewer_saw"]


def result(i, att, att_bytes, record_text, policy, beside, att_schema=None):
    o = ab_binding.check(att, record_text)
    sv = {"status": "verified"}
    if att_schema is not None:
        errs = list(Draft202012Validator(att_schema).iter_errors(att))
        if errs:
            sv = {"status": "failed", "findings": [e.message[:200] for e in errs[:5]]}
    sig, ta, facts = ab_sig.check(att, att_bytes, policy, beside)
    r = {"attachment_index": i, "decision_id": att.get("decision_id"), "attachment_digest": sha256_hex(att_bytes),
         "structural_validity": sv, "specifications": o["specifications"], "reviews": o["reviews"],
         "executed_specifications": o["executed_specifications"]}
    if o["standing_approvals"]:
        r["standing_approvals"] = o["standing_approvals"]
    for k in ("record_statements", "action_binding"):
        r[k] = o[k]
    r["stage_order"] = dict(o["stage_order"], time_basis="issuer_assertion")
    for k in ("authorisation_recheck", "observed_results", "rationale_provenance"):
        r[k] = o[k]
    r["identity_assurance"] = {"status": "not_checked", "basis": "issuer_assertion"}
    r["authority_assurance"] = {"status": "not_checked", "basis": "issuer_assertion"}
    r["time_assurance"] = ta
    if sig["status"] == "not_checked" and "key_ref" not in sig:
        sig = {"status": "not_checked", "findings": sig.get("findings", [])}
    r["issuer_signature"] = sig
    legal = [s for s in att.get("stages", []) if s.get("legal_signature_ref")]
    r["legal_signature"] = {"status": "not_checked", "basis": "issuer_assertion",
                            "findings": ["a legal signature is referenced; its effect is outside this extension"] if legal
                            else ["no legal signature is referenced"]}
    return r


def build(atts, records, policy, beside, policy_ref=None, att_schema=None, beside_bytes=None):
    from sigcore import policy_refusal
    ref = policy_refusal(policy)
    rep = {"profile": "dps-action-binding-report", "profile_version": "0.3.0", "attachment_count": len(atts),
           "trust_policy_ref": policy_ref or policy.get("policy_ref"),
           "trust_policy": {"status": "failed", "findings": [ref]} if ref else {"status": "verified"}}
    if beside is not None:
        rep["signatures_attachment_digest"] = sha256_hex(beside_bytes if beside_bytes is not None else compact(beside))
    recs = records or [None] * len(atts)
    rep["results"] = [result(i, a, compact(a) if not isinstance(a, tuple) else a[1], recs[i], policy, beside, att_schema)
                      for i, a in enumerate(atts)]
    rep["scope_of_conclusion"] = {"covers": "supplied_attachments_only", "not_assessed": NOT_ASSESSED}
    return rep


def strip_findings(o):
    if isinstance(o, dict):
        return {k: strip_findings(v) for k, v in o.items() if k != "findings"}
    if isinstance(o, list):
        return [strip_findings(v) for v in o]
    return o


def first_difference(a, b, path=""):
    if type(a) != type(b):
        return "%s: %r vs %r" % (path or "/", a if not isinstance(a, (dict, list)) else type(a).__name__,
                                 b if not isinstance(b, (dict, list)) else type(b).__name__)
    if isinstance(a, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a or k not in b:
                return "%s/%s: present only in %s" % (path, k, "mine" if k in a else "theirs")
            d = first_difference(a[k], b[k], path + "/" + k)
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return "%s: length %d vs %d" % (path, len(a), len(b))
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, "%s/%d" % (path, i))
            if d:
                return d
        return None
    return None if a == b else "%s: %r vs %r" % (path, a, b)
