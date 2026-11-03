"""Action binding 0.3.0: the issuer signature, time assurance and the whole report
('The verifier and its report'), over ab_check.py and sig_check.py."""
import hashlib, json, os
import jsonschema
from strictjson import loads, Unreadable, to_native
from times import instant, utc_text
import sig_check as S
from ab_check import check_attachment

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_SCHEMA = None

def _schema():
    global _SCHEMA
    if _SCHEMA is None:
        p = os.path.join(ROOT, "inputs/standard/extensions/action-binding/schemas/execution-evidence.schema.json")
        with open(p, "rb") as f:
            _SCHEMA = to_native(loads(f.read()))
    return _SCHEMA

COPY_MEMBERS = {"algorithm", "key_ref", "signed_bytes_ref", "sealed_at", "value_b64"}

def virtual_seal(att, att_bytes):
    """The seal of kind attachment the copy stands for, so that a timestamp's subject can name it."""
    c = att.get("issuer_signature")
    if not isinstance(c, dict):
        return None
    d = S.attachment_sealed_digest(att_bytes) if att_bytes is not None else None
    return {"profile": S.PROFILE, "profile_version": S.VERSION, "assertion": "organisation_seal",
            "sealed": {"kind": "attachment", "id": att.get("decision_id"), "digest": d},
            "sealed_at": c.get("sealed_at"),
            "signature": {"algorithm": c.get("algorithm"), "key_ref": c.get("key_ref"), "value_b64": c.get("value_b64")}}

def issuer_signature(att, att_bytes, policy, policy_ok, policy_reason, beside, held):
    """Returns (issuer_signature dimension, list of verified covering timestamps [(T, index, tsa_ref)])."""
    c = att.get("issuer_signature")
    if c is None:
        return {"status": "not_checked", "findings": ["the attachment carries no issuer signature"]}, []
    out = {"attests": "issuer_recorded_claims_only"}
    f = []
    if not policy_ok:
        out.update(status="failed", findings=["not checked: the trust policy is refused (%s)" % policy_reason],
                   key_state={"status": "failed", "findings": ["not checked: the trust policy is refused (%s)" % policy_reason]})
        return out, []
    if not isinstance(c, dict) or set(c) != COPY_MEMBERS:
        f.append("the copy does not have exactly the five members")
    elif c.get("algorithm") != "Ed25519":
        f.append("the copy's algorithm is not exactly Ed25519")
    elif c.get("signed_bytes_ref") != S.COPY_REF:
        f.append("the copy does not name the signatures 0.2.0 organisation seal as its signed bytes")
    if f:
        out.update(status="failed", findings=f, key_state={"status": "not_checked"})
        return out, []
    entry = S.find_key(policy, c.get("key_ref"))
    out["key_ref"] = c.get("key_ref"); out["algorithm"] = c.get("algorithm")
    if att_bytes is None:
        out.update(status="failed", findings=["the attachment has no bytes as received"], key_state={"status": "not_checked"})
        return out, []
    digest = S.attachment_sealed_digest(att_bytes)
    seal = {"sealed_at": c.get("sealed_at"), "signature": {"algorithm": c.get("algorithm"), "key_ref": c.get("key_ref"), "value_b64": c.get("value_b64")}}
    s_status, s_find, cert = S.seal_signature_dim(seal, entry, policy_ok, policy_reason, "attachment", att.get("decision_id"), digest)
    if entry is not None:
        out["holder"] = entry.get("holder")
        out["reference_source"] = "trust_policy"
    out["certificate"] = cert
    times = []
    if s_status == "verified":
        timestamps = (beside or {}).get("timestamps", []) or []
        for i, ts in enumerate(timestamps):
            if (ts.get("subject") or {}).get("value_b64") != c.get("value_b64"):
                continue
            r = S.check_timestamp(ts, held, policy, policy_ok, policy_reason)
            if r["status"] == "verified" and r.get("subject_bytes") == "verified":
                times.append((r["T"], i, ts.get("tsa_ref")))
        ks = S.key_state(entry, c.get("sealed_at"), [(t, i) for t, i, _ in times], policy_ok, policy_reason)
    else:
        ks = {"status": "not_checked", "findings": ["the signature is not verified"]}
    out["key_state"] = ks
    status = "verified" if s_status == "verified" and ks["status"] == "verified" else (
        s_status if s_status != "verified" else ks["status"])
    out["status"] = status
    if s_find:
        f += s_find
    # sealed_at earlier than the latest stage
    sa = instant(c.get("sealed_at"))
    if sa is not None:
        later = [s for s in att.get("stages", []) if instant(s.get("at")) is not None and instant(s.get("at")) > sa]
        if later:
            out["sealed_at_note"] = "earlier_than_a_stage"
            f.append("sealed_at (%s) is earlier than the latest stage the attachment records (%s); both are the issuer's times; the signature stands" % (c.get("sealed_at"), later[-1].get("at")))
    if f:
        out["findings"] = f
    return out, (times if status == "verified" else [])

def time_assurance(att, times):
    if not times:
        return {"status": "not_checked", "basis": "issuer_assertion"}
    T, idx, tsa = min(times)
    ta = {"status": "verified", "basis": "independent_source", "source_ref": tsa, "no_later_than": utc_text(T),
          "timestamp_index": idx,
          "findings": ["the issuer signature, and so the attachment's bytes as issued, existed no later than %s (%s); not when any stage happened" % (utc_text(T), tsa)]}
    after = [s for s in att.get("stages", []) if instant(s.get("at")) is not None and instant(s.get("at")) > T]
    if after:
        ta["stage_after_timestamp"] = True
        ta["findings"].append("the issuer's stage times are inconsistent with the timestamp: stage %s is dated %s; the time stands" % (after[0].get("stage_id"), after[0].get("at")))
    return ta

def build_result(index, att_bytes, att_doc, record_bytes, policy, policy_ok, policy_reason, beside, held):
    if att_bytes is not None:
        try:
            att = loads(att_bytes)
        except Unreadable as e:
            return {"attachment_index": index, "unreadable": str(e)}
    else:
        att = att_doc
    sv = {"status": "verified"}
    errs = list(jsonschema.Draft202012Validator(_schema()).iter_errors(to_native(att)))
    if errs:
        sv = {"status": "failed", "findings": [e.message[:200] for e in errs[:5]]}
    b = check_attachment(att, record_bytes)
    isig, times = issuer_signature(att, att_bytes, policy, policy_ok, policy_reason, beside, held)
    res = {"attachment_index": index, "decision_id": att.get("decision_id"),
           "attachment_digest": hashlib.sha256(att_bytes).hexdigest() if att_bytes is not None else None,
           "structural_validity": sv}
    res.update(b)
    res["identity_assurance"] = {"status": "not_checked", "basis": "issuer_assertion"}
    res["authority_assurance"] = {"status": "not_checked", "basis": "issuer_assertion"}
    res["time_assurance"] = time_assurance(att, times)
    res["issuer_signature"] = isig
    legal = [s for s in att.get("stages", []) if s.get("legal_signature_ref")]
    res["legal_signature"] = {"status": "not_checked", "basis": "issuer_assertion",
                              "findings": ["a legal signature is referenced; its legal effect is outside this extension"] if legal else ["no legal signature is referenced"]}
    return res

def build_report(attachments, records, policy, beside_bytes=None):
    """attachments: list of (bytes or None, doc). records: {decision_id: bytes}."""
    ok, reason = S.check_policy(policy)
    beside = loads(beside_bytes) if beside_bytes is not None else None
    held = []
    if beside:
        for s in beside.get("organisation_seals", []) or []:
            held.append(("organisation_seals", s))
        for s in beside.get("person_signatures", []) or []:
            held.append(("person_signatures", s))
    for raw, doc in attachments:
        try:
            a = loads(raw) if raw is not None else doc
        except Unreadable:
            continue
        v = virtual_seal(a, raw)
        if v is not None and not any((h[1].get("signature") or {}).get("value_b64") == v["signature"]["value_b64"] and h[1].get("sealed", {}).get("id") == v["sealed"]["id"] for h in held):
            held.append(("copy", v))
    results = []
    for i, (raw, doc) in enumerate(attachments):
        did = (loads(raw) if raw is not None else doc).get("decision_id")
        results.append(build_result(i, raw, doc, records.get(did), policy, ok, reason, beside, held))
    rep = {"profile": "dps-action-binding-report", "profile_version": "0.3.0", "attachment_count": len(results),
           "trust_policy_ref": policy.get("policy_ref", "unnamed"),
           "trust_policy": {"status": "verified"} if ok else {"status": "failed", "findings": [reason]}}
    if beside_bytes is not None:
        rep["signatures_attachment_digest"] = hashlib.sha256(beside_bytes).hexdigest()
    rep["results"] = results
    rep["scope_of_conclusion"] = {"covers": "supplied_attachments_only",
                                  "not_assessed": ["legal_requirements", "conformance_level", "events_not_in_attachment",
                                                   "truth_of_recorded_claims", "what_the_reviewer_saw"]}
    return rep
