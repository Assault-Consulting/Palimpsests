"""Second input: Lemonnier's examples/release-decision and interop/aqta/approval-record/out.
Bytes are read as downloaded. N1-N7b carry no documents, only a description and someone else's
results: they are rebuilt here from their 'what' text, and marked so."""
import json, hashlib, base64, copy
from common import *
from strictjson import loads, dumps_compact, to_native
import ab_report as AR
import sig_check as S

def rb(p):
    with open(p, "rb") as f:
        return f.read()

EMPTY_POLICY = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0",
                "policy_ref": "urn:dps-reading-1:verifier-policy:no-keys", "tsas": [], "checkpoint_sources": [], "keys": []}

def ab_dims(res):
    d = {"structural_validity": res["structural_validity"]["status"],
         "specification_digests": [s["digest"]["status"] for s in res["specifications"]],
         "specification_statements": [s["statements"]["status"] for s in res["specifications"]]}
    for k in ("record_statements", "action_binding", "stage_order", "authorisation_recheck", "observed_results",
              "rationale_provenance", "identity_assurance", "authority_assurance", "time_assurance", "issuer_signature",
              "legal_signature"):
        d[k] = res[k]["status"]
    d["execution_state"] = res["observed_results"]["execution_state"]
    d["observed"] = [[a["attempt_stage_id"], a["observed"], a.get("basis")] for a in res["observed_results"]["attempts"]]
    d["executed"] = [[e["spec_index"], e["reached_by"]] for e in res["executed_specifications"]]
    d["reviews"] = [[r["review_stage_id"], r["shown"], r.get("edited_by")] for r in res["reviews"]]
    d["findings"] = {k: res[k].get("findings") for k in ("action_binding", "record_statements", "stage_order",
                     "authorisation_recheck", "observed_results", "rationale_provenance", "issuer_signature") if res[k].get("findings")}
    return d

def person_dims(p):
    return {k: p.get(k) for k in ("status", "signature", "subject", "key_state", "identity", "policy", "time_basis", "consistency")} | \
           {"findings": {k: p.get(k + "_findings") for k in ("signature", "subject") if p.get(k + "_findings")}}

def record_seal_zeroed(record_bytes):
    """Not an extension rule: the convention the action-binding cases state for their fixture
    records (D11): SHA-256 of the record with the seal_hash value replaced by 64 zeros."""
    r = loads(record_bytes)
    t = record_bytes.replace(r["seal_hash"].encode(), b"0" * 64)
    return hashlib.sha256(t).hexdigest() == r["seal_hash"]

def run_release():
    base = os.path.join(LL, "examples/release-decision")
    att = rb(os.path.join(base, "action-binding-attachment.json"))
    rec = rb(os.path.join(base, "decision-record.json"))
    rep = AR.build_report([(att, None)], {loads(att)["decision_id"]: rec}, EMPTY_POLICY, None)
    r = rep["results"][0]
    return {"attachment_digest": r["attachment_digest"], "trust_policy": rep["trust_policy"]["status"],
            "trust_policy_ref": rep["trust_policy_ref"],
            "dimensions": ab_dims(r),
            "not_checked_because_unsigned": ["issuer_signature (the attachment carries no issuer signature)",
                                             "time_assurance (no verified timestamp over a verified issuer signature)",
                                             "issuer key state, holder and certificate (no signature)"],
            "not_checked_in_any_case": ["identity_assurance (no independent source)", "authority_assurance (no independent source)",
                                        "legal_signature (none referenced)"],
            "extra_record_seal_zeroed_convention": record_seal_zeroed(rec)}, rep

def aqta_inputs():
    base = os.path.join(LL, "interop/aqta/approval-record/out")
    return {n: rb(os.path.join(base, n)) for n in ("action-binding-attachment.json", "decision-record.json",
            "signatures-attachment.json", "trust-policy.json", "specification.bytes.json", "approval.canonical.json",
            "arguments.canonical.json", "review-view.txt")}

def run_aqta_case(att_bytes, rec_bytes, sig_bytes, policy):
    att = loads(att_bytes)
    did = att["decision_id"]
    rep = AR.build_report([(att_bytes, None)], {did: rec_bytes}, policy, sig_bytes)
    sa = loads(sig_bytes)
    persons = []
    held = [("person_signatures", p) for p in sa.get("person_signatures", [])]
    for p in sa.get("person_signatures", []):
        persons.append(person_dims(S.check_person(p, policy, {did: (att_bytes, None)}, None, sa.get("timestamps", []) or [], held)))
    return {"ab_attachment_digest": rep["results"][0]["attachment_digest"],
            "signatures_attachment_digest": hashlib.sha256(sig_bytes).hexdigest(),
            "trust_policy": rep["trust_policy"]["status"],
            "action_binding": ab_dims(rep["results"][0]), "person_approvals": persons}

def run_aqta():
    I = aqta_inputs()
    policy = loads(I["trust-policy.json"])
    out = {"base": run_aqta_case(I["action-binding-attachment.json"], I["decision-record.json"], I["signatures-attachment.json"], policy)}
    spec = I["specification.bytes.json"]
    out["extra"] = {
        "specification.bytes.json is the attachment's specification bytes": base64.b64decode(loads(I["action-binding-attachment.json"])["action_specifications"][0]["content"]["bytes_b64"]) == spec,
        "SHA-256(review-view.txt) equals the review's shown_view_digest": hashlib.sha256(I["review-view.txt"]).hexdigest() == loads(I["action-binding-attachment.json"])["stages"][1]["shown_view_digest"],
        "SHA-256(arguments.canonical.json) equals the specification's parameters.args_hash": hashlib.sha256(I["arguments.canonical.json"]).hexdigest() == loads(spec)["parameters"]["args_hash"],
        "record seal under the fixtures' zeroed convention": record_seal_zeroed(I["decision-record.json"]),
        "not attempted": ["seal_action_record (the AQTA action record's own signature: outside both extensions)",
                          "policy_checks (policy digest, approval age, valid_until, designated approver: rules of policy.json, outside both extensions)",
                          "composition_args_hash_bound (draft-chueayen composition: outside both extensions)"]}
    # ---- negatives, rebuilt from their 'what' text (read after their results were seen: not independent)
    A = to_native(loads(I["action-binding-attachment.json"]))
    R = I["decision-record.json"]; SIG = I["signatures-attachment.json"]
    neg = {}
    def enc(d): return dumps_compact(d)
    def add_spec(a, new_bytes, summary_patch=None):
        d = hashlib.sha256(new_bytes).hexdigest()
        s = copy.deepcopy(a["action_specifications"][0])
        s["spec_digest"] = d; s["content"]["bytes_b64"] = base64.b64encode(new_bytes).decode()
        if summary_patch: s["summary"].update(summary_patch)
        return s, d
    # N1: request and attempt carry a specification with pull_number 4522
    a = copy.deepcopy(A)
    s, d = add_spec(a, spec.replace(b'"pull_number":"4521"', b'"pull_number":"4522"'))
    a["action_specifications"].append(s)
    for st in a["stages"]:
        if st["kind"] in ("request", "attempt"): st["spec_digest"] = d
    neg["N1"] = run_aqta_case(enc(a), R, SIG, policy)
    # N2: a second request, recheck, attempt and result on o1 (request_limit 1)
    a = copy.deepcopy(A)
    q2 = copy.deepcopy(a["stages"][3]); q2.update(stage_id="q2", at="2026-10-29T16:14:00Z", request_id=q2["request_id"] + "-2")
    c2 = copy.deepcopy(a["stages"][4]); c2.update(stage_id="c2", at="2026-10-29T16:14:10Z", request_ref="q2")
    x2 = copy.deepcopy(a["stages"][5]); x2.update(stage_id="x2", at="2026-10-29T16:14:15Z", request_ref="q2", recheck_ref="c2")
    r2 = copy.deepcopy(a["stages"][6]); r2.update(stage_id="r2", at="2026-10-29T16:14:30Z", attempt_ref="x2")
    a["stages"] += [q2, c2, x2, r2]
    neg["N2"] = run_aqta_case(enc(a), R, SIG, policy)
    # N3: the approval made with a key the policy does not list
    sa = to_native(loads(SIG)); sa["person_signatures"][0]["signature"]["key_ref"] = "someone-else-key-1"
    neg["N3"] = run_aqta_case(I["action-binding-attachment.json"], R, enc(sa), policy)
    neg["N3"]["rebuilt_note"] = "key_ref changed only: the value is not a signature by someone-else-key-1, which this reading does not hold; the signature fails before any verification, on the key not being listed"
    # N3b: that key listed in role organisation
    p2 = to_native(copy.deepcopy(policy))
    p2["keys"].append({"key_ref": "someone-else-key-1", "holder": "someone-else", "role": "organisation", "algorithm": "Ed25519",
                       "public_key_hex": "11" * 32, "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-08-31T23:59:59Z"})
    neg["N3b"] = run_aqta_case(I["action-binding-attachment.json"], R, enc(sa), p2)
    neg["N3b"]["rebuilt_note"] = "public key of someone-else-key-1 invented (32 bytes of 0x11): the signature fails on the role before verification"
    # N4, N5: only policy.json changes or is absent; it is no input of either extension
    neg["N4"] = {"same_as": "base", "note": "the change is to policy.json, which neither extension reads: every dimension of both extensions is the base's"}
    neg["N5"] = {"same_as": "base", "note": "policy.json not held: neither extension reads it; every dimension is the base's"}
    # N6: the recheck, attempt and result 28 minutes after the approval
    a = copy.deepcopy(A)
    a["stages"][4]["at"] = "2026-10-29T16:40:00Z"; a["stages"][5]["at"] = "2026-10-29T16:40:00Z"; a["stages"][6]["at"] = "2026-10-29T16:40:20Z"
    neg["N6"] = run_aqta_case(enc(a), R, SIG, policy)
    neg["N6"]["rebuilt_note"] = "recheck and attempt moved to 16:40:00Z (28 min after o1), result 16:40:20Z; valid_until is a member of the specification, which action binding does not compare with any time outside standing approvals"
    # N7: the specification rewritten to name another policy; every digest in the attachment follows
    a = copy.deepcopy(A)
    newspec = spec.replace(b"6f89d3c6338be7291113bf0e99c676992c3a2493ce271b12d7d7ec08f756b9e8", b"0" * 64)
    s, d = add_spec(a, newspec, {"policy_version": "sha256:" + "0" * 64})
    a["action_specifications"] = [s]
    for st in a["stages"]:
        for k in ("spec_digest", "shown_spec_digest", "approved_spec_digest"):
            if k in st: st[k] = d
    neg["N7"] = run_aqta_case(enc(a), R, SIG, policy)
    neg["N7"]["rebuilt_note"] = "the other policy digest invented (64 zeros)"
    # N7b: authority_ref changed after signing
    a = copy.deepcopy(A); a["stages"][2]["authority"]["authority_ref"] = "urn:isoluce:policy:another#2026-10-01"
    neg["N7b"] = run_aqta_case(enc(a), R, SIG, policy)
    out["negatives_rebuilt"] = neg
    return out

if __name__ == "__main__":
    rel, rel_rep = run_release()
    aq = run_aqta()
    res = {"recorded_before_opening_any_summary_json": True, "release_decision": rel, "aqta": aq}
    with open(os.path.join(ROOT, "out", "second-input-verdicts.json"), "w") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    with open(os.path.join(ROOT, "out", "release-decision.report.json"), "w") as f:
        json.dump(rel_rep, f, indent=1, ensure_ascii=False)
    print(json.dumps(res, indent=1, ensure_ascii=False)[:9000])
