"""Second input (Lemonnier's repository at fdc5f63): the checks of this reading run on his
examples, and the negatives N1-N7b built from their descriptions. Writes out/second-input.json."""
import base64, copy, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from dps_common import strict_loads, compact, sha256_hex, instant
import ab_report, sig_check, sigcore
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

IN = os.environ.get("DPS_INPUTS", "/home/claude/run/inputs")
LL = IN + "/lemonnier"
AQ = LL + "/interop/aqta/approval-record/out"
EX = IN + "/standard/extensions"


def rb(p):
    with open(p, "rb") as fh:
        return fh.read()


AB_SCHEMA = strict_loads(rb(EX + "/action-binding/schemas/execution-evidence.schema.json"))
SG_SCHEMA = strict_loads(rb(EX + "/signatures/schemas/signatures-attachment.schema.json"))
TP_SCHEMA = strict_loads(rb(EX + "/anchoring/schemas/trust-policy.schema.json"))
CORE = strict_loads(rb(IN + "/standard/standard/v5.0/schemas/decision-record.schema.json"))
AB_REP = strict_loads(rb(EX + "/action-binding/schemas/verification-report.schema.json"))


MODE_DRIFT = "https://decisionprovenancestandard.org/schemas/mode-drift/layer-4-attestation.schema.json"


def valid(schema, doc):
    try:
        return [e.message[:160] for e in Draft202012Validator(schema).iter_errors(doc)][:3]
    except Exception as ex:
        # the core schema refers to a file that is not among the allowed inputs: validate with that
        # one subschema left open, and say so
        reg = Registry().with_resource(MODE_DRIFT, Resource.from_contents({"$schema": "https://json-schema.org/draft/2020-12/schema"}))
        errs = [e.message[:160] for e in Draft202012Validator(schema, registry=reg).iter_errors(doc)][:3]
        return errs + ["partial: %s not among the allowed inputs; that member's subschema left unchecked" % MODE_DRIFT.rsplit("/", 2)[-2] + "/layer-4-attestation.schema.json"]


def ab_view(att, att_bytes, rec_text, policy, beside):
    rep = ab_report.build([att], [rec_text], policy, beside, att_schema=AB_SCHEMA)
    # build() serialises compactly; replace the result with the one over the bytes as received
    r = ab_report.result(0, att, att_bytes, rec_text, policy, beside, AB_SCHEMA)
    rep["results"] = [r]
    errs = valid(AB_REP, rep)
    v = {"structural_validity": r["structural_validity"]["status"],
         "specification_digests": [s["digest"]["status"] for s in r["specifications"]],
         "specification_statements": [s["statements"]["status"] for s in r["specifications"]]}
    for d in ("record_statements", "action_binding", "stage_order", "authorisation_recheck", "observed_results",
              "rationale_provenance", "identity_assurance", "authority_assurance", "time_assurance", "issuer_signature",
              "legal_signature"):
        v[d] = r[d]["status"]
    v["execution_state"] = r["observed_results"]["execution_state"]
    v["observed"] = [[a["attempt_stage_id"], a["observed"], a.get("basis")] for a in r["observed_results"]["attempts"]]
    v["executed"] = [[e["spec_index"], e["reached_by"]] for e in r["executed_specifications"]]
    v["reviews"] = [[x["review_stage_id"], x["shown"], x.get("edited_by")] for x in r["reviews"]]
    v["trust_policy"] = rep["trust_policy"]["status"]
    v["attachment_digest"] = r["attachment_digest"]
    v["report_schema_errors"] = errs
    f = {d: r[d].get("findings") for d in ("record_statements", "action_binding", "stage_order", "authorisation_recheck",
                                           "observed_results", "rationale_provenance", "issuer_signature", "time_assurance") if r[d].get("findings")}
    return v, f, rep


def person_view(a, policy, ab_atts, timestamps=()):
    ref = sigcore.policy_refusal(policy)
    r = sig_check.person(a, policy, ab_atts, None, list(timestamps), ref)
    v = {"status": r["status"], "signature": r["signature"]["status"], "subject": r["subject"]["status"],
         "key_state": r["key_state"]["status"], "identity": r["identity"]["status"], "trust_policy": "failed" if ref else "verified"}
    for k in ("time_basis", "time"):
        if k in r["key_state"]: v["key_state_" + k] = r["key_state"][k]
    for k in ("consistency", "holder", "issuer_named", "source_ref"):
        if k in r["identity"]: v["identity_" + k] = r["identity"][k]
    f = {d: r[d].get("findings") for d in ("signature", "subject", "key_state", "identity") if r[d].get("findings")}
    return v, f


def main(outpath):
    out = {}
    # ---------------- examples/release-decision (unsigned)
    rd_b = rb(LL + "/examples/release-decision/action-binding-attachment.json")
    rd = strict_loads(rd_b)
    rd_rec = rb(LL + "/examples/release-decision/decision-record.json").decode("utf-8")
    tp_b = rb(AQ + "/trust-policy.json")
    tp = strict_loads(tp_b)
    v, f, rep = ab_view(rd, rd_b, rd_rec, tp, None)
    out["release-decision"] = {"schema_errors": {"attachment": valid(AB_SCHEMA, rd), "record": valid(CORE, strict_loads(rd_rec))},
                               "action_binding": v, "findings": f,
                               "policy_used": "interop/aqta/approval-record/out/trust-policy.json (urn:isoluce:trust-policy:verifier-1): the release decision names none"}
    # ---------------- interop/aqta/approval-record/out
    at_b = rb(AQ + "/action-binding-attachment.json")
    at = strict_loads(at_b)
    rec_t = rb(AQ + "/decision-record.json").decode("utf-8")
    sg_b = rb(AQ + "/signatures-attachment.json")
    sg = strict_loads(sg_b)
    appr = sg["person_signatures"][0]
    base = {"schema_errors": {"attachment": valid(AB_SCHEMA, at), "record": valid(CORE, strict_loads(rec_t)),
                              "signatures_attachment": valid(SG_SCHEMA, sg), "trust_policy": valid(TP_SCHEMA, tp)}}
    v, f, rep = ab_view(at, at_b, rec_t, tp, sg)
    base["action_binding"], base["action_binding_findings"] = v, f
    pv, pf = person_view(appr, tp, {at["decision_id"]: at})
    base["person_approval"], base["person_approval_findings"] = pv, pf
    spec_b = base64.b64decode(at["action_specifications"][0]["content"]["bytes_b64"])
    pol_b = rb(AQ + "/policy.json")
    view_b = rb(AQ + "/review-view.txt")
    specobj = strict_loads(spec_b)
    base["facts_outside_the_texts"] = {
        "specification.bytes.json is the specification's bytes": rb(AQ + "/specification.bytes.json") == spec_b,
        "review-view.txt hashes to the review's shown_view_digest": sha256_hex(view_b) == at["stages"][1].get("shown_view_digest"),
        "policy.json hashes to the specification's policy_version": "sha256:" + sha256_hex(pol_b) == specobj.get("policy_version"),
        "arguments.canonical.json hashes to the specification's args_hash": sha256_hex(rb(AQ + "/arguments.canonical.json")) == specobj["parameters"].get("args_hash"),
        "approval.canonical.json read as JSON equals the signed assertion": strict_loads(rb(AQ + "/approval.canonical.json")) == appr,
        "record seal_hash = SHA-256 with the seal_hash value replaced by 64 zeros (the AB fixtures' convention)":
            sha256_hex(rec_t.replace(strict_loads(rec_t)["seal_hash"], "0" * 64).encode()) == strict_loads(rec_t)["seal_hash"]}
    out["aqta"] = base

    # ---------------- negatives, built from their descriptions
    neg, choices = {}, {}
    o_idx = 2

    def ab_only(att2, rec=rec_t, beside=sg):
        b = compact(att2)
        return ab_view(att2, b, rec, tp, beside)[:2]

    # N1
    args_t = rb(AQ + "/arguments.canonical.json").decode("utf-8").replace('"pull_number":"4521"', '"pull_number":"4522"')
    s_t = spec_b.decode("utf-8").replace('"pull_number":"4521"', '"pull_number":"4522"').replace(specobj["parameters"]["args_hash"], sha256_hex(args_t.encode()))
    s2 = {"spec_digest": sha256_hex(s_t.encode()), "representation": {"kind": "original_bytes", "media_type": "application/json"},
          "content": {"availability": "available", "bytes_b64": base64.b64encode(s_t.encode()).decode()},
          "summary": copy.deepcopy(at["action_specifications"][0]["summary"])}
    a1 = copy.deepcopy(at); a1["action_specifications"].append(s2)
    for s in a1["stages"]:
        if s["stage_id"] in ("q1", "x1"): s["spec_digest"] = s2["spec_digest"]
    choices["N1"] = ["the executed specification is the base specification's bytes with pull_number \"4522\" and args_hash recomputed as the SHA-256 of arguments.canonical.json with \"4522\" (%s)" % s2["spec_digest"],
                     "added as action_specifications[1], with the base summary", "q1 and x1 name it; the action record is not changed, since no text of the two extensions reads it",
                     "attachment bytes: compact JSON, UTF-8"]
    neg["N1"] = ab_only(a1) + person_view(appr, tp, {a1["decision_id"]: a1})
    # N2
    a2 = copy.deepcopy(at)
    a2["stages"] += [
        {"stage_id": "q2", "kind": "request", "at": "2026-10-29T16:14:00Z", "request_id": "urn:aqta:action:n2-second", "authorised_by": "o1",
         "spec_digest": at["stages"][3]["spec_digest"], "requested_by": "urn:isoluce:service:release-assistant"},
        {"stage_id": "c2", "kind": "recheck", "at": "2026-10-29T16:14:10Z", "request_ref": "q2", "result": "authorised",
         "authority_source_ref": "urn:isoluce:policy:production_change_review#2026-10-01"},
        {"stage_id": "x2", "kind": "attempt", "at": "2026-10-29T16:14:15Z", "request_ref": "q2", "recheck_ref": "c2",
         "spec_digest": at["stages"][3]["spec_digest"], "executor_ref": "urn:aqta:enforcement-point:seal"},
        {"stage_id": "r2", "kind": "result", "at": "2026-10-29T16:14:30Z", "attempt_ref": "x2", "observed": "succeeded", "basis": "target_response"}]
    choices["N2"] = ["q2/c2/x2/r2 at 16:14:00, 16:14:10, 16:14:15, 16:14:30Z; request_id urn:aqta:action:n2-second; same requester, executor and specification as q1/x1; r2 succeeded, target_response"]
    neg["N2"] = ab_only(a2) + person_view(appr, tp, {a2["decision_id"]: a2})
    # N3, N3b
    seed_text = "dps-reading-1b test key someone-else-key-1"
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_text.encode()).digest())
    pk_hex = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    a3 = copy.deepcopy(appr); a3["signature"]["key_ref"] = "someone-else-key-1"
    a3["signature"]["value_b64"] = base64.b64encode(sk.sign(sig_check.person_signed_bytes(a3))).decode()
    choices["N3"] = ["key: Ed25519, seed SHA-256(%r) (this reading's own test key), public key %s" % (seed_text, pk_hex),
                     "the assertion is the base approval with key_ref someone-else-key-1, re-signed over the bytes built with that key_ref; signed_at unchanged"]
    neg["N3"] = ab_only(at, beside={"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [a3]}) + person_view(a3, tp, {at["decision_id"]: at})
    tp3 = copy.deepcopy(tp)
    tp3["keys"].append({"key_ref": "someone-else-key-1", "holder": "Someone else (test only)", "role": "organisation", "algorithm": "Ed25519",
                        "public_key_hex": pk_hex, "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-08-31T23:59:59Z"})
    choices["N3b"] = ["the N3 signature; the policy adds someone-else-key-1, holder \"Someone else (test only)\", role organisation, Ed25519, valid 2026-09-01 to 2027-08-31, no identity source"]
    r3b = person_view(a3, tp3, {at["decision_id"]: at})
    neg["N3b"] = ab_only(at, beside={"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [a3]}) + r3b
    # N4, N5: the issuer's policy document
    import re
    pol4, nsub = re.subn(r'("max_approval_age_seconds"\s*:\s*)900\b', r'\g<1>86400', pol_b.decode("utf-8"))
    assert nsub == 1 and pol4.encode() != pol_b
    choices["N4"] = ["policy.json with max_approval_age_seconds 86400 in place of 900, nothing else changed (digest %s)" % sha256_hex(pol4.encode()),
                     "no text of the two extensions defines a check that reads the issuer's policy document: the dimensions are those of the base; the digest comparison is given as a fact outside the texts"]
    neg["N4"] = ab_only(at) + person_view(appr, tp, {at["decision_id"]: at}) + (
        {"policy held hashes to policy_version (outside the texts)": "sha256:" + sha256_hex(pol4.encode()) == specobj["policy_version"]},)
    choices["N5"] = ["no policy document held; nothing else changed", "as N4: no dimension of the texts reads it"]
    neg["N5"] = ab_only(at) + person_view(appr, tp, {at["decision_id"]: at}) + ({"policy held": "none"},)
    # N6
    a6 = copy.deepcopy(at)
    for s in a6["stages"]:
        if s["stage_id"] == "c1": s["at"] = "2026-10-29T16:39:50Z"
        if s["stage_id"] == "x1": s["at"] = "2026-10-29T16:40:00Z"
        if s["stage_id"] == "r1": s["at"] = "2026-10-29T16:40:17Z"
    o_t = instant("2026-10-29T16:12:00Z")[0]; x_t = instant("2026-10-29T16:40:00Z")[0]
    choices["N6"] = ["recheck c1 at 16:39:50Z (result authorised), attempt x1 at 16:40:00Z (28 minutes after o1 at 16:12:00Z), result r1 at 16:40:17Z; request q1 unchanged at 16:12:30Z",
                     "no text of the two extensions compares an attempt's time with a specification's valid_until or with an issuer policy's maximum age"]
    neg["N6"] = ab_only(a6) + person_view(appr, tp, {a6["decision_id"]: a6}) + (
        {"attempt after valid_until (outside the texts)": x_t > instant(specobj["valid_until"])[0], "seconds from o1 to x1": int(x_t - o_t)},)
    # N7
    other = "sha256:" + sha256_hex(pol4.encode())
    s7 = spec_b.decode("utf-8").replace(specobj["policy_version"], other).encode()
    d7 = sha256_hex(s7)
    a7 = copy.deepcopy(at)
    sp = a7["action_specifications"][0]
    old = sp["spec_digest"]
    sp["spec_digest"], sp["content"]["bytes_b64"], sp["summary"]["policy_version"] = d7, base64.b64encode(s7).decode(), other
    for s in a7["stages"]:
        for k in ("spec_digest", "shown_spec_digest", "approved_spec_digest"):
            if s.get(k) == old: s[k] = d7
    choices["N7"] = ["the specification's bytes rewritten with policy_version %s (the N4 policy's digest); spec_digest, summary and every stage digest that named the old specification rewritten to %s" % (other, d7),
                     "the person's approval unchanged (it names the old digest); the decision record unchanged"]
    neg["N7"] = ab_only(a7) + person_view(appr, tp, {a7["decision_id"]: a7})
    # N7b
    a7b = copy.deepcopy(at)
    a7b["stages"][o_idx]["authority"]["authority_ref"] = "urn:isoluce:policy:production_change_review_relabelled#2026-10-01"
    choices["N7b"] = ["o1.authority.authority_ref set to urn:isoluce:policy:production_change_review_relabelled#2026-10-01; nothing else changed"]
    neg["N7b"] = ab_only(a7b) + person_view(appr, tp, {a7b["decision_id"]: a7b})
    out["negatives"] = {k: {"action_binding": v[0], "action_binding_findings": v[1], "person_approval": v[2],
                            "person_approval_findings": v[3], **({"facts_outside_the_texts": v[4]} if len(v) > 4 else {}),
                            "values_chosen": choices[k]} for k, v in neg.items()}
    with open(outpath, "w") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False, default=str)
    return out


if __name__ == "__main__":
    o = main(sys.argv[1])
    def line(name, ab, pa):
        keys = ["specification_digests", "specification_statements", "record_statements", "action_binding", "stage_order",
                "authorisation_recheck", "observed_results", "rationale_provenance", "issuer_signature", "time_assurance"]
        s = " ".join("%s=%s" % (k[:14], ab[k] if not isinstance(ab[k], list) else ",".join(ab[k])) for k in keys)
        s += " executed=%s" % ab["executed"]
        if pa:
            s += " || PA: " + " ".join("%s=%s" % (k, pa[k]) for k in ("status", "signature", "subject", "key_state", "identity"))
        return name + ": " + s
    print(json.dumps(o["release-decision"]["schema_errors"]), json.dumps(o["aqta"]["schema_errors"]))
    print(line("release-decision", o["release-decision"]["action_binding"], None))
    print(line("aqta", o["aqta"]["action_binding"], o["aqta"]["person_approval"]))
    print(json.dumps(o["aqta"]["facts_outside_the_texts"]))
    for k, n in o["negatives"].items():
        print(line(k, n["action_binding"], n["person_approval"]))
        if "facts_outside_the_texts" in n: print("   ", n["facts_outside_the_texts"])
