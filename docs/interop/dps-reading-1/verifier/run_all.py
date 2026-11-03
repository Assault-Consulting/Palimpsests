"""Runs every check of this reading and writes out/report.json."""
import json, sys, os
sys.setrecursionlimit(20000)
from common import Recorder, ROOT
import run_ab_binding, run_ab_sig, run_sig, run_sig_vectors, run_schema, run_pairing

rec = Recorder()
run_ab_binding.run_digest(rec); run_ab_binding.run_binding(rec)
run_ab_sig.run_signature(rec); run_ab_sig.run_vectors(rec)
run_schema.run_ab(rec); run_schema.run_sig(rec)
run_pairing.run_ab(rec); run_pairing.run_sig(rec)
run_sig.run_person(rec); run_sig.run_seal(rec); run_sig.run_timestamp(rec)
run_sig_vectors.run(rec)

second = json.load(open(os.path.join(ROOT, "out", "second-input-verdicts.json")))
def add2(cid, d, expected_from_summary=None):
    rec.rows.append({"suite": "second-input", "id": cid, "result": d})
rel = second["release_decision"]["dimensions"]
for k in ("structural_validity", "record_statements", "action_binding", "stage_order", "authorisation_recheck", "observed_results",
          "rationale_provenance", "identity_assurance", "authority_assurance", "time_assurance", "issuer_signature", "legal_signature"):
    rec.rows.append({"suite": "second-input/release-decision", "id": k, "result": rel[k]})
rec.rows.append({"suite": "second-input/release-decision", "id": "specification_digests", "result": rel["specification_digests"][0]})
rec.rows.append({"suite": "second-input/release-decision", "id": "specification_statements", "result": rel["specification_statements"][0]})
aq = second["aqta"]["base"]
for k, v in aq["action_binding"].items():
    if k in ("observed", "executed", "reviews", "findings", "execution_state"):
        continue
    rec.rows.append({"suite": "second-input/aqta", "id": "action_binding." + k, "result": v[0] if isinstance(v, list) else v})
for k in ("status", "signature", "subject", "key_state", "identity"):
    rec.rows.append({"suite": "second-input/aqta", "id": "person_approval." + k, "result": aq["person_approvals"][0][k]})
for n, v in second["aqta"]["negatives_rebuilt"].items():
    if "action_binding" not in v:
        rec.rows.append({"suite": "second-input/aqta-negatives-rebuilt", "id": n, "result": "same as base: " + v["note"]})
        continue
    ab = v["action_binding"]; p = v["person_approvals"][0]
    rec.rows.append({"suite": "second-input/aqta-negatives-rebuilt", "id": n,
                     "result": {"action_binding_dimensions_not_verified": [d for d in ("record_statements", "action_binding", "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance") if ab[d] != "verified"],
                                "executed": ab["executed"], "person_approval": {x: p[x] for x in ("status", "signature", "subject", "key_state", "identity")}}})
for x in ("seal_action_record", "policy_checks", "composition_args_hash_bound"):
    rec.rows.append({"suite": "second-input/aqta", "id": x, "result": "not attempted", "why": "outside both extensions"})

totals = {}
for r in rec.rows:
    if not r["suite"].startswith(("action-binding", "signatures")):
        continue
    t = totals.setdefault(r["suite"], {"cases": 0, "as_expected": 0, "not_as_expected": 0, "not_attempted": 0})
    t["cases"] += 1
    if r["result"] is True: t["as_expected"] += 1
    elif r["result"] is False: t["not_as_expected"] += 1
    else: t["not_attempted"] += 1
grand = {k: sum(t[k] for t in totals.values()) for k in ("cases", "as_expected", "not_as_expected", "not_attempted")}
out = {"reading": "dps-reading-1", "standard_commit": "c9043722384f784ae578ae0a64400be8a3864259",
       "lemonnier_commit": "fdc5f6352795fc713309cd25ac2669d22840e0cc",
       "meaning": "for suites of cases: true = the case behaved as its expected value says; false = it did not; 'not attempted' with why. For second-input rows: the dimension's status as this reading computed it.",
       "totals_by_suite": totals, "totals": grand, "checks": rec.rows}
with open(os.path.join(ROOT, "out", "report.json"), "w") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
print(json.dumps(totals, indent=1)); print(grand)
for r in rec.rows:
    if r["result"] is False: print("NOT AS EXPECTED", r["suite"], r["id"], json.dumps(r.get("detail"))[:300])
