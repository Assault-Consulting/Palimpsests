"""Writes out/report.json from out/first-run and out/final: one boolean or "not attempted" per
case, with totals. Three signatures vector cases whose computation did not match what the case
describes are reported as not attempted, with the reason (out/changes.md, entry 22)."""
import glob, json, os, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "out"
PARTIAL = {
    "signatures-vector": {
        "V03": "only the records' stated seals were compared with the published values; the SHA-256 over the record bytes was not computed in this case",
        "V25": "computed with the base attachment's copy against each seal, not on the attachments as their issuer wrote them",
        "V26": "computed on a 0.2.0 attachment rebuilt from the base attachment, not on the one action binding 0.2.0 wrote",
    }
}


def classify(suite, x):
    if x["id"] in PARTIAL.get(suite, {}):
        return "not attempted", PARTIAL[suite][x["id"]]
    if x["agrees"] == "not attempted":
        return "not attempted", x.get("note")
    return bool(x["agrees"]), None


def counts(suite, lst):
    c = {"cases": len(lst), "agree": 0, "differ": 0, "not_attempted": 0}
    for x in lst:
        v, _ = classify(suite, x)
        c["agree" if v is True else "differ" if v is False else "not_attempted"] += 1
    return c


rep = {"about": "Per case: true (this reading's check agrees with the case's expected outcome), false (differs), "
                "or \"not attempted\" with the reason. first_run: the first complete run of each suite; final: after "
                "the changes in out/changes.md.", "suites": {}, "totals": {}}
tot = {"first_run": {"cases": 0, "agree": 0, "differ": 0, "not_attempted": 0},
       "final": {"cases": 0, "agree": 0, "differ": 0, "not_attempted": 0}}
for f in sorted(glob.glob(os.path.join(OUT, "final", "*.json"))):
    s = os.path.basename(f)[:-5]
    if s == "second-input":
        continue
    fin = json.load(open(f))
    fr = json.load(open(os.path.join(OUT, "first-run", s + ".json")))
    cases = {}
    for x in fin:
        v, why = classify(s, x)
        cases[x["id"]] = v if why is None else {"result": v, "reason": why}
    rep["suites"][s] = {"first_run": counts(s, fr), "final": counts(s, fin), "cases": cases}
    for k in tot["final"]:
        tot["final"][k] += rep["suites"][s]["final"][k]
        tot["first_run"][k] += rep["suites"][s]["first_run"][k]
rep["totals"] = tot
json.dump(rep, open(os.path.join(OUT, "report.json"), "w"), indent=1, ensure_ascii=False)
print(json.dumps(tot))
