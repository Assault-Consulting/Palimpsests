"""Builds OUT/report.json from OUT/final: one verdict (or not attempted) per run of VERIFY-ANCHOR, with totals.
Usage: python make_report.py OUT_DIR"""
import json
import os
import sys

FIX = "declared validated for the test, not validated by this run"


def main():
    out = sys.argv[1]
    fin = os.path.join(out, "final")
    small = json.load(open(os.path.join(fin, "runs_small.json")))
    sub = json.load(open(os.path.join(fin, "d6_substitution.json")))
    insdel = json.load(open(os.path.join(fin, "d6_insert_delete.json")))
    a7 = json.load(open(os.path.join(fin, "a7_substitution_claimed_from_presented.json")))
    pins = json.load(open(os.path.join(out, "pins.json")))

    groups = {}
    for r in small:
        g = r["group"]
        e = groups.setdefault(g, {"runs": 0, "outcomes": {}, "agree_with_expected": 0, "expected": r["expected"]})
        e["runs"] += 1
        k = "%s at step %s" % (r["verdict"], r.get("decided_by_step"))
        e["outcomes"][k] = e["outcomes"].get(k, 0) + 1
        e["agree_with_expected"] += 1 if r["agrees"] else 0

    def big(name, res, expected, about):
        tot = {"runs": 0, "outcomes": {}, "agree_with_expected": 0, "expected": expected, "about": about,
               "per_artifact": {}}
        for v, x in res.items():
            tot["runs"] += x["runs"]
            tot["agree_with_expected"] += x["as_expected"]
            for k, c in x["counts"].items():
                tot["outcomes"][k] = tot["outcomes"].get(k, 0) + c
            tot["per_artifact"][v] = {"runs": x["runs"], "counts": x["counts"], "as_expected": x["as_expected"],
                                      "exceptions": len(x["exceptions"])}
        groups[name] = tot

    big("N1 D.6 first vector: single-byte substitutions", sub["results"], sub["expected"],
        "original proof and bundle; validated_chain fixture-12, " + FIX)
    big("N1o optional: one byte inserted", insdel["results"]["insert"], insdel["expected"],
        "reported apart; original proof and bundle; fixture-12, " + FIX)
    big("N1o optional: one byte deleted", insdel["results"]["delete"], insdel["expected"],
        "reported apart; original proof and bundle; fixture-12, " + FIX)
    big("A7 additional: substitutions, claimed_hash from the presented bytes", a7["results"], a7["expected"],
        "reported apart; expectation shown is D.6's; fixture-12, " + FIX)

    rep = {
        "about": "DPS reading 2b. One entry per run of VERIFY-ANCHOR (draft-fassbender-scitt-time-anchor-08, Section "
                 "4.1) as implemented on top of reading 2's parser and replay. Carried out by Andrii Sparysh using an "
                 "AI assistant.",
        "pins": {"dps-reading-2.zip": pins["inputs_from_the_human"]["dps-reading-2.zip"]["sha256"],
                 "draft-fassbender-scitt-time-anchor-08.txt":
                     pins["inputs_from_the_human"]["draft-fassbender-scitt-time-anchor-08.txt"]["sha256"],
                 "dps-reading-2b-PROMPT.md": pins["inputs_from_the_human"]["dps-reading-2b-PROMPT.md"]["sha256"],
                 "reading_2_replay_reproduced_byte_for_byte": pins["reading_2_replay_rerun"]["byte_identical"]},
        "fixture_note": "Every result with fixture-12, fixture-11, fixture-6, fixture-5 or fixture-0 as validated_chain "
                        "rests on a header set " + FIX + ". This run holds no validated chain.",
        "decided_by_step": "the step whose RETURN produced the verdict, except that an unverifiable RETURN at step 8 is "
                           "attributed to the step that left the branch unevaluated (7b here), as D.6 states it; "
                           "return_step keeps the RETURN's own step (ambiguity log B06)",
        "totals": groups,
        "grand_total_runs": sum(g["runs"] for g in groups.values()),
        "not_attempted": {
            "runs": "none: every run returned a verdict",
            "within_runs": [
                "step 10, Median Time Past (OPTIONAL): not attempted in every valid run; the eleven headers before "
                "957289 are not held",
                "no run validated a header chain: steps 7b and 9 read a fixture declared validated, or no view",
                "the header bytes were not cross-checked with a block explorer or a node (no network to either)"]},
        "runs": {
            "small_groups": [{"id": r["id"], "group": r["group"], "verdict": r["verdict"],
                              "return_step": r.get("return_step"), "decided_by_step": r.get("decided_by_step"),
                              "expected": [r["expected"]["verdict"], r["expected"]["step"]], "agrees": r["agrees"],
                              "validated_chain": r.get("validated_chain")} for r in small],
            "row_legend": {"substitution": ["position", "original byte", "substituted byte", "verdict",
                                            "decided_by_step"],
                           "insert/delete": ["kind", "position", "byte", "verdict", "decided_by_step"]},
            "N1_d6_substitution": {v: x["rows"] for v, x in sub["results"].items()},
            "N1o_insert": {v: x["rows"] for v, x in insdel["results"]["insert"].items()},
            "N1o_delete": {v: x["rows"] for v, x in insdel["results"]["delete"].items()},
            "A7_substitution_claimed_from_presented": {v: x["rows"] for v, x in a7["results"].items()},
        },
    }
    with open(os.path.join(out, "report.json"), "w") as f:
        json.dump(rep, f, separators=(",", ":"))
    print(json.dumps({"grand_total_runs": rep["grand_total_runs"],
                      "totals": {k: {kk: vv for kk, vv in v.items() if kk not in ("per_artifact",)}
                                 for k, v in groups.items()}}, indent=1))


if __name__ == "__main__":
    main()
