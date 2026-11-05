"""DPS reading 2b: Appendix D.6's vectors and D.3's positive result, run through this run's VERIFY-ANCHOR on top of
reading 2's parser and replay.

Usage: python run_2b.py READING2_DIR INPUTS_DIR OUT_DIR
  READING2_DIR  the unzipped dps-reading-2/ (its verifier/ is imported by path, unchanged)
  INPUTS_DIR    what dps-reading-2/inputs/dps-reading-2-fetch-inputs.sh fetched, with the draft placed at
                ietf/draft-fassbender-scitt-time-anchor-08.txt
  OUT_DIR       where the results are written
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_anchor as VA  # noqa: E402
from chain import FileHeaderSource, HeaderSet  # noqa: E402

FIXTURE_NOTE = ("declared validated for the test, not validated by this run")


def decisive_step(o):
    """The step that decided the outcome: the RETURN's step, except that an unverifiable RETURN at step 8 is
    decided by the step that left the branch unevaluated (7b or 5), as D.6 states it ("step 7b returns NULL, so
    step 8 leaves the branch unevaluated")."""
    if o.verdict == "unverifiable" and o.return_step == "8":
        return "7b" if "step 7b" in o.cause and "step 5" not in o.cause else ("5" if "step 5" in o.cause else "7b+5")
    return o.return_step


def main():
    r2dir, inputs, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    O, R2 = VA.load_reading2(r2dir)
    t_start = time.time()
    timing = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start))}

    base = os.path.join(inputs, "lemonnier", "interop", "umarise")
    draft = os.path.join(inputs, "ietf", "draft-fassbender-scitt-time-anchor-08.txt")
    headers_json = json.load(open(os.path.join(base, "headers-957289-957300.json")))
    draft_txt = open(draft, encoding="utf-8").read()
    d5 = R2.d5_from_draft(draft)
    art, proof = {}, {}
    checks = {"constants_not_found_in_draft": R2.constants_in_draft(draft)}
    for n in (1, 2, 3, 4):
        art[n] = open(os.path.join(base, "vectors", "vector%d.txt" % n), "rb").read()
        proof[n] = open(os.path.join(base, "vectors", "vector%d.ots" % n), "rb").read()
        s = 'artifact: "draft-fassbender-scitt-time-anchor-03 vector %d"' % n
        checks["vector%d" % n] = {
            "txt_equals_d1_string": s in draft_txt and art[n] == s.split('"')[1].encode("ascii"),
            "txt_sha256_equals_d1_hash": hashlib.sha256(art[n]).hexdigest() == R2.D1[n][0],
            "ots_equals_d5_base64": d5.get(n) == proof[n],
            "txt_bytes": len(art[n]), "ots_bytes": len(proof[n])}
    json.dump(checks, open(os.path.join(outdir, "inputs_check.json"), "w"), indent=1)

    src = FileHeaderSource(headers_json, "Lemonnier's headers-957289-957300.json (data supplied with the proofs)")
    allh = {int(k): bytes.fromhex(v["header"]) for k, v in headers_json.items()}

    def fixture(lo, hi, name, mode="held"):
        hs = {h: b for h, b in allh.items() if lo <= h <= hi}
        return HeaderSet(hs, "%s: headers %d-%d of Lemonnier's file (%d), %s" % (name, lo, hi, len(hs), FIXTURE_NOTE)
                         if hs else "%s: an empty header set, %s" % (name, FIXTURE_NOTE), R2, mode)

    fixtures = {
        "fixture-12": lambda: fixture(957289, 957300, "fixture-12"),
        "fixture-11": lambda: fixture(957290, 957300, "fixture-11"),
        "fixture-11-alt": lambda: fixture(957290, 957300, "fixture-11 under reading B07(b)", "held-or-committed"),
        "fixture-5": lambda: fixture(957289, 957293, "fixture-5"),
        "fixture-6": lambda: fixture(957289, 957294, "fixture-6"),
        "fixture-0": lambda: fixture(1, 0, "fixture-0"),
        "none": lambda: None,
    }
    json.dump({k: (f().describe() if f() is not None else "none: the verifier holds no validated view")
               for k, f in fixtures.items()}, open(os.path.join(outdir, "fixtures.json"), "w"), indent=1)

    bundle_p = {n: VA.make_bundle(proof[n], "sha256:" + R2.D1[n][0]) for n in (1, 2, 3, 4)}
    bundle_b = {n: VA.make_bundle(proof[n], R2.D1[n][0]) for n in (1, 2, 3, 4)}
    json.dump({"vector%d" % n: {"prefixed": {"claimed_hash": "sha256:" + R2.D1[n][0],
                                             "cbor_sha256": hashlib.sha256(bundle_p[n]).hexdigest(),
                                             "cbor_bytes": len(bundle_p[n])},
                                "bare": {"claimed_hash": R2.D1[n][0],
                                         "cbor_sha256": hashlib.sha256(bundle_b[n]).hexdigest(),
                                         "cbor_bytes": len(bundle_b[n])}} for n in (1, 2, 3, 4)},
              open(os.path.join(outdir, "bundles.json"), "w"), indent=1)

    # ------------------------------------------------------------ small groups, full traces
    small = []

    def run_small(rid, group, n, artifact, bundle, chain_key, expected, note=None):
        ch = fixtures[chain_key]()
        try:
            o = VA.verify_anchor(artifact, bundle, ch, src)
            rec = {"id": rid, "group": group, "vector": n, "validated_chain": "none" if ch is None else ch.label,
                   "claimed_hash": VA.read_bundle(bundle)["claimed_hash"],
                   "expected": expected, "verdict": o.verdict, "return_step": o.return_step,
                   "decided_by_step": decisive_step(o), "cause": o.cause,
                   "agrees": o.verdict == expected["verdict"] and decisive_step(o) == expected["step"],
                   "trace": o.trace}
        except VA.BundleError as e:
            rec = {"id": rid, "group": group, "vector": n, "verdict": "not attempted",
                   "why": "proof_bundle does not match Section 3.4.3: %s" % e, "expected": expected, "agrees": False}
        if note:
            rec["note"] = note
        small.append(rec)

    t0 = time.time()
    for n in (1, 2, 3, 4):
        run_small("P1-v%d" % n, "P1 positive, no validated_chain", n, art[n], bundle_p[n], "none",
                  {"verdict": "unverifiable", "step": "7b", "from": "prompt task 3; D.3; D.6 second vector"})
    for n in (1, 2, 3, 4):
        run_small("P2-v%d" % n, "P2 positive, fixture-12 as validated_chain", n, art[n], bundle_p[n], "fixture-12",
                  {"verdict": "valid", "step": "11", "from": "D.3: valid for a verifier that has placed block 957289 "
                                                              "on the validated most-work chain"},
                  note="the header set was declared validated for the test and was not validated by this run")
    for n in (1, 2, 3, 4):
        run_small("N2-v%d" % n, "N2 D.6 second vector, unmodified pair, no validated_chain", n, art[n], bundle_p[n],
                  "none", {"verdict": "unverifiable", "step": "7b", "from": "D.6 second vector"})
    for n in (1, 2, 3, 4):
        run_small("N2b-v%d" % n, "N2b D.6 second vector, unmodified pair, fixture-11 (957290-957300)", n, art[n],
                  bundle_p[n], "fixture-11",
                  {"verdict": "unverifiable", "step": "7b", "from": "D.6 second vector, if 'does not reach the "
                                                                   "attested height' covers this set (B07)"},
                  note="the header set was declared validated for the test and was not validated by this run")
    # additional, reported apart
    for n in (1, 2, 3, 4):
        run_small("A1-v%d" % n, "A1 additional: fixture-11 under reading B07(b) (header at H established through "
                  "957290's previous-block hash)", n, art[n], bundle_p[n], "fixture-11-alt",
                  {"verdict": "unverifiable", "step": "7b", "from": "D.6 second vector, as N2b"},
                  note="computed only to report the other reading of B07; the header set was declared validated for "
                       "the test and was not validated by this run")
    for n in (1, 2, 3, 4):
        run_small("A2-v%d" % n, "A2 additional: claimed_hash without the sha256: prefix, no validated_chain", n,
                  art[n], bundle_b[n], "none", {"verdict": "unverifiable", "step": "7b", "from": "as P1"})
    for n in (1, 2, 3, 4):
        run_small("A3-v%d" % n, "A3 additional: claimed_hash without the sha256: prefix, fixture-12", n, art[n],
                  bundle_b[n], "fixture-12", {"verdict": "valid", "step": "11", "from": "as P2"},
                  note="the header set was declared validated for the test and was not validated by this run")
    for n in (1, 2, 3, 4):
        run_small("A4-v%d" % n, "A4 additional: an empty validated header set (a view, holding nothing)", n, art[n],
                  bundle_p[n], "fixture-0", {"verdict": "unverifiable", "step": "7b",
                                             "from": "D.6 second vector, 'a validated header set that does not reach "
                                                     "the attested height'"},
                  note="the (empty) set was declared validated for the test")
    for n in (1, 2, 3, 4):
        run_small("A5-v%d" % n, "A5 additional: fixture-5 (957289-957293), five blocks at H and above", n, art[n],
                  bundle_p[n], "fixture-5", {"verdict": "unverifiable", "step": "9",
                                             "from": "Section 4.1 step 9 (k = 5 < MIN_CONFIRMATIONS 6)"},
                  note="the header set was declared validated for the test and was not validated by this run")
    for n in (1, 2, 3, 4):
        run_small("A6-v%d" % n, "A6 additional: fixture-6 (957289-957294), six blocks at H and above", n, art[n],
                  bundle_p[n], "fixture-6", {"verdict": "valid", "step": "11", "from": "Section 4.1 step 9 (k = 6)"},
                  note="the header set was declared validated for the test and was not validated by this run")
    timing["small_groups_seconds"] = round(time.time() - t0, 3)
    json.dump(small, open(os.path.join(outdir, "runs_small.json"), "w"), indent=1)

    # ------------------------------------------------------------ D.6 first vector: every single-byte substitution
    def mutation_group(gen, bundle_for, chain_key, expected, full_exceptions=True):
        """full_exceptions=False (change C01, A7 only): an exception is listed as its row, and the full outcome is
        kept for the first exception of each artifact only."""
        out = {}
        for n in (1, 2, 3, 4):
            ch = fixtures[chain_key]()
            rows, exceptions = [], []
            counts = {}
            for key, mutated in gen(art[n]):
                try:
                    o = VA.verify_anchor(mutated, bundle_for(n, mutated), ch, src)
                    v, st = o.verdict, decisive_step(o)
                except VA.BundleError as e:
                    o, v, st = None, "not attempted", "bundle: %s" % e
                rows.append(list(key) + [v, st])
                counts["%s at step %s" % (v, st)] = counts.get("%s at step %s" % (v, st), 0) + 1
                if not (v == expected["verdict"] and st == expected["step"]):
                    if full_exceptions or not exceptions:
                        exceptions.append({"mutation": list(key), "artifact_hex": mutated.hex(), "verdict": v,
                                           "decided_by_step": st, "outcome": o.as_dict() if o else None})
                    else:
                        exceptions.append(list(key) + [v, st])
            out["vector%d" % n] = {"runs": len(rows), "counts": counts,
                                   "as_expected": sum(1 for r in rows if r[-2] == expected["verdict"]
                                                      and r[-1] == expected["step"]),
                                   "exceptions": exceptions, "rows": rows}
        return out

    def substitutions(a):
        for i in range(len(a)):
            for v in range(256):
                if v != a[i]:
                    yield (i, a[i], v), a[:i] + bytes([v]) + a[i + 1:]

    def insertions(a):
        for i in range(len(a) + 1):
            for v in range(256):
                yield ("insert", i, v), a[:i] + bytes([v]) + a[i:]

    def deletions(a):
        for i in range(len(a)):
            yield ("delete", i, a[i]), a[:i] + a[i + 1:]

    exp2 = {"verdict": "invalid", "step": "2", "from": "D.6 first vector"}
    t0 = time.time()
    n1 = mutation_group(substitutions, lambda n, m: bundle_p[n], "fixture-12", exp2)
    timing["d6_substitution_seconds"] = round(time.time() - t0, 3)
    json.dump({"about": "D.6 first vector. Each single-byte substitution of each artifact, with the original proof and "
                        "the original bundle (claimed_hash = 'sha256:' + D.1 hash). validated_chain: fixture-12, "
                        "declared validated for the test, not validated by this run (B04). Row: position, original "
                        "byte, substituted byte, verdict, deciding step.", "expected": exp2, "results": n1},
              open(os.path.join(outdir, "d6_substitution.json"), "w"))
    t0 = time.time()
    n1o = {"insert": mutation_group(insertions, lambda n, m: bundle_p[n], "fixture-12", exp2),
           "delete": mutation_group(deletions, lambda n, m: bundle_p[n], "fixture-12", exp2)}
    timing["d6_insert_delete_seconds"] = round(time.time() - t0, 3)
    json.dump({"about": "Optional, reported apart from D.6: one byte inserted (each position 0..len, each of 256 "
                        "values) and one byte deleted (each position), with the original proof and bundle; "
                        "fixture-12 as above. Row: kind, position, byte, verdict, deciding step.",
               "expected": exp2, "results": n1o},
              open(os.path.join(outdir, "d6_insert_delete.json"), "w"))
    t0 = time.time()
    a7 = mutation_group(substitutions,
                        lambda n, m: VA.make_bundle(proof[n], "sha256:" + hashlib.sha256(m).hexdigest()),
                        "fixture-12", exp2, full_exceptions=False)
    timing["a7_substitution_claimed_from_presented_seconds"] = round(time.time() - t0, 3)
    json.dump({"about": "A7 additional, reported apart: the same substitutions, with a bundle whose claimed_hash is "
                        "computed from the presented (modified) bytes, as a harness or holder that builds the bundle "
                        "from the artifact it holds would (B03). The expectation shown is D.6's (invalid, step 2). "
                        "fixture-12, declared validated for the test, not validated by this run. Exceptions to D.6's "
                        "step are listed as rows; the full outcome is kept for the first of each artifact (C01).",
               "expected": exp2, "results": a7},
              open(os.path.join(outdir, "a7_substitution_claimed_from_presented.json"), "w"))

    timing["ended_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    timing["total_seconds"] = round(time.time() - t_start, 3)
    json.dump(timing, open(os.path.join(outdir, "timing.json"), "w"), indent=1)
    print(json.dumps({"small": {r["id"]: [r["verdict"], r.get("decided_by_step"), r["agrees"]] for r in small},
                      "d6_substitution": {k: [v["runs"], v["counts"]] for k, v in n1.items()},
                      "d6_insert": {k: [v["runs"], v["counts"]] for k, v in n1o["insert"].items()},
                      "d6_delete": {k: [v["runs"], v["counts"]] for k, v in n1o["delete"].items()},
                      "a7": {k: [v["runs"], v["counts"]] for k, v in a7.items()},
                      "timing": timing}, indent=1))


if __name__ == "__main__":
    main()
