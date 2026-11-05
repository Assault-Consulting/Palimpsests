"""Runs every case of extensions/anchoring/tests/cases.json against this reading's own check, and records the result
of each case beside its expectation. Usage: python run_suites.py INPUTS_DIR OUT_DIR"""
import base64
import copy
import hashlib
import json
import os
import sys
import traceback

import jsonschema
from referencing import Registry, Resource

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dpsr import checkpoint as C, policy as P, report as R, timestamp as TS  # noqa: E402
from dpsr.common import doc_bytes, sha256_hex, strict_loads  # noqa: E402
import vector_checks  # noqa: E402

CHAIN = "urn:example:chain:issuer-1"


def ptr_get(doc, ptr):
    if ptr == "":
        return doc
    cur = doc
    for tok in ptr.lstrip("/").split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(tok)]
        else:
            cur = cur[tok]
    return cur


def _parent(doc, ptr):
    toks = [t.replace("~1", "/").replace("~0", "~") for t in ptr.lstrip("/").split("/")]
    cur = doc
    for t in toks[:-1]:
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    return cur, toks[-1]


class Env:
    def __init__(self, inputs):
        base = os.path.join(inputs, "standard", "extensions")
        self.base = base
        with open(os.path.join(base, "anchoring", "tests", "vectors.json"), encoding="utf-8") as f:
            self.V = strict_loads(f.read())
        with open(os.path.join(base, "anchoring", "tests", "cases.json"), encoding="utf-8") as f:
            self.C = strict_loads(f.read())
        self.schemas = {}
        for name, path in (("attachment", "anchoring/schemas/anchoring-attachment.schema.json"),
                           ("checkpoint", "anchoring/schemas/checkpoint.schema.json"),
                           ("trust_policy", "anchoring/schemas/trust-policy.schema.json"),
                           ("report", "anchoring/schemas/verification-report.schema.json"),
                           ("pv_export", "portable-verification/schemas/verification-export.schema.json")):
            with open(os.path.join(base, path), encoding="utf-8") as f:
                self.schemas[name] = strict_loads(f.read())

    def validator(self, name, defname=None):
        s = self.schemas[name]
        if defname:
            reg = Registry().with_resource(s["$id"], Resource.from_contents(s))
            return jsonschema.Draft202012Validator({"$ref": s["$id"] + "#/$defs/" + defname}, registry=reg)
        return jsonschema.Draft202012Validator(s)

    def apply(self, doc, patch, built=None):
        doc = copy.deepcopy(doc)
        for op in patch:
            if "set" in op:
                ptr = op["set"]
                if "vector" in op:
                    val = copy.deepcopy(ptr_get(self.V, op["vector"]))
                elif "digest_of" in op:
                    val = sha256_hex(doc_bytes(built[op["digest_of"]]))
                else:
                    val = copy.deepcopy(op["value"])
                if ptr == "":
                    doc = val
                    continue
                par, k = _parent(doc, ptr)
                if isinstance(par, list):
                    par[int(k)] = val
                else:
                    par[k] = val
            elif "remove" in op:
                par, k = _parent(doc, op["remove"])
                if isinstance(par, list):
                    del par[int(k)]
                else:
                    del par[k]
            elif "insert" in op:
                val = copy.deepcopy(ptr_get(self.V, op["vector"])) if "vector" in op else copy.deepcopy(op["value"])
                par, k = _parent(doc, op["insert"])
                if isinstance(par, list):
                    par.insert(len(par) if k == "-" else int(k), val)
                else:
                    par[k] = val
            elif "copy" in op or "move" in op:
                src = op.get("copy", op.get("move"))
                val = copy.deepcopy(ptr_get(doc, src))
                if "move" in op:
                    par, k = _parent(doc, src)
                    if isinstance(par, list):
                        del par[int(k)]
                    else:
                        del par[k]
                par, k = _parent(doc, op["to"])
                if isinstance(par, list):
                    par.insert(int(k), val)
                else:
                    par[k] = val
            else:
                raise ValueError("unknown patch op %r" % op)
        return doc

    def resolve(self, spec):
        if isinstance(spec, str):
            return copy.deepcopy(ptr_get(self.V, spec))
        base = ptr_get(self.V, spec["from"])
        return self.apply(base, spec.get("patch", []))

    def headers(self, spec):
        if not spec:
            return None
        hs = self.V["opentimestamps"]["headers"][spec["set"]]
        only = spec.get("only")
        return {"source_ref": spec["source_ref"],
                "headers": {int(h): bytes.fromhex(x["header_hex"]) for h, x in hs.items() if only is None or int(h) in only}}

    def export(self, case):
        e = copy.deepcopy(self.V["exports"][case.get("export", "full")])
        return self.apply(e, case.get("export_patch", []))

    def policy(self, case):
        return self.apply(self.V["trust_policy"], case.get("policy_patch", []))

    def cp_item(self, spec, obtained_from, source_ref, export, attachment_index=None):
        if spec is None:
            return C_item(None, obtained_from, source_ref)
        if spec == "issuer_checkpoint":
            return R.item_from_carrier(copy.deepcopy(export["issuer_checkpoint"]), "same_export", source_ref)
        if isinstance(spec, str):
            cp = copy.deepcopy(self.V["checkpoints"][spec]["checkpoint"])
        else:
            cp = self.resolve(spec)
        return R.item_from_carrier(cp, obtained_from, source_ref, attachment_index)

    def st_item(self, spec, obtained_from, source_ref, attachment_index=None):
        if isinstance(spec, str):
            carrier = copy.deepcopy(self.V["scitt"]["statements"][spec]["carrier"])
        else:
            carrier = self.resolve(spec)
        return R.item_from_carrier(carrier, obtained_from, source_ref, attachment_index)


def C_item(c, o, s):
    return R.item_from_carrier(c, o, s)


# ---------------------------------------------------------------------------------------------------

def run_schema(env):
    out = []
    for case in env.C["schema_cases"]:
        doc = env.apply(ptr_get(env.V, case["base"]), case["patch"])
        errs = list(env.validator(case["schema"]).iter_errors(doc))
        got = "pass" if not errs else "fail"
        out.append({"id": case["id"], "expected": case["expected"], "got": got, "agree": got == case["expected"],
                    "detail": None if not errs else errs[0].message[:200]})
    return out


def _exp_ts(case, res):
    exp = case["expected"]
    is_ots = res.get("format") == "opentimestamps"
    names = ["proof", "subject_bytes", "operations", "attestation", "header"] if is_ots else \
        ["token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "signer_certificate", "tsa_state"]
    diffs = []
    want = exp.get("status", "verified")
    if res["status"] != want:
        diffs.append("status %s, expected %s" % (res["status"], want))
    for n in names:
        w = exp.get(n, "verified")
        if res["checks"][n] != w:
            diffs.append("%s %s, expected %s" % (n, res["checks"][n], w))
    w = exp.get("issuer_time", "not_checked" if is_ots else "verified")
    if res["issuer_time"]["status"] != w:
        diffs.append("issuer_time %s, expected %s" % (res["issuer_time"]["status"], w))
    for k in ("consistency",):
        if k in exp and res["issuer_time"].get(k) != exp[k]:
            diffs.append("%s %s, expected %s" % (k, res["issuer_time"].get(k), exp[k]))
    for k in ("existed_no_later_than", "gen_time", "miner_stated_time"):
        if k in exp and res.get(k) != exp[k]:
            diffs.append("%s %s, expected %s" % (k, res.get(k), exp[k]))
    for k in ("height", "hash_hex"):
        if k in exp and (res.get("block") or {}).get(k) != exp[k]:
            diffs.append("%s %s, expected %s" % (k, (res.get("block") or {}).get(k), exp[k]))
    if "finding" in exp and not any(exp["finding"] in f for f in res.get("findings", [])):
        diffs.append("no finding containing %r" % exp["finding"])
    return diffs


def run_timestamps(env):
    out = []
    for case in env.C["timestamp_cases"]:
        try:
            ts = env.resolve(case["timestamp"])
            export = env.export(case)
            pol = env.policy(case)
            held = []
            for h in case.get("held_checkpoints", []):
                held.append(copy.deepcopy(env.V["checkpoints"][h]["checkpoint"]) if isinstance(h, str) else env.resolve(h))
            ctx = R.make_ctx(pol, case.get("chain_id", CHAIN), export, held, env.headers(case.get("headers")))
            res = TS.check(ts, 0, ctx)
            diffs = _exp_ts(case, res)
            if case["expected"].get("result_schema_valid"):
                v = env.validator("report", "ots_timestamp_result" if res.get("format") else "timestamp_result")
                errs = list(v.iter_errors(R.strip_internal(res)))
                if errs:
                    diffs.append("result not valid against the report schema: " + errs[0].message[:150])
            out.append({"id": case["id"], "agree": not diffs, "detail": diffs or None,
                        "got": {"status": res["status"], "checks": res["checks"], "issuer_time": res["issuer_time"]["status"]}})
        except Exception as e:
            out.append({"id": case["id"], "agree": False, "detail": ["exception: %s" % traceback.format_exc(limit=3)]})
    return out


def _cp_items(env, case, export):
    items = []
    def mk(spec_holder):
        o = spec_holder["obtained_from"]
        s = spec_holder.get("source_ref")
        if "statement" in spec_holder:
            return env.st_item(spec_holder["statement"], o, s)
        return env.cp_item(spec_holder["checkpoint"], o, s, export)
    prim = mk(case)
    others = [mk(o) for o in case.get("others", [])]
    allitems = [prim] + others
    obtained = [it for it in allitems if it["obtained_from"] != "beside_export"]
    beside = [it for it in allitems if it["obtained_from"] == "beside_export"]
    for i, it in enumerate(beside):
        it["attachment_index"] = i
    ordered = obtained + beside
    return ordered, ordered.index(prim)


def _exp_cp(case, r):
    exp = case["expected"]
    diffs = []
    beside = r["obtained_from"] == "beside_export"
    scitt = r.get("format") == "scitt"
    dflt = {"status": "failed" if beside or r["obtained_from"] == "same_export" else "verified",
            "independence": "failed" if beside or r["obtained_from"] == "same_export" else "verified",
            "signature": "verified", "key_state": "verified",
            "comparison": "not_checked" if beside else "verified"}
    for k, w in dflt.items():
        w = exp.get(k, w)
        if r[k]["status"] if isinstance(r[k], dict) else r[k] != w:
            pass
        got = r[k]["status"] if isinstance(r[k], dict) else r[k]
        if got != w:
            diffs.append("%s %s, expected %s" % (k, got, w))
    if beside:
        w = exp.get("prefix", "verified")
        if r["prefix"]["status"] != w:
            diffs.append("prefix %s, expected %s" % (r["prefix"]["status"], w))
        if r.get("freshness") != "not_established":
            diffs.append("freshness not not_established")
        if "prefix_covered_count" in exp and r["prefix"].get("covered_count") != exp["prefix_covered_count"]:
            diffs.append("prefix covered_count %s" % r["prefix"].get("covered_count"))
        if "prefix_time_basis" in exp and r["prefix"].get("time_basis") != exp["prefix_time_basis"]:
            diffs.append("prefix time_basis %s" % r["prefix"].get("time_basis"))
    if scitt:
        w = exp.get("receipt", "verified")
        if r["receipt"]["status"] != w:
            diffs.append("receipt %s, expected %s" % (r["receipt"]["status"], w))
        for k in ("tree_size", "leaf_index", "service_key_ref"):
            if k in exp and r["receipt"].get(k) != exp[k]:
                diffs.append("%s %s, expected %s" % (k, r["receipt"].get(k), exp[k]))
        if "receipt_finding" in exp and not any(exp["receipt_finding"] in f for f in r["receipt"].get("findings", [])):
            diffs.append("no receipt finding containing %r" % exp["receipt_finding"])
        if r["log_consistency"]["status"] != "not_checked":
            diffs.append("log_consistency not not_checked")
    if r["key_state"]["status"] == "verified":
        w = exp.get("time_basis", "stated_time")
        if r["key_state"].get("time_basis") != w:
            diffs.append("time_basis %s, expected %s" % (r["key_state"].get("time_basis"), w))
    for k in ("covered_count", "not_covered_indexes"):
        if k in exp and r["comparison"].get(k) != exp[k]:
            diffs.append("%s %s, expected %s" % (k, r["comparison"].get(k), exp[k]))
    if "conflict" in exp:
        has = any(f.startswith("conflict:") for f in r.get("findings", []))
        if has != exp["conflict"]:
            diffs.append("conflict finding %s, expected %s" % (has, exp["conflict"]))
    if "finding" in exp:
        allf = []
        for d in r.values():
            if isinstance(d, dict):
                allf += d.get("findings", [])
        allf += r.get("findings", [])
        if not any(exp["finding"] in f for f in allf):
            diffs.append("no finding containing %r" % exp["finding"])
    return diffs


def run_checkpoints(env):
    out = []
    for case in env.C["checkpoint_cases"]:
        try:
            export = env.export(case)
            pol = env.policy(case)
            items, pi = _cp_items(env, case, export)
            held = [it["checkpoint"] for it in items if it.get("type") == "plain"]
            ctx = R.make_ctx(pol, case.get("chain_id", CHAIN), export, held, env.headers(case.get("headers")))
            tss = [env.resolve(p) for p in case.get("timestamps", [])]
            ctx["ts_results"] = [TS.check(t, i, ctx) for i, t in enumerate(tss)]
            res = [C.check(it, i, ctx) for i, it in enumerate(items)]
            C.conflicts(res)
            r = res[pi]
            diffs = _exp_cp(case, r)
            v = env.validator("report", "checkpoint_result")
            errs = list(v.iter_errors(R.strip_internal(r)))
            if errs:
                diffs.append("result not valid against the report schema: " + errs[0].message[:150])
            out.append({"id": case["id"], "agree": not diffs, "detail": diffs or None,
                        "got": {k: (r[k]["status"] if isinstance(r.get(k), dict) else r.get(k))
                                for k in ("status", "independence", "signature", "key_state", "comparison", "prefix", "receipt") if k in r}})
        except Exception:
            out.append({"id": case["id"], "agree": False, "detail": ["exception: %s" % traceback.format_exc(limit=4)]})
    return out


def run_pairing(env):
    out = []
    ctxb = env.V["base_context"]
    for case in env.C["pairing_cases"]:
        try:
            ename = case.get("export", ctxb["export"])
            export = env.apply(env.V["exports"][ename], case.get("export_patch", []))
            attachment = env.apply(env.V["base_attachment"], case.get("attachment_patch", []))
            pol = env.policy(case)
            cps = case.get("checkpoints", ctxb["checkpoints"])
            obtained = [env.cp_item(c["checkpoint"], c["obtained_from"], c.get("source_ref"), export) for c in cps]
            report = env.apply(env.V["base_report"], case.get("report_patch", []), {"attachment": attachment, "export": export})
            errs = list(env.validator("report").iter_errors(report))
            got, where = R.pair(report, attachment, export, pol, ctxb["chain_id"], obtained, env.headers(case.get("headers")))
            if errs:
                got, where = "inconsistent", "schema: " + errs[0].message[:150]
            out.append({"id": case["id"], "expected": case["expected"], "got": got, "agree": got == case["expected"],
                        "detail": where})
        except Exception:
            out.append({"id": case["id"], "agree": False, "detail": "exception: %s" % traceback.format_exc(limit=4)})
    return out


def main():
    inputs, outdir = sys.argv[1], sys.argv[2]
    env = Env(inputs)
    os.makedirs(outdir, exist_ok=True)
    results = {"schema_cases": run_schema(env), "vector_cases": vector_checks.run(env),
               "timestamp_cases": run_timestamps(env), "checkpoint_cases": run_checkpoints(env),
               "pairing_cases": run_pairing(env)}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "review.json"), encoding="utf-8") as f:
        review = json.load(f)
    for suite, cases in review.items():
        if suite == "about":
            continue
        for x in results[suite]:
            if x["id"] in cases and x["agree"] is True:
                x["agree"] = False
                x["verdict_matches"] = True
                x["review"] = cases[x["id"]]
    totals = {}
    for k, v in results.items():
        agree = sum(1 for x in v if x["agree"] is True)
        na = sum(1 for x in v if x["agree"] == "not attempted")
        totals[k] = {"cases": len(v), "agree": agree, "disagree": len(v) - agree - na, "not_attempted": na}
        with open(os.path.join(outdir, k + ".json"), "w", encoding="utf-8") as f:
            json.dump(v, f, indent=1, ensure_ascii=False)
    with open(os.path.join(outdir, "totals.json"), "w") as f:
        json.dump(totals, f, indent=1)
    print(json.dumps(totals, indent=1))


if __name__ == "__main__":
    main()
