"""Schema cases of both extensions, validated with jsonschema (Draft 2020-12), every document
read strictly first. A case whose schema is not among the reading's inputs is not attempted."""
import json, hashlib
import jsonschema
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from common import *
from strictjson import loads, dumps_compact, to_native
import patch as P

def sch(rel):
    return to_native(load_strict(os.path.join(STD, rel)))

AB_ATT = sch("extensions/action-binding/schemas/execution-evidence.schema.json")
AB_REP = sch("extensions/action-binding/schemas/verification-report.schema.json")
SIG_ATT = sch("extensions/signatures/schemas/signatures-attachment.schema.json")
SIG_REP = sch("extensions/signatures/schemas/verification-report.schema.json")
PV_EXP = sch("extensions/portable-verification/schemas/verification-export.schema.json")
CORE = sch("standard/v5.0/schemas/decision-record.schema.json")
REG = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in (AB_ATT, AB_REP, SIG_ATT, SIG_REP, PV_EXP, CORE)])

def validate(schema, doc):
    v = jsonschema.Draft202012Validator(schema, registry=REG)
    errs = list(v.iter_errors(doc))
    return (not errs), [e.message[:160] for e in errs[:3]]

def defref(base_schema, name):
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$ref": base_schema["$id"] + "#/$defs/" + name}

def run_ab(rec):
    C = load_strict(os.path.join(STD, "extensions/action-binding/tests/cases.json"))
    V = load_strict(os.path.join(STD, "extensions/action-binding/tests/vectors.json"))
    def digest_of(x):
        if x == "beside":
            return hashlib.sha256(dumps_compact(V["signatures_attachments"]["beside"])).hexdigest()
        return hashlib.sha256(dumps_compact(V["attachments"][x.split(":", 1)[1]])).hexdigest()
    for c in C["schema_cases"]:
        try:
            if c["schema"] == "core_record":
                doc = to_native(loads(C["records"][c["record"]].encode())); schema = CORE
            else:
                base = V["attachments"][c["base"]] if c["schema"] == "attachment" else V["base_report"]
                d = P.apply(base, c["patch"], vectors=V, digest_of=digest_of)
                doc = to_native(loads(dumps_compact(d)))
                schema = AB_ATT if c["schema"] == "attachment" else AB_REP
            ok, errs = validate(schema, doc)
            got = "pass" if ok else "fail"
            rec.add("action-binding/schema", c["id"], got == c["expected"], None if got == c["expected"] else {"expected": c["expected"], "got": got, "errors": errs})
        except Unresolvable as e:
            rec.add("action-binding/schema", c["id"], None, attempted=False, why="the schema refers to a file outside the inputs (%s)" % e)
        except Exception as e:
            rec.add("action-binding/schema", c["id"], False, {"exception": repr(e)})

def run_sig(rec):
    C = load_strict(os.path.join(STD, "extensions/signatures/tests/cases.json"))
    V = load_strict(os.path.join(STD, "extensions/signatures/tests/vectors.json"))
    def digest_of(x):
        if x == "attachment":
            d = V["base_attachment"]
        elif x == "export":
            d = V["exports"][V["base_context"]["export"]]
        else:
            d = V["action_binding_attachments"][x.split(":", 1)[1]]
        return hashlib.sha256(dumps_compact(d)).hexdigest()
    m = {"attachment": SIG_ATT, "report": SIG_REP, "ab_attachment": AB_ATT, "pv_export": PV_EXP, "core_record": CORE,
         "person_signature": defref(SIG_ATT, "person_signature"), "organisation_seal": defref(SIG_ATT, "organisation_seal")}
    for c in C["schema_cases"]:
        if c["schema"] == "trust_policy":
            rec.add("signatures/schema", c["id"], None, attempted=False,
                    why="the trust policy schema is anchoring 0.2.0's (../anchoring/schemas/trust-policy.schema.json), not among the inputs")
            continue
        try:
            base = P.get(V, c["base"])
            if c["schema"] == "core_record":
                base = loads(base.encode())
            d = P.apply(base, c["patch"], vectors=V, digest_of=digest_of)
            raw = dumps_compact(d)
            doc = to_native(loads(raw))
            ok, errs = validate(m[c["schema"]], doc)
            got = "pass" if ok else "fail"
            rec.add("signatures/schema", c["id"], got == c["expected"], None if got == c["expected"] else {"expected": c["expected"], "got": got, "errors": errs, "desc": c["description"][:120]})
        except Unresolvable as e:
            rec.add("signatures/schema", c["id"], None, attempted=False, why="the schema refers to a file outside the inputs (%s)" % e)
        except UnicodeEncodeError:
            rec.add("signatures/schema", c["id"], None, attempted=False, why="the document has no UTF-8 encoding")
        except Exception as e:
            rec.add("signatures/schema", c["id"], False, {"exception": repr(e), "desc": c["description"][:120]})

if __name__ == "__main__":
    rec = Recorder(); run_ab(rec); run_sig(rec)
    from collections import Counter
    print(Counter((r["suite"], str(r["result"])) for r in rec.rows))
    for r in rec.rows:
        if r["result"] is not True and r["result"] != "not attempted":
            print(r["id"], json.dumps(r.get("detail"), ensure_ascii=False)[:500])
