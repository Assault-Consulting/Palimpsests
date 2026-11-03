"""Runs action binding 0.3.0's tests/cases.json with this reading's check. Writes one JSON result
per case: expected, what this check found, and whether they agree, or "not attempted" and why."""
import base64, hashlib, json, os, sys, copy
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from dps_common import strict_loads, compact, apply_patch, get_ptr, sha256_hex, Unreadable
import ab_binding, ab_sig, sigcore

IN = os.environ.get("DPS_INPUTS", "/home/claude/run/inputs")
AB = IN + "/standard/extensions/action-binding"
SG = IN + "/standard/extensions/signatures"


def load(p):
    with open(p, "rb") as fh:
        return strict_loads(fh.read())


cases = load(AB + "/tests/cases.json")
vec = load(AB + "/tests/vectors.json")
SCHEMAS = {"attachment": load(AB + "/schemas/execution-evidence.schema.json"),
           "report": load(AB + "/schemas/verification-report.schema.json"),
           "core_record": load(IN + "/standard/standard/v5.0/schemas/decision-record.schema.json")}


def validator(name):
    reg = Registry()
    for s in SCHEMAS.values():
        if "$id" in s:
            reg = reg.with_resource(s["$id"], Resource.from_contents(s))
    return Draft202012Validator(SCHEMAS[name], registry=reg)


def resolver(atts=None):
    def r(v):
        if isinstance(v, dict) and set(v) == {"vector"}:
            return copy.deepcopy(get_ptr(vec, v["vector"]))
        if isinstance(v, dict) and set(v) == {"digest_of"}:
            k = v["digest_of"]
            if k.startswith("attachment:"):
                return sha256_hex(compact((atts or vec["attachments"])[k.split(":", 1)[1]]))
            if k == "beside":
                return sha256_hex(compact(atts["__beside__"]))
        if isinstance(v, dict) and "value" in v and len(v) == 1:
            return v["value"]
        return v
    return r


def res(case, expected, got, ok, note=None):
    o = {"id": case["id"], "expected": expected, "got": got, "agrees": ok}
    if note:
        o["note"] = note
    return o


# ---------------------------------------------------------------- schema cases
def run_schema():
    out = []
    for c in cases["schema_cases"]:
        if c["schema"] == "core_record":
            doc = strict_loads(cases["records"][c["record"]])
        else:
            base = vec["attachments"][c["base"]] if c["schema"] == "attachment" else vec["base_report"]
            doc = apply_patch(base, c.get("patch", []), resolver())
        errs = list(validator(c["schema"]).iter_errors(doc))
        got = "pass" if not errs else "fail"
        out.append(res(c, c["expected"], got, got == c["expected"],
                       None if not errs else "; ".join(e.message[:120] for e in errs[:2])))
    return out


# ---------------------------------------------------------------- digest cases
def run_digest():
    out = []
    S = cases["specifications"]
    for c in cases["digest_cases"]:
        k = c["check"]
        if k == "known_vector":
            got = "match" if hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"] else "mismatch"
        elif k == "spec_digests":
            got = "match" if all(sha256_hex(s["text"].encode()) == s["spec_digest"] for s in S.values()) else "mismatch"
        elif k == "base_attachments":
            ok = True
            for a, names in c["carries"].items():
                sp = vec["attachments"][a]["action_specifications"]
                for n in names:
                    ok &= any(x["spec_digest"] == S[n]["spec_digest"] and base64.b64decode(x["content"]["bytes_b64"]) == S[n]["text"].encode() for x in sp)
            got = "match" if ok else "mismatch"
        elif k == "spec":
            t = S[c["spec"]]["text"]
            if "edit" in c:
                t = t.replace(c["edit"]["replace"], c["edit"]["with"])
            if c.get("reserialise") == "indent_2":
                t = json.dumps(json.loads(t), indent=2)
            elif c.get("reserialise") == "sorted_keys":
                t = json.dumps(json.loads(t), sort_keys=True, separators=(",", ":"))
            target = S[c["variant"]]["spec_digest"] if "variant" in c else S[c["spec"]]["spec_digest"]
            got = "match" if sha256_hex(t.encode()) == target else "mismatch"
        elif k == "record_seal":
            r = cases["records"][c["record"]]
            sh = json.loads(r)["seal_hash"]
            z = r.replace('"seal_hash":"%s"' % sh, '"seal_hash":"%s"' % ("0" * 64))
            got = "match" if sha256_hex(z.encode()) == sh else "mismatch"
        elif k == "bounds_digests":
            got = "match" if all(sha256_hex(b["text"].encode()) == b["bounds_digest"] for b in cases["bounds"].values()) else "mismatch"
        elif k == "bounds_carried":
            st = vec["attachments"][c["attachment"]]["stages"][c["stage"]]
            b = cases["bounds"][c["bounds"]]
            got = "match" if (base64.b64decode(st["bounds"]["bytes_b64"]) == b["text"].encode() and st["bounds_digest"] == b["bounds_digest"]) else "mismatch"
        else:
            out.append(res(c, c["expected"], "not attempted", "not attempted", "unknown check %s" % k)); continue
        out.append(res(c, c["expected"], got, got == c["expected"]))
    return out


# ---------------------------------------------------------------- binding cases
DIMS = ["record_statements", "action_binding", "stage_order", "authorisation_recheck", "observed_results",
        "rationale_provenance", "specification_digests", "specification_statements"]


def agg(statuses, prefer):
    if "failed" in statuses: return "failed"
    for p in prefer:
        if p in statuses: return p
    return "verified"


def binding_view(o):
    v = {d: o[d]["status"] for d in DIMS[:6]}
    v["specification_digests"] = agg([s["digest"]["status"] for s in o["specifications"]], ["unavailable", "not_checked"])
    v["specification_statements"] = agg([s["statements"]["status"] for s in o["specifications"]], ["not_checked", "unavailable"])
    v["execution_state"] = o["observed_results"]["execution_state"]
    v["observed"] = [[a["attempt_stage_id"], a["observed"], a.get("basis")] for a in o["observed_results"]["attempts"]]
    v["executed"] = [[e["spec_index"], e["reached_by"]] for e in o["executed_specifications"]]
    v["reviews"] = [[r["review_stage_id"], r["shown"], r.get("edited_by")] for r in o["reviews"]]
    v["standing"] = [[s["stage_id"], s["bounds"]["status"], s["requests_recorded"], s.get("max_requests"), s["revocation"]] for s in o["standing_approvals"]]
    return v


def run_binding():
    out = []
    for c in cases["binding_cases"]:
        att = apply_patch(vec["attachments"][c["attachment"]], c.get("patch", []), resolver())
        rec = cases["records"][c["record"]] if c.get("record") else None
        try:
            o = ab_binding.check(att, rec)
        except Exception as ex:
            out.append(res(c, c["expected"], "exception: %r" % ex, False)); continue
        v = binding_view(o)
        exp = {d: "verified" for d in DIMS}
        exp["execution_state"] = "attempted"
        exp.update(c["expected"])
        diffs = {k: [exp[k], v.get(k)] for k in exp if v.get(k) != exp[k]}
        got = {k: v[k] for k in exp}
        o2 = res(c, c["expected"], got, not diffs)
        if diffs:
            o2["differs"] = diffs
            o2["findings"] = [f for d in DIMS[:6] for f in o[d].get("findings", [])] + \
                             [f for s in o["standing_approvals"] for f in s["bounds"].get("findings", [])]
        out.append(o2)
    return out


# ---------------------------------------------------------------- signature cases
def run_signature():
    out = []
    for c in cases["signature_cases"]:
        covers = c.get("covers", ["A0", "A1"])
        atts = {n: copy.deepcopy(vec["attachments"][n]) for n in covers}
        for n, p in (c.get("attachment_patches") or {}).items():
            atts[n] = apply_patch(atts[n], p, resolver())
        bname = c.get("attachment", "beside")
        beside = None if bname is None else copy.deepcopy(vec["signatures_attachments"][bname])
        if beside is not None and c.get("beside_patch"):
            beside = apply_patch(beside, c["beside_patch"], resolver())
        pol = apply_patch(vec["trust_policy"], c.get("policy_patch", []), resolver())
        n = covers[c.get("index", 0)]
        a = atts[n]
        try:
            s, t, facts = ab_sig.check(a, compact(a), pol, beside)
        except Exception as ex:
            out.append(res(c, c["expected"], "exception: %r" % ex, False)); continue
        got = {"status": s["status"], "key_state": s["key_state"]["status"], "policy": facts["policy"],
               "time_basis": s["key_state"].get("time_basis"), "time_assurance": t["status"]}
        for k in ("holder", "certificate"):
            if k in s: got[k] = s[k]
        if "no_later_than" in t: got["no_later_than"] = t["no_later_than"]; got["timestamp_index"] = t["timestamp_index"]
        got.update({k: facts[k] for k in ("sealed_at_note", "stage_after_timestamp") if k in facts})
        exp = {"status": "verified", "key_state": "verified", "policy": "verified"}
        if c["expected"].get("status", "verified") == "verified" and c["expected"].get("key_state", "verified") == "verified":
            exp.update({"time_basis": "stated_time", "time_assurance": "not_checked"})
        exp.update(c["expected"])
        diffs = {k: [exp[k], got.get(k)] for k in exp if got.get(k) != exp[k]}
        o2 = res(c, c["expected"], got, not diffs)
        if diffs:
            o2["differs"] = diffs
            o2["findings"] = s.get("findings", []) + s["key_state"].get("findings", [])
        out.append(o2)
    return out


# ---------------------------------------------------------------- vector cases
def run_vector():
    out = []
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec
    from cryptography.hazmat.primitives import serialization
    for c in cases["vector_cases"]:
        k = c["check"]
        note = None
        try:
            if k == "known_vector":
                got = "match" if hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"] else "mismatch"
            elif k == "copies_verify":
                ok = True
                for n in c["attachments"]:
                    a = vec["attachments"][n]
                    s, _, _ = ab_sig.check(a, compact(a), vec["trust_policy"], None)
                    ok &= s["status"] == "verified"
                got = "match" if ok else "mismatch"
            elif k == "test_keys":
                ok = True
                for name, tk in vec["test_keys"].items():
                    seed = hashlib.sha256(tk["seed_text"].encode()).digest()
                    if tk["algorithm"] == "Ed25519":
                        pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    else:
                        n_ = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
                        d = int.from_bytes(seed, "big") % (n_ - 1) + 1
                        pub = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_bytes(
                            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                    ok &= pub.hex() == tk["public_key_hex"]
                got = "match" if ok else "mismatch"
            elif k == "token_imprints":
                from asn1crypto import cms, tsp
                ok = True
                for name, t in vec["tokens"].items():
                    ci = cms.ContentInfo.load(base64.b64decode(t["token_b64"]))
                    tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
                    ok &= tst["message_imprint"]["hashed_message"].native == hashlib.sha256(bytes.fromhex(t["imprint_of_hex"])).digest()
                got = "match" if ok else "mismatch"
            elif k == "seal_digests":
                ok = True
                for sname, aname in c["seals"].items():
                    ok &= vec["seals"][sname]["assertion"]["sealed"]["digest"] == ab_sig.sealed_digest(compact(vec["attachments"][aname]))
                got = "match" if ok else "mismatch"
            elif k == "duplicate_member":
                t = vec["texts"][c["text"]]
                txt = t["attachment_text"]
                strict = True
                try:
                    strict_loads(txt); strict = False
                except Unreadable:
                    pass
                last = json.loads(txt)
                first = json.loads(txt, object_pairs_hook=lambda ps: {k: v for k, v in reversed(ps)})
                s_last, _, _ = ab_sig.check(last, txt.encode("utf-8"), vec["trust_policy"], None)
                s_first, _, _ = ab_sig.check(first, txt.encode("utf-8"), vec["trust_policy"], None)
                note = "strict reader refuses: %s; last-member reader: %s (decision_id %s); first-member reader: %s (decision_id %s)" % (
                    strict, s_last["status"], last.get("decision_id"), s_first["status"], first.get("decision_id"))
                got = "match" if strict and s_last["status"] == "verified" and (
                    s_first["status"] != "verified" or first.get("decision_id") != last.get("decision_id")) else "mismatch"
            elif k == "signatures_vectors_agree":
                sv = load(SG + "/tests/vectors.json")
                ok = compact(vec["attachments"]["B0"]) == compact(sv["action_binding_attachments"]["DR-2099-101"]) and \
                    compact(vec["attachments"]["B1"]) == compact(sv["action_binding_attachments"]["DR-2099-102"]) and \
                    compact(vec["seals"]["seal_b0"]["assertion"]) == compact(sv["organisation_seals"]["seal_attachment"]["assertion"]) and \
                    compact(vec["trust_policy"]) == compact(sv["trust_policy"])
                got = "match" if ok else "mismatch"
                note = "compared as parsed documents re-serialised compactly"
            elif k == "reproduction":
                out.append(res(c, c["expected"], "not attempted", "not attempted",
                               "needs generate_vectors.py, which the boundary forbids reading or running")); continue
            elif k == "base_report":
                import ab_report
                rep = ab_report.build([vec["attachments"][n] for n in vec["base_context"]["covers"]],
                                      [cases["records"].get(r) for r in vec["base_context"]["records"]],
                                      vec["trust_policy"], vec["base_context"].get("attachment") and vec["signatures_attachments"][vec["base_context"]["attachment"]])
                a_, b_ = ab_report.strip_findings(rep), ab_report.strip_findings(vec["base_report"])
                got = "match" if json.dumps(a_, sort_keys=True) == json.dumps(b_, sort_keys=True) else "mismatch"
                note = "compared with findings removed (their wording is not fixed by the text)"
                if got == "mismatch":
                    note += "; first difference: " + str(ab_report.first_difference(a_, b_))
            else:
                out.append(res(c, c["expected"], "not attempted", "not attempted", "unknown check")); continue
        except Exception as ex:
            got = "exception: %r" % ex
        out.append(res(c, c["expected"], got, got == c["expected"], note))
    return out


def run_pairing():
    import ab_report, ab_pairing
    out = []
    for c in cases["pairing_cases"]:
        try:
            ctx = vec["base_context"]
            covers = c.get("covers", ctx["covers"])
            atts = {}
            lst = []
            for n in covers:
                a = copy.deepcopy(vec["attachments"][n])
                lst.append([n, a])
            pats = c.get("attachment_patches") or {}
            for e in lst:
                if e[0] in pats:
                    e[1] = apply_patch(e[1], pats[e[0]], resolver())
            atts = {n: a for n, a in lst}
            bname = c.get("attachment", ctx["attachment"])
            beside = None if bname is None else copy.deepcopy(vec["signatures_attachments"][bname])
            if beside is not None and c.get("beside_patch"):
                beside = apply_patch(beside, c["beside_patch"], resolver())
            pol = apply_patch(vec["trust_policy"], c.get("policy_patch", []), resolver())
            recs = [cases["records"][x] if x else None for x in c.get("records", ctx["records"])]
            mine = ab_report.build([a for _, a in lst], recs, pol, beside)
            atts["__beside__"] = beside
            if c.get("report") == "reference":
                base = mine
                note = "report 'reference': this reading's own report stands in for the reference check's"
            else:
                base = vec["base_report"]; note = None
            rep = apply_patch(base, c.get("report_patch", []), resolver(atts))
            errs = list(validator("report").iter_errors(rep))
            inc = ["schema: " + e.message[:100] for e in errs[:2]] + ab_pairing.read(
                rep, mine, [compact(a) for _, a in lst], compact(beside) if beside is not None else None)
            got = "inconsistent" if inc else "consistent"
            o = res(c, c["expected"], got, got == c["expected"], note)
            if inc: o["reasons"] = inc[:4]
        except Exception as ex:
            import traceback
            o = res(c, c["expected"], "exception: %r" % ex, False, traceback.format_exc()[-300:])
        out.append(o)
    return out


SUITES = {"pairing": run_pairing, "schema": run_schema, "digest": run_digest, "binding": run_binding, "signature": run_signature,
          "vector": run_vector}

if __name__ == "__main__":
    outdir = sys.argv[1]
    which = sys.argv[2:] or list(SUITES)
    os.makedirs(outdir, exist_ok=True)
    for w in which:
        r = SUITES[w]()
        n_ok = sum(1 for x in r if x["agrees"] is True)
        n_na = sum(1 for x in r if x["agrees"] == "not attempted")
        print("action-binding %-9s cases %3d  agree %3d  differ %3d  not attempted %d" % (w, len(r), n_ok, len(r) - n_ok - n_na, n_na))
        with open(os.path.join(outdir, "action-binding-%s.json" % w), "w") as fh:
            json.dump(r, fh, indent=1, ensure_ascii=False, default=str)
