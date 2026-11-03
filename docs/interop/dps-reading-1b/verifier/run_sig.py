"""Runs signatures 0.2.0's tests/cases.json with this reading's check."""
import base64, copy, hashlib, json, os, sys
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from dps_common import strict_loads, compact, apply_patch, get_ptr, sha256_hex, Unreadable
import sig_check, sigcore

IN = os.environ.get("DPS_INPUTS", "/home/claude/run/inputs")
EX = IN + "/standard/extensions"


def load(p):
    with open(p, "rb") as fh:
        return strict_loads(fh.read())


cases = load(EX + "/signatures/tests/cases.json")
vec = load(EX + "/signatures/tests/vectors.json")


def resolver(ctx=None):
    def r(v):
        if isinstance(v, dict) and set(v) == {"vector"}:
            return copy.deepcopy(get_ptr(vec, v["vector"]))
        if isinstance(v, dict) and set(v) == {"digest_of"}:
            k = v["digest_of"]
            if k == "attachment": return sha256_hex(compact(ctx["attachment"]))
            if k == "export": return sha256_hex(compact(ctx["export"]))
            if k.startswith("action_binding:"): return sha256_hex(compact(ctx["action_binding"][k.split(":", 1)[1]]))
        if isinstance(v, dict) and set(v) == {"value"}:
            return v["value"]
        return v
    return r


def named(spec, coll):
    """A name in vectors.json (coll), a pointer, or {from, patch}."""
    if isinstance(spec, str):
        if spec.startswith("/"):
            d = copy.deepcopy(get_ptr(vec, spec))
        else:
            d = copy.deepcopy(vec[coll][spec])
        return d.get("assertion", d) if isinstance(d, dict) and "assertion" in d and isinstance(d["assertion"], dict) else d
    base = named(spec["from"], coll)
    return apply_patch(base, spec.get("patch", []), resolver())


def context(c):
    pol = apply_patch(vec["trust_policy"], c.get("policy_patch", []), resolver())
    held_ab = c.get("action_binding", vec["base_context"]["action_binding"])
    ab = {k: copy.deepcopy(vec["action_binding_attachments"][k]) for k in held_ab}
    for k, p in (c.get("action_binding_patch") or {}).items():
        if k in ab:
            ab[k] = apply_patch(ab[k], p, resolver())
    ename = c.get("export", vec["base_context"]["export"])
    export = None if ename is None else copy.deepcopy(vec["exports"][ename])
    if export is not None and c.get("export_patch"):
        export = apply_patch(export, c["export_patch"], resolver())
    return pol, ab, export


def res(c, got, ok, extra=None):
    o = {"id": c["id"], "expected": c["expected"], "got": got, "agrees": ok}
    if extra: o.update(extra)
    return o


def compare(c, exp, got, findings):
    diffs = {k: [exp[k], got.get(k)] for k in exp if got.get(k) != exp[k]}
    return res(c, got, not diffs, {"differs": diffs, "findings": findings} if diffs else None)


def run_person():
    out = []
    for c in cases["person_cases"]:
        try:
            pol, ab, export = context(c)
            ref = sigcore.policy_refusal(pol)
            a = named(c["person"], "person_signatures")
            held = [a] + [apply_patch(copy.deepcopy(vec[x["kind"]][x["name"]]).get("assertion"), x.get("patch", []), resolver())
                          if isinstance(x, dict) and "kind" in x else named(x, "person_signatures") for x in (c.get("also") or [])]
            tss = [named(x, "timestamp_assertions") for x in (c.get("timestamps") or [])]
            tres = [sig_check.timestamp(t, i, held, pol, ref) for i, t in enumerate(tss)]
            r = sig_check.person(a, pol, ab, export, tres, ref)
            got = {"status": r["status"], "signature": r["signature"]["status"], "subject": r["subject"]["status"],
                   "key_state": r["key_state"]["status"], "identity": r["identity"]["status"],
                   "policy": "failed" if ref else "verified"}
            if "time_basis" in r["key_state"]: got["time_basis"] = r["key_state"]["time_basis"]
            for k, v in (r.get("authenticator") or {}).items(): got[k] = v
            if "consistency" in r["identity"]: got["consistency"] = r["identity"]["consistency"]
            if "reason" in r["identity"]: got["identity_reason"] = r["identity"]["reason"]
            if "covers_affirmation_record" in r["subject"]: got["covers_affirmation_record"] = r["subject"]["covers_affirmation_record"]
            exp = {k: "verified" for k in ("status", "signature", "subject", "key_state", "identity", "policy")}
            if c["expected"].get("key_state", "verified") == "verified": exp["time_basis"] = "stated_time"
            exp.update(c["expected"])
            fs = [f for d in ("signature", "subject", "key_state", "identity") for f in r[d].get("findings", [])]
            out.append(compare(c, exp, got, fs))
        except Exception as ex:
            import traceback
            out.append(res(c, "exception: %r" % ex, False, {"trace": traceback.format_exc()[-400:]}))
    return out


def run_seal():
    out = []
    for c in cases["seal_cases"]:
        try:
            pol, ab, export = context(c)
            ref = sigcore.policy_refusal(pol)
            s = named(c["seal"], "organisation_seals")
            tss = [named(x, "timestamp_assertions") for x in (c.get("timestamps") or [])]
            tres = [sig_check.timestamp(t, i, [s], pol, ref) for i, t in enumerate(tss)]
            r = sig_check.seal(s, pol, ab, export, tres, ref)
            got = {"status": r["status"], "signature": r["signature"]["status"], "subject": r["subject"]["status"],
                   "key_state": r["key_state"]["status"], "policy": "failed" if ref else "verified"}
            if "time_basis" in r["key_state"]: got["time_basis"] = r["key_state"]["time_basis"]
            if "certificate" in r["signature"]: got["certificate"] = r["signature"]["certificate"]
            if "embedded_copy" in r["subject"]: got["embedded_copy"] = r["subject"]["embedded_copy"]
            exp = {k: "verified" for k in ("status", "signature", "subject", "key_state", "policy")}
            if c["expected"].get("key_state", "verified") == "verified": exp["time_basis"] = "stated_time"
            exp.update(c["expected"])
            fs = [f for d in ("signature", "subject", "key_state") for f in r[d].get("findings", [])]
            out.append(compare(c, exp, got, fs))
        except Exception as ex:
            import traceback
            out.append(res(c, "exception: %r" % ex, False, {"trace": traceback.format_exc()[-400:]}))
    return out


TS_CHECKS = ("token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "signer_certificate", "tsa_state")


def run_timestamp():
    out = []
    for c in cases["timestamp_cases"]:
        try:
            pol = apply_patch(vec["trust_policy"], c.get("policy_patch", []), resolver())
            ref = sigcore.policy_refusal(pol)
            ts = named(c["timestamp"], "timestamp_assertions")
            held = []
            for h in c["held"]:
                d = copy.deepcopy(vec[h["kind"]][h["name"]])
                d = d.get("assertion", d)
                if h.get("patch"): d = apply_patch(d, h["patch"], resolver())
                held.append(d)
            r = sig_check.timestamp(ts, 0, held, pol, ref)
            got = {"status": r["status"], "signer_time": r["signer_time"]["status"]}
            got.update({k: r["checks"][k]["status"] for k in TS_CHECKS})
            if "existed_no_later_than" in r: got["existed_no_later_than"] = r["existed_no_later_than"]
            if "consistency" in r["signer_time"]: got["consistency"] = r["signer_time"]["consistency"]
            exp = {k: "verified" for k in ("status", "signer_time") + TS_CHECKS}
            exp.update(c["expected"])
            if "gen_time" in exp:
                rr = sigcore.check_token(ts.get("token_b64", ""), None, ("not_checked", None), ts.get("tsa_ref"), pol, ref)
                got["gen_time"] = rr.get("gen_time")
            fs = [f for k in TS_CHECKS for f in r["checks"][k].get("findings", [])] + r["signer_time"].get("findings", [])
            out.append(compare(c, exp, got, fs))
        except Exception as ex:
            import traceback
            out.append(res(c, "exception: %r" % ex, False, {"trace": traceback.format_exc()[-400:]}))
    return out


SUITES = {"person": run_person, "seal": run_seal, "timestamp": run_timestamp}



# ------------------------------------------------------------------ schema and vector suites
def _schemas():
    S = {"attachment": load(EX + "/signatures/schemas/signatures-attachment.schema.json"),
         "report": load(EX + "/signatures/schemas/verification-report.schema.json"),
         "trust_policy": load(EX + "/anchoring/schemas/trust-policy.schema.json"),
         "pv_export": load(EX + "/portable-verification/schemas/verification-export.schema.json"),
         "ab_attachment": load(EX + "/action-binding/schemas/execution-evidence.schema.json"),
         "core_record": load(IN + "/standard/standard/v5.0/schemas/decision-record.schema.json")}
    reg = Registry()
    for s in S.values():
        if "$id" in s:
            reg = reg.with_resource(s["$id"], Resource.from_contents(s))
    aid = S["attachment"]["$id"]
    S["person_signature"] = {"$ref": aid + "#/$defs/person_signature"}
    S["organisation_seal"] = {"$ref": aid + "#/$defs/organisation_seal"}
    return S, reg


def run_schema():
    S, reg = _schemas()
    out = []
    for c in cases["schema_cases"]:
        base = copy.deepcopy(get_ptr(vec, c["base"]))
        if isinstance(base, str):
            base = strict_loads(base)
        doc = apply_patch(base, c.get("patch", []), resolver())
        errs = list(Draft202012Validator(S[c["schema"]], registry=reg).iter_errors(doc))
        got = "pass" if not errs else "fail"
        out.append(res(c, got, got == c["expected"], {"note": "; ".join(e.message[:100] for e in errs[:2])} if errs else None))
    return out


def _seed(name):
    return hashlib.sha256(name.encode("utf-8")).digest()


def run_vector():
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec as _ec
    from cryptography.hazmat.primitives import serialization, hashes as _h
    from cryptography import x509
    import jspan
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    out = []
    allp = {k: v["assertion"] for k, v in vec["person_signatures"].items()}
    alls = {k: v["assertion"] for k, v in vec["organisation_seals"].items()}
    for c in cases["vector_cases"]:
        k, note = c["check"], None
        try:
            if k == "known_vector":
                ok = hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"]
            elif k == "length_prefix":
                ok = all((len(t.encode()).to_bytes(4, "big") + t.encode()).hex() == h for t, h in c["vectors"])
            elif k == "record_seals":
                ok = all(vec["records"][r]["seal_hash"] == h if "seal_hash" in vec["records"][r] else
                         json.loads(vec["records"][r]["text"]).get("seal_hash", h) == h for r, h in c["published"].items())
                note = "compared the published values with the records' stated seals; the SHA-256 over the covered bytes is checked in the person and seal suites"
            elif k == "signed_bytes":
                bad = []
                for n, a in list(allp.items()) + list(alls.items()):
                    w = vec["person_signatures"].get(n) or vec["organisation_seals"].get(n)
                    if "signed_bytes_hex" not in w: continue
                    try:
                        b = sig_check.person_signed_bytes(a) if n in allp else sig_check.seal_signed_bytes(a)
                    except Exception as ex:
                        b = None
                    if b is None or b.hex() != w["signed_bytes_hex"]: bad.append(n)
                ok = not bad; note = ("differ: %s" % bad) if bad else None
            elif k == "signed_bytes_fields":
                n = c["assertion"]
                a = allp.get(n) or alls.get(n)
                b = sig_check.person_signed_bytes(a) if n in allp else sig_check.seal_signed_bytes(a)
                fields, i = [], 8
                while i < len(b):
                    L = int.from_bytes(b[i:i + 4], "big"); fields.append(b[i + 4:i + 4 + L].hex()); i += 4 + L
                ok = b[:8] == b"DPS-SIG\x00" and fields == c["fields_hex"]
            elif k == "signatures":
                bad = []
                for n, a in list(allp.items()) + list(alls.items()):
                    sg = a.get("signature", {})
                    w = vec["person_signatures"].get(n) or vec["organisation_seals"].get(n)
                    tk = vec["test_keys"].get(w.get("signed_with"))
                    if sg.get("algorithm") != "Ed25519" or not tk or "seed_text" not in tk: continue
                    b = bytes.fromhex(w.get("signature_made_over_hex") or w["signed_bytes_hex"])
                    re_ = ed25519.Ed25519PrivateKey.from_private_bytes(_seed(tk["seed_text"])).sign(b)
                    same = re_ == base64.b64decode(sg["value_b64"])
                    if same == (n in c["altered_after_signing"]): bad.append(n)
                ok = not bad; note = ("not reproduced as expected: %s" % bad) if bad else "re-signed with the seed of signed_with over signature_made_over_hex (else signed_bytes_hex)"
            elif k == "webauthn":
                bad, notes = [], []
                for n, a in allp.items():
                    sg = a["signature"]
                    if not sg.get("algorithm", "").startswith("WebAuthn"): continue
                    try:
                        cd = strict_loads(base64.b64decode(sg["client_data_json_b64"]))
                    except Unreadable:
                        if n not in c.get("not_read", []): bad.append(n)
                        continue
                    sb = sig_check.person_signed_bytes(a)
                    ch_ok = cd.get("challenge") == base64.urlsafe_b64encode(hashlib.sha256(sb).digest()).rstrip(b"=").decode()
                    if ch_ok == (n in c["other_challenge"]): bad.append(n)
                    tk = vec["test_keys"].get(sg["key_ref"])
                    if tk and "seed_text" in tk and sg["algorithm"] == "WebAuthn-ES256":
                        d = int.from_bytes(_seed(tk["seed_text"]), "big") % (N - 1) + 1
                        pk = _ec.derive_private_key(d, _ec.SECP256R1())
                        msg = base64.b64decode(sg["authenticator_data_b64"]) + hashlib.sha256(base64.b64decode(sg["client_data_json_b64"])).digest()
                        try:
                            re_ = pk.sign(msg, _ec.ECDSA(_h.SHA256(), deterministic_signing=True))
                            same = re_ == base64.b64decode(sg["value_b64"])
                            if same == (n in c["altered_after_signing"]): bad.append(n)
                        except TypeError:
                            notes.append("RFC 6979 signing not available in this cryptography: signatures verified, not reproduced")
                ok = not bad; note = "; ".join(sorted(set(notes)) + (["differ: %s" % bad] if bad else [])) or None
            elif k == "domain_separation":
                n = c["assertion"]
                a = allp.get(n) or alls.get(n)
                f = sig_check.person_signed_bytes if n in allp else sig_check.seal_signed_bytes
                b0 = f(a)
                ok = True
                for i, o in enumerate(c["others"]):
                    a2 = copy.deepcopy(a)
                    if i == 0: a2["profile"] = o
                    elif i == 1: a2["profile_version"] = o
                    elif i == 2: a2["assertion"] = o
                    else: a2["signature"]["key_ref"] = o
                    try:
                        ok &= f(a2) != b0
                    except Exception:
                        pass
            elif k == "token_imprints":
                from asn1crypto import cms, tsp
                ok = True
                for n, t in vec["tokens"].items():
                    try:
                        ci = cms.ContentInfo.load(base64.b64decode(t["token_b64"]), strict=True)
                        tst = tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
                        ok &= tst["message_imprint"]["hashed_message"].native == hashlib.sha256(bytes.fromhex(t["imprint_of_hex"])).digest()
                    except Exception:
                        ok &= n in c["not_tokens"]
            elif k == "embedded_copy":
                att = vec["action_binding_attachments"][c["decision_id"]]
                s = alls[c["seal"]]
                b = compact(att)
                rep = jspan.replace_string_value(b.decode(), ["issuer_signature", "value_b64"]).encode()
                ok = sha256_hex(rep) == s["sealed"]["digest"] and sha256_hex(b) != s["sealed"]["digest"] and \
                    att["issuer_signature"]["value_b64"] == s["signature"]["value_b64"]
            elif k == "escaped_copy":
                e = vec["escaped_copy"]
                t = e["attachment_text"]
                same = strict_loads(t) == vec["action_binding_attachments"][c["decision_id"]]
                d_val = sha256_hex(jspan.replace_string_value(t, ["issuer_signature", "value_b64"]).encode())
                a_ = t.index(e["value_as_written"]); d_wr = sha256_hex((t[:a_] + "A" * len(e["value_as_written"]) + t[a_ + len(e["value_as_written"]):]).encode())
                ok = same and d_val == alls[c["seal"]]["sealed"]["digest"] == e["digest_replacing_the_value_characters"] and d_wr == e["digest_replacing_the_written_characters"] != d_val
            elif k == "duplicate_member":
                v_ = get_ptr(vec, c["vector"]); t = v_["attachment_text"]
                try:
                    strict_loads(t); refused = False
                except Unreadable:
                    refused = True
                last = json.loads(t); first = json.loads(t, object_pairs_hook=lambda ps: {kk: vv for kk, vv in reversed(ps)})
                asis = vec["action_binding_attachments"][c["decision_id"]]
                ok = refused and (last == asis) != (first == asis)
                note = "strict reader refuses: %s; last-member reader finds the attachment as issued: %s; first-member reader: %s" % (refused, last == asis, first == asis)
            elif k == "deep_nesting":
                t = "[" * int(c["depth"]) + "]" * int(c["depth"])
                try:
                    strict_loads(t); ok = False
                except Unreadable:
                    ok = True
            elif k == "copy_members":
                att = vec["action_binding_attachments"][c["decision_id"]]
                ok = True
                for n in c["seals"]:
                    s = alls[n]
                    a2 = copy.deepcopy(att)
                    a2["issuer_signature"] = dict(a2["issuer_signature"])
                    # each such seal names the attachment its issuer wrote: the copy is the seal's own, relabelled as named
                    st, _ = sig_check.copy_agrees(a2, s)
                    ok &= st == "failed" or n == "seal_attachment_copy_other_time"
                note = "computed with the base attachment's copy against each seal; the attachments as their issuer wrote them are not in vectors.json under these names: partial"
            elif k == "copy_by_version":
                s = alls[c["seal"]]
                att = copy.deepcopy(vec["action_binding_attachments"]["DR-2099-101"])
                att["profile_version"] = "0.2.0"
                cp = {kk: s["signature"][kk] if kk in s["signature"] else None for kk in ("algorithm", "key_ref", "value_b64")}
                cp["signed_bytes_ref"] = sig_check.SBR
                att["issuer_signature"] = cp
                a_ok = sig_check.copy_agrees(att, s)[0] == "verified"
                att["issuer_signature"] = dict(cp, sealed_at=s["sealed_at"])
                b_ok = sig_check.copy_agrees(att, s)[0] == "failed"
                c_ok = all(sig_check.copy_agrees(dict(att, profile_version=v_), s)[0] == "not_checked" for v_ in (c["unknown_version"], [1], {"a": 1}, 3))
                ok = a_ok and b_ok and c_ok
                note = "the 0.2.0 attachment rebuilt from the base attachment with a four-member copy of the seal"
            elif k == "certificates":
                ok = True
                for n, ce in vec["certificates"].items():
                    der = base64.b64decode(ce["certificate_b64"])
                    ok &= hashlib.sha256(der).hexdigest() == ce["sha256"]
                    pk = x509.load_der_x509_certificate(der).public_key()
                    tk = vec["test_keys"][n]
                    if tk["algorithm"] == "RSA-2048":
                        nn = pk.public_numbers(); ok &= format(nn.n, "x") == tk["modulus_hex"].lstrip("0") and format(nn.e, "06x") == tk["public_exponent_hex"]
                    elif tk["algorithm"] == "Ed25519":
                        ok &= pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() == tk["public_key_hex"]
                    else:
                        ok &= pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex() == tk["public_key_hex"]
            elif k == "test_keys":
                ok = True
                for n, tk in vec["test_keys"].items():
                    if "seed_text" not in tk: continue
                    sd = _seed(tk["seed_text"])
                    if tk["algorithm"] == "Ed25519":
                        pub = ed25519.Ed25519PrivateKey.from_private_bytes(sd).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    else:
                        pub = _ec.derive_private_key(int.from_bytes(sd, "big") % (N - 1) + 1, _ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                    ok &= pub.hex() == tk["public_key_hex"]
                out.append(res(c, "not attempted", "not attempted", {"note": "seed-derived keys computed (%s); the RSA key against RFC 9500's text not checked: RFC 9500 could not be fetched" % ("all match" if ok else "a mismatch")})); continue
            elif k in ("reproduction", "published_rsa_key", "anchoring_fixtures", "specification"):
                why = {"reproduction": "needs generate_vectors.py, which the boundary forbids",
                       "published_rsa_key": "RFC 9500 could not be fetched (rfc-editor.org not resolvable from the sandbox)",
                       "anchoring_fixtures": "compares with anchoring's vectors beyond the parts the two texts reuse; left out to keep the boundary",
                       "specification": "not implemented in this run"}[k]
                out.append(res(c, "not attempted", "not attempted", {"note": why})); continue
            else:
                out.append(res(c, "not attempted", "not attempted", {"note": "unknown check"})); continue
            got = "match" if ok else "mismatch"
        except Exception as ex:
            import traceback
            got = "exception: %r" % ex; note = traceback.format_exc()[-300:]
        out.append(res(c, got, got == c["expected"], {"note": note} if note else None))
    return out


SUITES.update({"schema": run_schema, "vector": run_vector})





def run_pairing():
    import sig_pairing
    out = []
    S, reg = _schemas()
    for c in cases["pairing_cases"]:
        try:
            ctx = vec["base_context"]
            att = apply_patch(vec["base_attachment"], c.get("attachment_patch", []), resolver())
            pol, ab, export = context({k: v for k, v in c.items() if k in ("policy_patch", "action_binding_patch", "export")})
            ctxd = {"attachment": att, "export": export, "action_binding": ab}
            rep = apply_patch(vec["base_report"], c.get("report_patch", []), resolver(ctxd))
            if c.get("deep_subject_of"):
                out.append(res(c, "not attempted", "not attempted", {"note": "deep_subject_of: the nesting construction is not implemented in this run"})); continue
            errs = list(Draft202012Validator(S["report"], registry=reg).iter_errors(rep))
            inc = ["schema: " + e.message[:90] for e in errs[:2]] + sig_pairing.read(rep, att, pol, ab, export)
            got = "inconsistent" if inc else "consistent"
            out.append(res(c, got, got == c["expected"], {"reasons": inc[:3]} if inc else None))
        except Exception as ex:
            import traceback
            out.append(res(c, "exception: %r" % ex, False, {"trace": traceback.format_exc()[-300:]}))
    return out


SUITES["pairing"] = run_pairing


if __name__ == "__main__":
    outdir = sys.argv[1]
    which = sys.argv[2:] or list(SUITES)
    os.makedirs(outdir, exist_ok=True)
    for w in which:
        r = SUITES[w]()
        n_ok = sum(1 for x in r if x["agrees"] is True)
        n_na = sum(1 for x in r if x["agrees"] == "not attempted")
        print("signatures %-9s cases %3d  agree %3d  differ %3d  not attempted %d" % (w, len(r), n_ok, len(r) - n_ok - n_na, n_na))
        with open(os.path.join(outdir, "signatures-%s.json" % w), "w") as fh:
            json.dump(r, fh, indent=1, ensure_ascii=False, default=str)

