"""Reading a signatures report with its documents (signatures, "The verifier and its report":
"a reader holding both the report and the documents it covers checks the counts, the digests, and
that each dimension reported as verified is verified")."""
from dps_common import compact, sha256_hex, is_json_int
import sig_check, sigcore

LESS = ("not_checked", "unavailable", "not_supported")


def mine(att, policy, ab, export):
    ref = sigcore.policy_refusal(policy)
    held = list(att.get("person_signatures", []) or []) + list(att.get("organisation_seals", []) or [])
    ts = [sig_check.timestamp(t, i, held, policy, ref) for i, t in enumerate(att.get("timestamps", []) or [])]
    ps = [sig_check.person(a, policy, ab, export, ts, ref) for a in att.get("person_signatures", []) or []]
    ss = [sig_check.seal(s, policy, ab, export, ts, ref) for s in att.get("organisation_seals", []) or []]
    return ref, ps, ss, ts


def _st(r, m, where, out):
    if r in LESS:
        return
    if r != m:
        out.append("%s: reported %r, the check finds %r" % (where, r, m))


def read(rep, att, policy, ab, export):
    out = []
    ref, ps, ss, ts = mine(att, policy, ab, export)
    if rep.get("attachment_digest") != sha256_hex(compact(att)):
        out.append("attachment_digest is not the attachment's")
    want = []
    if export is not None:
        want.append(("export", None, sha256_hex(compact(export))))
    for k in sorted(ab):
        want.append(("action_binding_attachment", k, sha256_hex(compact(ab[k]))))
    got = [(d.get("kind"), d.get("decision_id"), d.get("digest")) for d in rep.get("documents", [])]
    if sorted(got, key=str) != sorted(want, key=str):
        out.append("documents do not match those held")
    if rep.get("trust_policy_ref") != policy.get("policy_ref"):
        out.append("trust_policy_ref is not the policy's policy_ref")
    tp = rep.get("trust_policy", {}).get("status")
    if tp != ("failed" if ref else "verified"):
        out.append("trust_policy reported %r" % tp)
    for name, lst, mlist, ix in (("person_signature", rep.get("person_signatures", []), ps, "signature_index"),
                                 ("organisation_seal", rep.get("organisation_seals", []), ss, "seal_index"),
                                 ("timestamp", rep.get("timestamps", []), ts, "timestamp_index")):
        cnt = rep.get(name + "_count")
        if not is_json_int(cnt) or cnt != len(mlist):
            out.append("%s_count %r; the attachment has %d" % (name, cnt, len(mlist)))
        idx = [x.get(ix) for x in lst]
        if not all(is_json_int(i) for i in idx) or sorted(idx) != list(range(len(mlist))):
            out.append("%s results do not give each index once: %r" % (name, idx)); continue
        for x in lst:
            m = mlist[x[ix]]
            w = "%s %d" % (name, x[ix])
            _st(x.get("status"), m["status"], w, out)
            if name == "timestamp":
                if x.get("tsa_ref") != m["tsa_ref"]: out.append(w + ": tsa_ref differs")
                for k, v in (x.get("checks") or {}).items():
                    _st(v if isinstance(v, str) else v.get("status"), m["checks"][k]["status"], w + " " + k, out)
                if x.get("status") == "verified" and x.get("existed_no_later_than") != m.get("existed_no_later_than"):
                    out.append(w + ": existed_no_later_than differs")
                st = x.get("signer_time", {})
                _st(st.get("status"), m["signer_time"]["status"], w + " signer_time", out)
                if "consistency" in st and st.get("consistency") != m["signer_time"].get("consistency"):
                    out.append(w + ": signer_time consistency differs")
                continue
            if x.get("key_ref") != m["key_ref"]: out.append(w + ": key_ref differs")
            if name == "person_signature":
                if x.get("stage_id") != m.get("stage_id"): out.append(w + ": stage_id differs")
                if "covers_affirmation_record" in x.get("subject", {}) and \
                        x["subject"]["covers_affirmation_record"] != m["subject"].get("covers_affirmation_record"):
                    out.append(w + ": covers_affirmation_record not carried through")
                for k in ("assertion", "decision_id"):
                    if x.get(k) != m.get(k): out.append(w + ": %s differs" % k)
            for d in ("signature", "subject", "key_state") + (("identity",) if name == "person_signature" else ()):
                xd, md = x.get(d, {}), m[d]
                _st(xd.get("status"), md["status"], "%s %s" % (w, d), out)
                if d == "signature":
                    if "certificate" in xd: _st(xd["certificate"], md.get("certificate", "not_checked"), w + " certificate", out)
                    if xd.get("key_ref", md.get("key_ref")) != md.get("key_ref"): out.append(w + ": signature key_ref differs")
                if d == "subject" and "embedded_copy" in xd:
                    _st(xd["embedded_copy"], md.get("embedded_copy"), w + " embedded_copy", out)
                if d == "key_state" and xd.get("status") == "verified":
                    for k in ("key_ref", "time_basis", "time", "timestamp_index"):
                        if xd.get(k) != md.get(k): out.append("%s key_state %s differs" % (w, k))
                if d == "identity":
                    for k in ("holder", "issuer_named", "source_ref", "consistency"):
                        if k in xd and xd.get(k) != md.get(k): out.append("%s identity %s differs" % (w, k))
            if name == "person_signature":
                xa, ma = x.get("authenticator"), m.get("authenticator")
                if xa is not None:
                    for k, v in xa.items():
                        if (ma or {}).get(k) != v: out.append(w + ": authenticator %s differs" % k)
    return out
