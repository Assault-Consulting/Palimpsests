"""Action binding 0.3.0 item 7 and the issuer_signature/time bullets of "The verifier and its
report", with signatures 0.2.0 ("The organisation's seal", "Independent timestamps over signature
values") and anchoring 0.2.0 by reference."""
import base64, hashlib
from dps_common import (f_text, f_digest, f_time, signed_bytes, Unencodable, sha256_hex, instant,
                        real_utc, utc_text)
from sigcore import (policy_refusal, find_key, ed25519_verify, strict_key_bytes, certificate_holds,
                     key_state, check_token, REFUSED)
from jspan import replace_string_value

COPY_MEMBERS = {"algorithm", "key_ref", "signed_bytes_ref", "sealed_at", "value_b64"}
SBR = "dps-signatures 0.2.0 organisation_seal"


def sealed_digest(att_bytes):
    text = att_bytes.decode("utf-8")
    return sha256_hex(replace_string_value(text, ["issuer_signature", "value_b64"]).encode("utf-8"))


def seal_signed_bytes(key_ref, kind, sid, digest_hex, sealed_at):
    return signed_bytes([f_text("dps-signatures"), f_text("0.2.0"), f_text("organisation_seal"), f_text(key_ref),
                         f_text(kind), f_text(sid), f_digest(digest_hex), f_time(sealed_at)])


def _names_seal(of, key_ref, sid):
    return (isinstance(of, dict) and of.get("assertion") == "organisation_seal" and of.get("key_ref") == key_ref
            and of.get("sealed_kind") == "attachment" and of.get("sealed_id") == sid
            and of.get("profile", "dps-signatures") == "dps-signatures")


def check(att, att_bytes, policy, beside=None):
    """Returns issuer_signature, time_assurance and the extra facts used by the cases."""
    refused = policy_refusal(policy)
    facts = {"policy": "failed" if refused else "verified"}
    copy = att.get("issuer_signature")
    if copy is None:
        sig = {"status": "not_checked", "attests": "issuer_recorded_claims_only",
               "key_state": {"status": "not_checked"}, "findings": ["the attachment carries no signature"]}
        return sig, {"status": "not_checked", "basis": "issuer_assertion",
                     "findings": ["no verified issuer signature"]}, facts
    f = []
    sig = {"status": "failed", "attests": "issuer_recorded_claims_only", "key_ref": copy.get("key_ref"),
           "algorithm": copy.get("algorithm"), "reference_source": "trust_policy"}
    ok_form = True
    if set(copy) != COPY_MEMBERS:
        ok_form = False; f.append("the copy does not have exactly the five members")
    if copy.get("algorithm") != "Ed25519":
        ok_form = False; f.append("algorithm is not exactly Ed25519")
    if copy.get("signed_bytes_ref") != SBR:
        ok_form = False; f.append("signed_bytes_ref is not exactly %r" % SBR)
    # agreement with a seal carried beside
    try:
        my_digest = sealed_digest(att_bytes)
    except Exception:
        my_digest = None
    if beside is not None:
        for s in beside.get("organisation_seals", []) or []:
            sd = s.get("sealed", {})
            if sd.get("kind") == "attachment" and sd.get("id") == att.get("decision_id") and sd.get("digest") == my_digest:
                if (s.get("signature", {}).get("algorithm") != copy.get("algorithm") or
                        s.get("signature", {}).get("value_b64") != copy.get("value_b64") or
                        s.get("sealed_at") != copy.get("sealed_at")):
                    ok_form = False; f.append("the copy does not agree with the seal carried beside")
    entry = find_key(policy, copy.get("key_ref"))
    value = None
    try:
        value = base64.b64decode(copy.get("value_b64", ""), validate=True)
    except Exception:
        f.append("value_b64 cannot be decoded")
    sig_ok = False
    try:
        dg = sealed_digest(att_bytes)
        sb = seal_signed_bytes(copy.get("key_ref"), "attachment", att.get("decision_id"), dg, copy.get("sealed_at"))
    except (Unencodable, ValueError, UnicodeError) as ex:
        sb = None; f.append("signed bytes cannot be built: %s" % ex)
    if refused:
        f.append("signature " + REFUSED % refused)
    elif entry is None:
        f.append("the policy does not list the key %r" % copy.get("key_ref"))
    elif entry.get("role") != "organisation":
        f.append("the key is in role %s, not organisation" % entry.get("role"))
    elif entry.get("algorithm") != copy.get("algorithm"):
        f.append("the policy's label %r is not the copy's %r" % (entry.get("algorithm"), copy.get("algorithm")))
    elif sb is not None and value is not None and ok_form:
        kb, why = strict_key_bytes(entry)
        if kb is None:
            f.append(why)
        else:
            cst, cwhy = certificate_holds(entry, kb)
            sig["certificate"] = cst
            if cst == "failed":
                f.append(cwhy)
            else:
                sig_ok, why = ed25519_verify(entry, sb, value)
                if not sig_ok:
                    f.append(why)
    # timestamps beside over this signature value
    ts_times, ts_notes = [], []
    if beside is not None and sig_ok:
        for i, ts in enumerate(beside.get("timestamps", []) or []):
            subj = ts.get("subject", {})
            try:
                sv = base64.b64decode(subj.get("value_b64", ""), validate=True)
            except Exception:
                continue
            if sv != value:
                continue
            named = _names_seal(subj.get("of"), copy.get("key_ref"), att.get("decision_id"))
            r = check_token(ts.get("token_b64", ""), sv, ("verified", None) if named else
                            ("failed", "the subject names another assertion than the one with that value"),
                            ts.get("tsa_ref"), policy, refused)
            if r["status"] == "verified":
                ts_times.append((r["T"], i, ts.get("tsa_ref")))
    if refused:
        ks = key_state(entry or {}, copy.get("sealed_at"), [], refused)
    elif not sig_ok or entry is None:
        ks = {"status": "not_checked", "findings": ["the signature is not verified"]}
    else:
        ks = key_state(entry, copy.get("sealed_at"), [(t, i) for t, i, _ in ts_times])
    sig["key_state"] = ks
    if sig_ok and ks["status"] == "verified":
        sig["status"] = "verified"
    elif sig_ok and ks["status"] == "unavailable":
        sig["status"] = "unavailable"
    else:
        sig["status"] = "failed"
    if entry is not None and entry.get("role") == "organisation" and not refused:
        sig["holder"] = entry.get("holder")
    if "certificate" not in sig and entry is not None and not refused:
        sig["certificate"] = "not_checked" if entry.get("certificate_b64") is None else sig.get("certificate", "not_checked")
    # notes on the issuer's times
    stages = att.get("stages", [])
    latest = None
    for s in stages:
        a, _ = instant(s.get("at"))
        if a is not None and (latest is None or a > latest[0]):
            latest = (a, s.get("at"), s.get("stage_id"))
    sa_, _ = real_utc(copy.get("sealed_at"))
    if latest is not None and sa_ is not None and sa_ < latest[0]:
        f.append("sealed_at is earlier than stage %s (%s): both are the issuer's times; the signature stands" % (latest[2], latest[1]))
        facts["sealed_at_note"] = "earlier_than_a_stage"
    if sig["status"] == "verified" and ts_times:
        T, idx, tref = min(ts_times, key=lambda x: (x[0], x[1]))
        ta = {"status": "verified", "basis": "independent_source", "source_ref": tref,
              "no_later_than": utc_text(T), "timestamp_index": idx}
        late = [s for s in stages if instant(s.get("at"))[0] is not None and instant(s.get("at"))[0] > T]
        if late:
            ta["findings"] = ["stage %s is dated %s, after the time the signature existed by: the issuer's stage times are inconsistent with the timestamp" % (s.get("stage_id"), s.get("at")) for s in late]
            facts["stage_after_timestamp"] = True
    else:
        ta = {"status": "not_checked", "basis": "issuer_assertion",
              "findings": ["no verified independent timestamp over a verified issuer signature"]}
    if f:
        sig["findings"] = f
    return sig, ta, facts
