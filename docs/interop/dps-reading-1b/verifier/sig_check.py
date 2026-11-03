"""Signatures 0.2.0: the person's signature, the organisation's seal and a timestamp over a
signature value, written from the text ("Signed bytes", "The person's signature", "The
organisation's seal", "Independent timestamps over signature values", "The trust policy and key
states"), with anchoring 0.2.0 by reference."""
import base64, hashlib, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from dps_common import (f_text, f_digest, f_time, signed_bytes, Unencodable, sha256_hex, strict_loads,
                        Unreadable, real_utc, utc_text, compact)
from sigcore import (policy_refusal, find_key, ed25519_verify, strict_key_bytes, certificate_holds,
                     key_state, check_token, REFUSED)
from jspan import replace_string_value

SUPPORTED_PERSON = ("Ed25519", "WebAuthn-ES256")
SBR = "dps-signatures 0.2.0 organisation_seal"


def person_signed_bytes(a):
    t = a.get("assertion")
    head = [f_text(a.get("profile")), f_text(a.get("profile_version")), f_text(t), f_text(a.get("signature", {}).get("key_ref"))]
    if t == "person_approval":
        body = [f_text(a.get("decision_id")), f_text(a.get("stage_id")), f_text(a.get("outcome")),
                f_digest(a.get("shown_spec_digest")), f_digest(a.get("shown_view_digest")),
                f_digest(a.get("approved_spec_digest")), f_time(a.get("signed_at"))]
    elif t == "person_review":
        body = [f_text(a.get("decision_id")), f_text(a.get("stage_id")), f_text(a.get("outcome")),
                f_digest(a.get("shown_spec_digest")), f_digest(a.get("shown_view_digest")), f_time(a.get("signed_at"))]
    elif t == "person_standing_approval":
        body = [f_text(a.get("decision_id")), f_text(a.get("stage_id")), f_digest(a.get("bounds_digest")),
                f_digest(a.get("shown_view_digest")), f_time(a.get("signed_at"))]
    elif t == "person_affirmation":
        body = [f_text(a.get("decision_id")), f_digest(a.get("affirmed_digest")), f_time(a.get("signed_at"))]
    else:
        raise Unencodable("unknown assertion type %r" % t)
    for f in (a.get("shown_spec_digest"), a.get("approved_spec_digest"), a.get("bounds_digest"), a.get("affirmed_digest")):
        pass
    return signed_bytes(head + body)


def seal_signed_bytes(s):
    sd = s.get("sealed", {})
    return signed_bytes([f_text(s.get("profile")), f_text(s.get("profile_version")), f_text(s.get("assertion")),
                         f_text(s.get("signature", {}).get("key_ref")), f_text(sd.get("kind")), f_text(sd.get("id")),
                         f_digest(sd.get("digest")), f_time(s.get("sealed_at"))])


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def webauthn_verify(entry, sig, sb):
    """Returns (ok, finding, authenticator facts)."""
    facts = {}
    wa = entry.get("webauthn")
    if not isinstance(wa, dict) or not wa.get("rp_id") or not wa.get("origins"):
        return False, "the policy's entry names no relying party and origins", facts
    kb, why = strict_key_bytes(entry)
    if kb is None:
        return False, why, facts
    if len(kb) != 65 or kb[0] != 4:
        return False, "the policy's key is not a 65-byte uncompressed P-256 point", facts
    try:
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), kb)
    except Exception:
        return False, "the policy's key is not a P-256 point", facts
    try:
        ad = base64.b64decode(sig.get("authenticator_data_b64", ""), validate=True)
        cdj = base64.b64decode(sig.get("client_data_json_b64", ""), validate=True)
        val = base64.b64decode(sig.get("value_b64", ""), validate=True)
    except Exception:
        return False, "authenticator data, client data or value cannot be decoded", facts
    if len(ad) < 37:
        return False, "authenticatorData too short", facts
    flags = ad[32]
    facts["user_present"] = bool(flags & 0x01)
    facts["user_verified"] = bool(flags & 0x04)
    try:
        cd = strict_loads(cdj)
    except Unreadable as e:
        facts.pop("user_present"); facts.pop("user_verified")
        return False, "the client data cannot be read: %s" % e, {}
    if not isinstance(cd, dict):
        return False, "the client data is not an object", facts
    if isinstance(cd.get("crossOrigin"), bool):
        facts["cross_origin"] = cd["crossOrigin"]
    if isinstance(cd.get("topOrigin"), str) and cd["topOrigin"]:
        facts["top_origin"] = cd["topOrigin"]
    f = []
    if cd.get("type") != "webauthn.get":
        f.append("client data type is not webauthn.get")
    if cd.get("challenge") != _b64url(hashlib.sha256(sb).digest()):
        f.append("the challenge is not the SHA-256 of the signed bytes")
    if cd.get("origin") not in wa["origins"]:
        f.append("an origin the policy does not allow for the key")
    if "crossOrigin" in cd and cd["crossOrigin"] is not False:
        f.append("crossOrigin is not false")
    if "topOrigin" in cd:
        f.append("a topOrigin is stated")
    if ad[:32] != hashlib.sha256(wa["rp_id"].encode("utf-8")).digest():
        f.append("authenticatorData does not carry the SHA-256 of the policy's relying party identifier")
    if not facts["user_present"]:
        f.append("the UP flag is absent")
    try:
        pk.verify(val, ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        f.append("the ES256 signature does not verify")
    except Exception as ex:
        f.append("the ES256 signature cannot be verified: %s" % ex)
    return (not f), "; ".join(f) or None, facts


def _sig_value(a):
    try:
        return base64.b64decode(a.get("signature", {}).get("value_b64", ""), validate=True)
    except Exception:
        return None


def names(of, a):
    """The subject's `of` names assertion a (signatures, "Independent timestamps")."""
    if not isinstance(of, dict) or of.get("profile", "dps-signatures") != "dps-signatures":
        return False
    t = a.get("assertion")
    if of.get("assertion") != t or of.get("key_ref") != a.get("signature", {}).get("key_ref"):
        return False
    if t == "organisation_seal":
        return of.get("sealed_kind") == a.get("sealed", {}).get("kind") and of.get("sealed_id") == a.get("sealed", {}).get("id")
    if of.get("decision_id") != a.get("decision_id"):
        return False
    if t in ("person_approval", "person_review", "person_standing_approval"):
        return of.get("stage_id") == a.get("stage_id")
    return "stage_id" not in of


def timestamp(ts, index, held, policy, refused):
    """One timestamp over a signature value. held: assertions in the attachment."""
    subj = ts.get("subject", {})
    try:
        sv = base64.b64decode(subj.get("value_b64", ""), validate=True)
    except Exception:
        sv = None
    same = [a for a in held if sv is not None and _sig_value(a) == sv]
    named = [a for a in same if names(subj.get("of"), a)]
    if not same:
        sb = ("not_checked", "no assertion in the attachment has this signature value")
    elif not named:
        sb = ("failed", "the subject names another assertion than the one with this signature value")
    else:
        sb = ("verified", None)
    r = check_token(ts.get("token_b64", ""), sv, sb, ts.get("tsa_ref"), policy, refused)
    out = {"timestamp_index": index, "tsa_ref": ts.get("tsa_ref"), "status": r["status"], "checks": r["checks"]}
    st = {"status": "not_checked"}
    if r["status"] == "verified":
        out["existed_no_later_than"] = utc_text(r["T"])
        a = named[0]
        field = "sealed_at" if a.get("assertion") == "organisation_seal" else "signed_at"
        t, why = real_utc(a.get(field))
        st = {"status": "not_checked", "stated_in": field, "findings": [why]} if t is None else \
            ({"status": "failed", "stated": a[field], "stated_in": field, "consistency": "inconsistent"} if t > r["T"]
             else {"status": "verified", "stated": a[field], "stated_in": field, "consistency": "consistent"})
        out["T"] = r["T"]
    out["signer_time"] = st
    out["named"] = named[0] if named else None
    return out


def _ts_for(a, timestamps):
    return [(t["T"], t["timestamp_index"]) for t in timestamps if t["status"] == "verified" and t.get("named") is a]


def person(a, policy, ab_atts, export, ts_results, refused=None):
    """ab_atts: {decision_id: attachment} held; export: export doc held or None."""
    out = {"assertion": a.get("assertion"), "decision_id": a.get("decision_id"), "key_ref": a.get("signature", {}).get("key_ref")}
    if "stage_id" in a:
        out["stage_id"] = a["stage_id"]
    sig = a.get("signature", {})
    alg = sig.get("algorithm")
    entry = find_key(policy, sig.get("key_ref"))
    S = {"status": "failed", "key_ref": sig.get("key_ref"), "algorithm": alg, "reference_source": "trust_policy"}
    sig_ok = False
    facts = {}
    try:
        sb = person_signed_bytes(a)
    except Unencodable as ex:
        sb = None
        S["findings"] = ["the signed bytes cannot be built: %s" % ex]
    if refused:
        S["findings"] = [REFUSED % refused]
    elif sb is None:
        pass
    elif alg not in SUPPORTED_PERSON:
        S["status"] = "not_supported"; S["findings"] = ["algorithm %r is not supported" % alg]
    elif entry is None:
        S["findings"] = ["the policy does not list the key %r" % sig.get("key_ref")]
    elif entry.get("role") != "person":
        S["findings"] = ["the key is in role %s, not person" % entry.get("role")]
    elif entry.get("algorithm") != alg:
        S["findings"] = ["the label %r is not its entry's %r" % (alg, entry.get("algorithm"))]
    elif alg == "Ed25519":
        if "authenticator_data_b64" in sig or "client_data_json_b64" in sig:
            S["findings"] = ["an Ed25519 signature carries authenticator data"]
        else:
            v = _sig_value(a)
            sig_ok, why = (False, "value cannot be decoded") if v is None else ed25519_verify(entry, sb, v)
            if not sig_ok: S["findings"] = [why]
    else:
        sig_ok, why, facts = webauthn_verify(entry, sig, sb)
        if not sig_ok: S["findings"] = [why]
    if sig_ok:
        S["status"] = "verified"
    out["signature"] = S
    if facts:
        out["authenticator"] = facts
    # subject
    t = a.get("assertion")
    U = {"status": "verified"}
    actor, actor_reason = None, None
    if t in ("person_approval", "person_review", "person_standing_approval"):
        U["checked_against"] = "action_binding_attachment"
        att = ab_atts.get(a.get("decision_id"))
        if att is None:
            U = {"status": "not_checked", "checked_against": "action_binding_attachment",
                 "findings": ["the action-binding attachment of %s is not held" % a.get("decision_id")]}
            actor_reason = "not_held"
        else:
            st = {s.get("stage_id"): s for s in att.get("stages", [])}
            stage = st.get(a.get("stage_id"))
            f = []
            want = "standing_approval" if t == "person_standing_approval" else "outcome"
            if stage is None or stage.get("kind") != want:
                f.append("stage %r is not a%s %s stage" % (a.get("stage_id"), "n" if want == "outcome" else "", want))
            else:
                actor = stage.get("actor_ref")
                rv = st.get(stage.get("review_ref"))
                if rv is None or rv.get("kind") != "review":
                    f.append("the review the stage answers is not in the attachment")
                    rv = {}
                if t == "person_standing_approval":
                    if stage.get("bounds_digest") != a.get("bounds_digest"):
                        f.append("the stage's bounds_digest is not the signed one")
                    if rv and rv.get("shown_bounds_digest") != a.get("bounds_digest"):
                        f.append("the review was not shown the signed bounds digest")
                else:
                    if stage.get("outcome") != a.get("outcome"):
                        f.append("the stage's outcome is %r, the signed one %r" % (stage.get("outcome"), a.get("outcome")))
                    if rv and "shown_bounds_digest" in rv:
                        f.append("the review was shown bounds: no person type for such an outcome in this version")
                    elif rv and rv.get("shown_spec_digest") != a.get("shown_spec_digest"):
                        f.append("the review's shown digest is not the signed one")
                    if t == "person_approval" and stage.get("approved_spec_digest") != a.get("approved_spec_digest"):
                        f.append("the outcome's approved digest is not the signed one")
                if rv and rv.get("shown_view_digest") != a.get("shown_view_digest"):
                    f.append("the review's view digest is not the signed one (or one states none)")
            if f:
                U = {"status": "failed", "checked_against": "action_binding_attachment", "findings": f}
    elif t == "person_affirmation":
        U["checked_against"] = "export_entry"
        ent = None
        if export is not None:
            ent = next((e for e in export.get("entries", []) if e.get("decision_id") == a.get("decision_id")), None)
        if ent is None:
            U = {"status": "not_checked", "checked_against": "export_entry", "findings": ["no export entry of the record is held"]}
            actor_reason = "not_held"
        else:
            seal = ent.get("seal", {})
            if "affirmation_record_covered" in seal:
                U["covers_affirmation_record"] = seal["affirmation_record_covered"]
            if seal.get("seal_hash") != a.get("affirmed_digest"):
                U = {"status": "failed", "checked_against": "export_entry", "findings": ["affirmed_digest is not the entry's seal"]}
            c = ent.get("content", {})
            if c.get("availability") != "available":
                if U["status"] == "verified":
                    U = dict(U, status="unavailable", findings=["the covered bytes are unavailable"])
                actor_reason = "none_read"
            else:
                try:
                    cb = base64.b64decode(c.get("covered_bytes_b64", ""), validate=True)
                except Exception:
                    cb = None
                if cb is None or sha256_hex(cb) != seal.get("seal_hash"):
                    U = {"status": "failed", "checked_against": "export_entry", "findings": ["the covered bytes do not hash to the entry's seal"]}
                    actor_reason = "none_read"
                else:
                    try:
                        rec = strict_loads(cb)
                        actor = (rec.get("affirmation_record") or {}).get("actor_identity") if isinstance(rec, dict) else None
                        if actor is None:
                            actor_reason = "none_read"
                    except Unreadable:
                        actor_reason = "not_read"
    else:
        U = {"status": "failed", "findings": ["unknown assertion type"]}
    out["subject"] = U
    # key state
    if refused:
        K = key_state(entry or {}, a.get("signed_at"), [], refused)
    elif not sig_ok:
        K = {"status": "not_checked", "findings": ["the signature is not verified"]}
    else:
        K = key_state(entry, a.get("signed_at"), _ts_for(a, ts_results))
    out["key_state"] = K
    # identity
    I = {"status": "not_checked", "basis": "trust_policy"}
    if entry is not None and not refused:
        I["holder"] = entry.get("holder")
        if entry.get("identity_source_ref"):
            I["source_ref"] = entry["identity_source_ref"]
    if actor is not None:
        I["issuer_named"] = actor
    if refused:
        I.update(status="failed", findings=[REFUSED % refused])
    elif entry is None:
        I["findings"] = ["the policy does not list the key"]
    elif entry.get("role") != "person":
        I.update(status="failed", findings=["the policy binds the key to no person (role %s)" % entry.get("role")])
    elif not sig_ok:
        I["findings"] = ["the signature is not verified"]
    elif actor is None:
        I["findings"] = ["no actor read: %s" % (actor_reason or "none_read")]
        I["reason"] = actor_reason or "none_read"
    elif actor != entry.get("holder"):
        I.update(status="failed", consistency="inconsistent",
                 findings=["the holder the policy gives (%s) is not the actor the issuer names (%s)" % (entry.get("holder"), actor)])
    elif K["status"] != "verified":
        I["findings"] = ["the key's state when it signed is not verified"]
    elif not entry.get("identity_source_ref"):
        I.update(status="failed", findings=["the policy names no identity source for the key"])
    else:
        I.update(status="verified", consistency="consistent")
    out["identity"] = I
    st = [S["status"], U["status"], K["status"]]
    out["status"] = "verified" if all(x == "verified" for x in st) else (
        "failed" if "failed" in st else "not_supported" if "not_supported" in st else
        "unavailable" if "unavailable" in st else "not_checked")
    return out


def copy_agrees(att, s):
    copy = att.get("issuer_signature")
    v = att.get("profile_version")
    if v == "0.3.0":
        want = {"algorithm": s.get("signature", {}).get("algorithm"), "key_ref": s.get("signature", {}).get("key_ref"),
                "signed_bytes_ref": SBR, "sealed_at": s.get("sealed_at"), "value_b64": s.get("signature", {}).get("value_b64")}
    elif v == "0.2.0":
        want = {"algorithm": s.get("signature", {}).get("algorithm"), "key_ref": s.get("signature", {}).get("key_ref"),
                "signed_bytes_ref": SBR, "value_b64": s.get("signature", {}).get("value_b64")}
    else:
        return "not_checked", "an attachment of version %r: the copy is not compared" % (v,)
    if not isinstance(copy, dict) or set(copy) != set(want) or any(copy[k] != want[k] for k in want):
        return "failed", "the copy does not agree with the seal member for member"
    return "verified", None


def seal(s, policy, ab_atts, export, ts_results, refused=None):
    sig = s.get("signature", {})
    sd = s.get("sealed", {})
    out = {"sealed": sd, "key_ref": sig.get("key_ref")}
    entry = find_key(policy, sig.get("key_ref"))
    S = {"status": "failed", "key_ref": sig.get("key_ref"), "algorithm": sig.get("algorithm"), "reference_source": "trust_policy"}
    sig_ok = False
    try:
        sb = seal_signed_bytes(s)
    except Unencodable as ex:
        sb = None; S["findings"] = ["the signed bytes cannot be built: %s" % ex]
    if refused:
        S["findings"] = [REFUSED % refused]
    elif sb is None:
        pass
    elif sig.get("algorithm") != "Ed25519":
        S["status"] = "not_supported"; S["findings"] = ["algorithm %r is not supported for a seal" % sig.get("algorithm")]
    elif entry is None:
        S["findings"] = ["the policy does not list the key"]
    elif entry.get("role") != "organisation":
        S["findings"] = ["the key is in role %s, not organisation" % entry.get("role")]
    elif entry.get("algorithm") != sig.get("algorithm"):
        S["findings"] = ["the label %r is not its entry's %r" % (sig.get("algorithm"), entry.get("algorithm"))]
    else:
        kb, why = strict_key_bytes(entry)
        if kb is None:
            S["findings"] = [why]
        else:
            cst, cwhy = certificate_holds(entry, kb)
            S["certificate"] = cst
            if cst == "failed":
                S["findings"] = [cwhy]
            else:
                v = _sig_value(s)
                sig_ok, why = (False, "value cannot be decoded") if v is None else ed25519_verify(entry, sb, v)
                if not sig_ok: S["findings"] = [why]
    if sig_ok:
        S["status"] = "verified"
    out["signature"] = S
    k = sd.get("kind")
    U = {"status": "verified"}
    if k == "attachment":
        U["checked_against"] = "action_binding_attachment"
        att = ab_atts.get(sd.get("id"))
        if att is None:
            U = {"status": "not_checked", "checked_against": "action_binding_attachment", "findings": ["the attachment is not held"]}
        else:
            try:
                b = compact(att)
                if "issuer_signature" in att:
                    dg = sha256_hex(replace_string_value(b.decode("utf-8"), ["issuer_signature", "value_b64"]).encode("utf-8"))
                else:
                    dg = sha256_hex(b)
                if dg != sd.get("digest"):
                    U = {"status": "failed", "checked_against": "action_binding_attachment", "findings": ["the sealed digest is not the attachment's"]}
            except (UnicodeError, ValueError) as ex:
                U = {"status": "failed", "checked_against": "action_binding_attachment", "findings": ["the attachment has no bytes as issued: %s" % ex]}
            if "issuer_signature" not in att:
                U["embedded_copy"] = "not_checked"
                U.setdefault("findings", []).append("the attachment carries no copy of the seal")
            else:
                ec_, why = copy_agrees(att, s)
                U["embedded_copy"] = ec_
                if ec_ == "failed":
                    U["status"] = "failed"; U.setdefault("findings", []).append(why)
                elif why:
                    U.setdefault("findings", []).append(why)
    elif k == "record":
        U["checked_against"] = "export_entry"
        ent = None if export is None else next((e for e in export.get("entries", []) if e.get("decision_id") == sd.get("id")), None)
        if ent is None:
            U = {"status": "not_checked", "checked_against": "export_entry", "findings": ["no export entry of the record is held"]}
        elif ent.get("seal", {}).get("seal_hash") != sd.get("digest"):
            U = {"status": "failed", "checked_against": "export_entry", "findings": ["the sealed digest is not the entry's seal"]}
        elif ent.get("content", {}).get("availability") != "available":
            U = {"status": "unavailable", "checked_against": "export_entry", "findings": ["the covered bytes are unavailable"]}
        else:
            try:
                cb = base64.b64decode(ent["content"]["covered_bytes_b64"], validate=True)
                if sha256_hex(cb) != sd.get("digest"):
                    U = {"status": "failed", "checked_against": "export_entry", "findings": ["the covered bytes do not hash to the seal"]}
            except Exception:
                U = {"status": "failed", "checked_against": "export_entry", "findings": ["covered bytes cannot be decoded"]}
    elif k == "export":
        U["checked_against"] = "export"
        if export is None:
            U = {"status": "not_checked", "checked_against": "export", "findings": ["the export is not held"]}
        else:
            try:
                if sha256_hex(compact(export)) != sd.get("digest"):
                    U = {"status": "failed", "checked_against": "export", "findings": ["the sealed digest is not the export's"]}
            except UnicodeError as ex:
                U = {"status": "failed", "checked_against": "export", "findings": ["no bytes as issued: %s" % ex]}
    out["subject"] = U
    if refused:
        K = key_state(entry or {}, s.get("sealed_at"), [], refused)
    elif not sig_ok:
        K = {"status": "not_checked", "findings": ["the signature is not verified"]}
    else:
        K = key_state(entry, s.get("sealed_at"), _ts_for(s, ts_results))
    out["key_state"] = K
    st = [S["status"], U["status"], K["status"]]
    out["status"] = "verified" if all(x == "verified" for x in st) else (
        "failed" if "failed" in st else "not_supported" if "not_supported" in st else
        "unavailable" if "unavailable" in st else "not_checked")
    return out
