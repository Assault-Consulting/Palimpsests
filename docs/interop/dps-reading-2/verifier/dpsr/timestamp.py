"""An independent timestamp checked as anchoring 0.2.0 has it: an RFC 3161 token ("An independent timestamp")
or an OpenTimestamps proof ("An OpenTimestamps proof as a timestamp")."""
import datetime as _dt
import hashlib
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ots as O
from . import policy as P
from . import tsp as TSP
from .common import (CannotEncode, b64_strict, checkpoint_signed_bytes, combine, fmt_instant, hex_strict,
                     is_json_int, links, parse_stated, parse_utc, sha256, strict_loads, entry_digest)


def _refused(reason):
    return "not checked: the trust policy is refused (%s)" % reason


def subject_view(subject):
    """'The subject as the attachment states it, without its value.'"""
    if not isinstance(subject, dict):
        return {"kind": "seal"}
    out = {"kind": subject.get("kind")}
    for k in ("decision_id", "chain_id", "sequence", "of"):
        if k in subject:
            out[k] = subject[k]
    return out


def subject_value(subject):
    if subject.get("kind") in ("seal", "chain_link"):
        v = subject.get("value_hex")
        return bytes.fromhex(v) if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) else None
    if subject.get("kind") == "signature":
        return b64_strict(subject.get("value_b64"))
    return None


def held_verifies(cp, policy):
    """A held checkpoint counts only when its signature verifies over its own fields with the key the policy
    lists for its key_ref (T63-T66). Any malformed copy gives nothing and the check goes on."""
    try:
        if not isinstance(cp, dict):
            return False
        s = cp.get("signature")
        if not isinstance(s, dict) or s.get("algorithm") != "Ed25519":
            return False
        k = P.key(policy, s.get("key_ref"))
        if k is None:
            return False
        raw = hex_strict(k.get("public_key_hex"))
        sv = b64_strict(s.get("value_b64"))
        if raw is None or len(raw) != 32 or sv is None:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sv, checkpoint_signed_bytes(cp, s.get("key_ref")))
        return True
    except (CannotEncode, Exception):
        return False


def check_subject(subject, ctx):
    """Check 3, subject_bytes. Returns (status, finding, source) where source tells where the issuer's time is read."""
    kind = subject.get("kind")
    export = ctx["export"]
    if kind == "seal":
        did = subject.get("decision_id")
        ents = [(i, e) for i, e in enumerate(export.get("entries", [])) if e.get("decision_id") == did]
        if not ents:
            return "not_checked", "the export holds no record %s" % did, None
        i, e = ents[0]
        if entry_digest(e) != subject.get("value_hex"):
            return "failed", "the subject's value is not the seal_hash of %s in the export" % did, None
        return "verified", None, ("seal", i)
    if kind == "chain_link":
        if subject.get("chain_id") != ctx["chain_id"]:
            return "not_checked", "a link of another chain than the one the verifier checks", None
        seq = subject.get("sequence")
        if not is_json_int(seq):
            return "failed", "sequence %r is not written as a JSON integer" % (seq,), None
        ls = links(export)
        if seq < 0 or seq >= len(ls):
            return "not_checked", "link(%d) cannot be recomputed from an export of %d entries" % (seq, len(ls)), None
        if ls[seq].hex() != subject.get("value_hex"):
            return "failed", "link(%d) recomputed from the export is not the subject's value" % seq, None
        return "verified", None, ("chain_link", seq)
    if kind == "signature":
        of = subject.get("of") or {}
        if of.get("assertion") != "checkpoint":
            return "not_checked", "an assertion of the signatures profile: that profile checks the subject", None
        val = b64_strict(subject.get("value_b64"))
        held = [c for c in ctx["held"] if held_verifies(c, ctx["policy"])]
        def names(c):
            return (c["signature"].get("key_ref") == of.get("key_ref") and c.get("chain_id") == of.get("chain_id")
                    and c.get("count") == of.get("count") and type(c.get("count")) is type(of.get("count")))
        carriers = [c for c in held if b64_strict(c["signature"].get("value_b64")) == val]
        both = [c for c in carriers if names(c)]
        if both:
            return "verified", None, ("checkpoint", both[0])
        if carriers or any(names(c) for c in held):
            return "failed", "the signature value is not that of the checkpoint the subject names", None
        return "not_checked", "no checkpoint whose signature verifies carries this value", None
    return "not_checked", "unknown subject kind", None


def issuer_time(src, ctx, T):
    """Compare the issuer's own time for the subject with T (README, after the seven checks)."""
    def rec_time(i):
        e = ctx["export"]["entries"][i]
        c = e.get("content") or {}
        if c.get("availability") != "available":
            return None, "the record's covered bytes are not available"
        b = b64_strict(c.get("covered_bytes_b64"))
        if b is None or sha256(b).hex() != entry_digest(e):
            return None, "the covered bytes are not those whose SHA-256 is the entry's seal"
        try:
            rec = strict_loads(b)
            st = rec["affirmation_record"]["timestamp"]
        except Exception:
            return None, "affirmation_record.timestamp cannot be read from the covered bytes"
        t = parse_stated(st)
        if t is None:
            return None, "affirmation_record.timestamp is not a time that can be read"
        return (st, t), None

    if src is None:
        return {"status": "not_checked", "findings": ["the subject's bytes are not verified"]}
    kind = src[0]
    if kind == "seal":
        v, why = rec_time(src[1])
        if v is None:
            return {"status": "not_checked", "findings": [why]}
        stated, t, stated_in = v[0], v[1], "affirmation_record.timestamp"
    elif kind == "chain_link":
        best = None
        for i in range(src[1] + 1):
            v, why = rec_time(i)
            if v is None:
                return {"status": "not_checked", "findings": ["entry %d: %s" % (i, why)]}
            if best is None or v[1] > best[1]:
                best = v
        stated, t, stated_in = best[0], best[1], "affirmation_record.timestamp"
    else:
        cp = src[1]
        t = parse_utc(cp.get("checkpoint_time"))
        if t is None:
            return {"status": "not_checked", "findings": ["checkpoint_time is not a real UTC time, so it is not compared"]}
        stated, stated_in = cp["checkpoint_time"], "checkpoint_time"
    if t > T:
        return {"status": "failed", "stated": stated, "stated_in": stated_in, "consistency": "inconsistent",
                "findings": ["the issuer's time is later than the timestamp's time"]}
    return {"status": "verified", "stated": stated, "stated_in": stated_in, "consistency": "consistent"}


def check_rfc3161(ts, idx, ctx):
    subj = ts.get("subject") or {}
    res = {"timestamp_index": idx, "subject": subject_view(subj), "status": None, "tsa_ref": ts.get("tsa_ref")}
    findings = []
    checks = {}
    val = subject_value(subj)
    sb, why, src = check_subject(subj, ctx)
    if why:
        findings.append("subject_bytes: " + why)
    der = b64_strict(ts.get("token_b64"))
    p, why = TSP.parse_token(der) if der is not None else (None, "token_b64 is not padded base64")
    internal = {"_format": "rfc3161"}
    if p is None:
        checks = {"token": "failed", "message_imprint": "not_checked", "subject_bytes": sb, "message_digest": "not_checked",
                  "tsa_signature": "not_checked", "signer_certificate": "not_checked", "tsa_state": "not_checked"}
        findings.append("token: " + why)
    else:
        checks["token"] = "verified"
        internal["_imprint"] = p["tst"]["message_imprint"]["hashed_message"].native
        st, why = TSP.check_imprint(p, val if val is not None else b"")
        if val is None:
            st, why = "failed", "the subject states no value"
        checks["message_imprint"] = st
        if why:
            findings.append("message_imprint: " + why)
        checks["subject_bytes"] = sb
        st, why = TSP.check_message_digest(p)
        checks["message_digest"] = st
        if why:
            findings.append("message_digest: " + why)
        entry = P.tsa(ctx["policy"], ts.get("tsa_ref"))
        if not ctx["policy_ok"]:
            checks.update(tsa_signature="failed", signer_certificate="not_checked", tsa_state="failed")
            findings.append("tsa_signature, tsa_state: " + _refused(ctx["policy_reason"]))
        elif entry is None:
            checks.update(tsa_signature="failed", signer_certificate="not_checked", tsa_state="not_checked")
            findings.append("tsa_signature: the authority %r is not in the trust policy" % ts.get("tsa_ref"))
        else:
            pinned = TSP.load_pinned(entry)
            if pinned is None:
                checks.update(tsa_signature="failed", signer_certificate="not_checked")
                findings.append("tsa_signature: the pinned certificate cannot be read")
            else:
                st, why = TSP.check_signature(p, pinned)
                checks["tsa_signature"] = st
                if why:
                    findings.append("tsa_signature: " + why)
                st, why = TSP.check_signer_certificate(p, pinned)
                checks["signer_certificate"] = st
                if why:
                    findings.append("signer_certificate: " + why)
            st, why = TSP.check_tsa_state(entry, p["gen"])
            checks["tsa_state"] = st
            if why:
                findings.append("tsa_state: " + why)
    order = ["token", "message_imprint", "subject_bytes", "message_digest", "tsa_signature", "signer_certificate", "tsa_state"]
    checks = {k: checks[k] for k in order}
    status = combine([v for k, v in checks.items() if not (k == "signer_certificate" and v == "not_checked")])
    res["status"] = status
    if status == "verified":
        res["reference_source"] = "trust_policy"
        res["gen_time"] = fmt_instant(p["gen"])
        res["existed_no_later_than"] = fmt_instant(p["T"])
        internal["_T"] = p["T"]
        it = issuer_time(src, ctx, p["T"])
    else:
        it = {"status": "not_checked", "findings": ["the timestamp is not verified"]}
    res["checks"] = checks
    res["issuer_time"] = it
    if findings:
        res["findings"] = findings
    res.update(internal)
    return res


def check_ots(ts, idx, ctx):
    subj = ts.get("subject") or {}
    res = {"timestamp_index": idx, "subject": subject_view(subj), "format": "opentimestamps", "status": None}
    findings = []
    checks = {"proof": "not_checked", "subject_bytes": "not_checked", "operations": "not_checked",
              "attestation": "not_checked", "header": "not_checked"}
    val = subject_value(subj)
    sb, why, _src = check_subject(subj, ctx)
    if why:
        findings.append("subject_bytes: " + why)
    data = b64_strict(ts.get("proof_b64"))
    parsed = None
    try:
        if data is None:
            raise O.ProofError("proof_b64 is not padded base64")
        parsed = O.parse(data)
        checks["proof"] = "verified"
    except O.ProofError as e:
        checks["proof"] = "failed"
        findings.append("proof: not read: %s" % e)
    except RecursionError:
        checks["proof"] = "failed"
        findings.append("proof: not read: timestamps nested deeper than 256")
    if parsed is not None:
        _op, digest, root = parsed
        if val is None or digest != hashlib.sha256(val).digest():
            sb = "failed"
            findings.append("subject_bytes: the proof does not start from the SHA-256 of the subject's bytes")
    checks["subject_bytes"] = sb
    block = None
    if parsed is not None:
        atts = O.replay(root, digest)
        btc = [a for a in atts if a["tag"] == O.TAG_BITCOIN]
        pend = [a for a in atts if a["tag"] == O.TAG_PENDING]
        unknown = [a for a in atts if a["tag"] not in (O.TAG_BITCOIN, O.TAG_PENDING)]
        for a in unknown:
            findings.append("attestation: an attestation of a kind this check does not know (tag %s) skipped by its length" % a["tag"].hex())
        usable = [a for a in btc if not a["unsupported"]]
        if btc and not usable:
            checks["operations"] = "not_supported"
            findings.append("operations: an operation other than sha256, append or prepend on the way (%s)" %
                            ", ".join(sorted(set(sum((a["unsupported"] for a in btc), [])))))
        elif not btc and any(a["unsupported"] for a in atts):
            checks["operations"] = "not_supported"
            findings.append("operations: an operation other than sha256, append or prepend on the way")
        else:
            checks["operations"] = "verified"
            if len(usable) < len(btc):
                findings.append("operations: a Bitcoin branch with another operation is not replayed")
        if checks["operations"] == "verified":
            heights = []
            errs = []
            for a in usable:
                try:
                    heights.append((O.bitcoin_height(a["payload"]), a))
                except O.ProofError as e:
                    errs.append(str(e))
            if heights:
                checks["attestation"] = "verified"
            elif errs:
                checks["attestation"] = "failed"
                findings.append("attestation: " + "; ".join(errs))
            elif pend:
                checks["attestation"] = "unavailable"
                findings.append("attestation: pending attestations only, a calendar's promise not yet in a block")
            else:
                checks["attestation"] = "failed"
                findings.append("attestation: no Bitcoin attestation")
            if checks["attestation"] == "verified":
                hs = ctx["policy"].get("bitcoin_header_sources")
                held = ctx.get("headers")
                if not hs:
                    checks["header"] = "not_checked"
                    findings.append("header: the trust policy names no Bitcoin header source")
                elif held is None or held["source_ref"] not in [s.get("source_ref") for s in hs]:
                    checks["header"] = "unavailable"
                    findings.append("header: no header from a source the policy names")
                else:
                    match, mism, missing = [], [], []
                    for h, a in heights:
                        hb = held["headers"].get(h)
                        if hb is None:
                            missing.append(h)
                            continue
                        if len(hb) == 80 and hb[36:68] == a["digest"]:
                            match.append((h, hb))
                        elif len(hb) == 80 and hb[36:68] == a["digest"][::-1]:
                            mism.append(h)
                            findings.append("header: block %d holds the proof's result only in the reverse byte order, as explorers show it; the header's own bytes 36 to 67 differ" % h)
                        else:
                            mism.append(h)
                            findings.append("header: block %d's Merkle root is not the proof's result" % h)
                    if match:
                        h, hb = min(match, key=lambda x: x[0])
                        checks["header"] = "verified"
                        ntime = int.from_bytes(hb[68:72], "little")
                        block = {"height": h, "hash_hex": hashlib.sha256(hashlib.sha256(hb).digest()).digest()[::-1].hex(),
                                 "header_source_ref": held["source_ref"]}
                        mst = fmt_instant(_dt.datetime.fromtimestamp(ntime, _dt.timezone.utc))
                    elif missing:
                        checks["header"] = "unavailable"
                        findings.append("header: no header held for block(s) %s" % ", ".join(map(str, missing)))
                    else:
                        checks["header"] = "failed"
    status = combine(list(checks.values()))
    res["status"] = status
    res["checks"] = checks
    if status == "verified":
        res["block"] = block
        res["miner_stated_time"] = mst
    res["issuer_time"] = {"status": "not_checked", "findings": [
        "an OpenTimestamps proof gives no time the bytes existed by: no issuer's time is compared with it"]}
    if findings:
        res["findings"] = findings
    res["_format"] = "opentimestamps"
    return res


def check(ts, idx, ctx):
    if isinstance(ts, dict) and ts.get("format") == "opentimestamps":
        return check_ots(ts, idx, ctx)
    return check_rfc3161(ts, idx, ctx)
