"""A checkpoint checked as anchoring 0.2.0 has it ("An independent checkpoint", "A checkpoint beside the export",
"A transparency service as a checkpoint source")."""
import hashlib
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import cbor_strict as cb
from . import policy as P
from .common import (CannotEncode, MAX_SAFE, b64_strict, checkpoint_signed_bytes, combine, hex_strict,
                     is_json_int, links, parse_signed_bytes, signed_time_form, fmt_instant)

BESIDE_FINDING = "carried beside the export: the issuer chose which checkpoint to carry, so it is never independent"
EXPORT_FINDING = "found in the export: the issuer chose which checkpoint to carry, so it is never independent"


def _refused(reason):
    return "not checked: the trust policy is refused (%s)" % reason


def _ed25519_verify(key_entry, sig, data):
    """Returns (ok, finding). The key is read strictly ('lowercase hex pairs and nothing else')."""
    raw = hex_strict(key_entry.get("public_key_hex"))
    if raw is None or len(raw) != 32:
        return False, "the policy's public_key_hex is not 32 bytes of lowercase hex, read strictly"
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, data)
        return True, None
    except Exception:
        return False, "the signature does not verify over the bytes the verifier builds"


def report_values(chain_id, count, head_link, checkpoint_time):
    """'The values as obtained', leaving out a value the report schema cannot carry (K128-K136)."""
    out = {}
    if isinstance(chain_id, str) and len(chain_id) >= 1:
        out["chain_id"] = chain_id
    if is_json_int(count) and 1 <= count <= MAX_SAFE:
        out["count"] = count
    if isinstance(head_link, str) and re.fullmatch(r"[0-9a-f]{64}", head_link):
        out["head_link"] = head_link
    if isinstance(checkpoint_time, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z", checkpoint_time):
        out["checkpoint_time"] = checkpoint_time
    if "count" not in out or "head_link" not in out:
        return None
    return out


def covering(ts_results, sig_value):
    """Verified RFC 3161 timestamps whose imprint is the SHA-256 of this signature value (OpenTimestamps proofs
    never count: 'no key state rests on it')."""
    if sig_value is None:
        return []
    h = hashlib.sha256(sig_value).digest()
    out = []
    for r in ts_results:
        if r.get("_format") == "rfc3161" and r.get("status") == "verified" and r.get("_imprint") == h \
                and r.get("subject", {}).get("kind") == "signature":
            out.append((r["_T"], r["timestamp_index"]))
    return out


def compare(export, count, head_link):
    """'the links recomputed from the export's seals ... must give head_link at entry count - 1'."""
    ls = links(export)
    n = len(export.get("entries", []))
    if len(ls) < n:
        return "failed", None, ["an entry's digest cannot be read"]
    if n < count:
        return "failed", None, ["the export has %d entries, fewer than the checkpoint's count %d" % (n, count)]
    if ls[count - 1].hex() != head_link:
        return "failed", None, ["link(%d) recomputed from the export is not the checkpoint's head_link" % (count - 1)]
    return "verified", list(range(count, n)), []


def _key_listing_rule(ctx, key_ref, src, fmt):
    """Which listings make a key usable. fmt 'dps' (shared rule) or 'scitt'. src: the configured source, or None
    for a checkpoint beside the export or in it (then: a source the policy configures for the chain the verifier
    checks). Returns a finding when the key may not be used, else None."""
    pol = ctx["policy"]
    w_any, s_any = P.key_listings(pol, key_ref)
    if w_any and s_any:
        return ("the key %s is listed both for checkpoints under the shared rule and for SCITT statements: "
                "one key, one purpose (RFC 9943 section 9.4)" % key_ref)
    if src is not None:
        if key_ref not in (src.get("key_refs") or []):
            return "the key %s is not listed for the source %s" % (key_ref, src.get("source_ref"))
        return None
    chain = ctx["chain_id"]
    ok = False
    for s in pol.get("checkpoint_sources", []) or []:
        if chain in (s.get("chain_ids") or []) and key_ref in (s.get("key_refs") or []):
            if (fmt == "dps" and P.is_witness_src(s)) or (fmt == "scitt" and P.is_scitt(s)):
                ok = True
    if ok:
        return None
    if fmt == "dps" and s_any:
        return "the key %s is listed for SCITT statements only" % key_ref
    if fmt == "scitt" and w_any:
        return "the key %s is listed for checkpoints under the shared rule only" % key_ref
    return "the key %s is not listed for a source the policy configures for the chain %s" % (key_ref, chain)


def check(item, index, ctx):
    """item: {'type': 'plain'|'scitt'|'issuer'|None, 'checkpoint', 'statement', 'receipt', 'obtained_from',
    'source_ref', 'attachment_index'}. ctx: policy, policy_ok, policy_reason, chain_id, export, ts_results."""
    pol = ctx["policy"]
    ofrom = item["obtained_from"]
    sref = item.get("source_ref")
    typ = item.get("type")
    res = {"checkpoint_index": index, "obtained_from": ofrom}
    if sref is not None and ofrom != "beside_export":
        res["source_ref"] = sref
    src = P.source(pol, sref) if (sref is not None and ofrom == "configured_source") else None
    values = {}   # chain_id, count, head_link, checkpoint_time as read
    refused_values = False
    internal = {"sig_value": None, "fmt": "dps"}
    sig = {"status": "not_checked"}
    receipt = None
    statement_read = False

    # ---- read and check the signature ----
    if typ is None:
        sig = {"status": "not_checked", "findings": ["the source gave no checkpoint"]}
    elif typ == "issuer":
        cp = item["checkpoint"]
        values = {k: cp.get(k) for k in ("chain_id", "count", "head_link", "checkpoint_time")}
        sig = {"status": "not_checked", "findings": ["the issuer's checkpoint carries no signature"]}
    elif typ == "plain":
        cp = item["checkpoint"] if isinstance(item["checkpoint"], dict) else {}
        values = {k: cp.get(k) for k in ("chain_id", "count", "head_link", "checkpoint_time")}
        s = cp.get("signature") if isinstance(cp.get("signature"), dict) else {}
        key_ref = s.get("key_ref")
        sv = b64_strict(s.get("value_b64"))
        internal["sig_value"] = sv
        sig = _check_plain_sig(ctx, src, sref, ofrom, cp, s, key_ref, sv)
    elif typ == "scitt":
        internal["fmt"] = "scitt"
        sig, values, refused_values, statement_read, internal = _check_statement(ctx, src, sref, ofrom, item, internal)

    # ---- independence ----
    if ofrom == "same_export":
        ind = {"status": "failed", "findings": [EXPORT_FINDING]}
    elif ofrom == "beside_export":
        ind = {"status": "failed", "findings": [BESIDE_FINDING]}
    elif not ctx["policy_ok"]:
        ind = {"status": "failed", "findings": [_refused(ctx["policy_reason"])]}
    elif src is None:
        ind = {"status": "failed", "findings": ["the source %r is not configured in the trust policy" % sref]}
    else:
        # no checkpoint, or a statement that could not be read: the source is judged for the chain the verifier
        # checks (K25, K109-K114, K125; ambiguity log A16)
        chain = values.get("chain_id") if (typ is not None and values) else ctx["chain_id"]
        if not isinstance(chain, str) or chain not in (src.get("chain_ids") or []):
            ind = {"status": "failed", "findings": ["the trust policy does not configure the source %s for the chain %r" % (sref, chain)]}
        else:
            ind = {"status": "verified"}

    # ---- key state ----
    key_ref = sig.get("key_ref") if sig.get("status") == "verified" else None
    if sig.get("status") == "verified":
        ks = P.key_state(pol, key_ref, values.get("checkpoint_time"), covering(ctx["ts_results"], internal["sig_value"]))
    elif not ctx["policy_ok"] and typ not in (None, "issuer") and sig.get("_policy_refused"):
        ks = {"status": "failed", "findings": [_refused(ctx["policy_reason"])]}
    else:
        ks = {"status": "not_checked", "findings": ["the signature is not verified"]}
    for _k in [k for k in sig if k.startswith("_")]:
        del sig[_k]

    # ---- receipt (SCITT) ----
    if typ == "scitt":
        receipt = _check_receipt(ctx, src, ofrom, item, statement_read, internal)

    dims = [ind["status"], sig["status"], ks["status"]]
    if receipt is not None:
        dims.append(receipt["status"])
    status = combine(dims)
    if typ is None and status != "failed":
        status = "unavailable"
    if ofrom in ("same_export", "beside_export"):
        status = "failed"

    res["status"] = status
    rv = report_values(values.get("chain_id"), values.get("count"), values.get("head_link"), values.get("checkpoint_time")) if typ is not None else None
    if rv is not None:
        res["checkpoint"] = rv
    res["independence"] = ind
    res["signature"] = sig
    res["key_state"] = ks

    # ---- comparison ----
    if ofrom == "beside_export":
        res["comparison"] = {"status": "not_checked", "findings": ["a checkpoint beside the export is never compared as an independent one"]}
    elif status != "verified":
        res["comparison"] = {"status": "not_checked", "findings": ["the checkpoint is not verified"]}
    elif values.get("chain_id") != ctx["chain_id"]:
        res["comparison"] = {"status": "not_checked", "findings": ["a checkpoint for another chain than the one the verifier checks"]}
    else:
        st, nc, f = compare(ctx["export"], values["count"], values["head_link"])
        res["comparison"] = {"status": st, "findings": f} if st != "verified" else {"status": st, "covered_count": values["count"], "not_covered_indexes": nc}

    if ofrom == "beside_export":
        if sig["status"] == "verified" and ks["status"] == "verified" and values.get("chain_id") == ctx["chain_id"]:
            st, nc, f = compare(ctx["export"], values["count"], values["head_link"])
            if st == "verified":
                pre = {"status": "verified", "covered_count": values["count"], "not_covered_indexes": nc,
                       "time_basis": ks["time_basis"], "time": ks["time"]}
                if ks["time_basis"] == "independent_timestamp":
                    pre["timestamp_index"] = ks["timestamp_index"]
            else:
                pre = {"status": "failed", "findings": f}
        else:
            why = "the signature and the key's state are not both verified" if values.get("chain_id") == ctx["chain_id"] or sig["status"] != "verified" else "a checkpoint for another chain than the one the verifier checks"
            pre = {"status": "not_checked", "findings": [why]}
        res["prefix"] = pre
        res["freshness"] = "not_established"
        if item.get("attachment_index") is not None:
            res["attachment_index"] = item["attachment_index"]
    if typ == "scitt":
        res["format"] = "scitt"
        res["receipt"] = receipt
        res["log_consistency"] = {"status": "not_checked", "findings": [
            "a consistency proof against a root the verifier holds is not in this version"]}
    for d in (res["independence"], res["signature"], res["key_state"], res["comparison"]):
        if "findings" in d and not d["findings"]:
            del d["findings"]
    res["_values"] = values
    return res


def _check_plain_sig(ctx, src, sref, ofrom, cp, s, key_ref, sv):
    pol = ctx["policy"]
    out = {"status": "failed"}
    if isinstance(key_ref, str):
        out["key_ref"] = key_ref
    if not ctx["policy_ok"]:
        out.update(findings=[_refused(ctx["policy_reason"])], _policy_refused=True)
        return out
    if src is not None:
        if src.get("kind") == "transparency_log" and src.get("format") != "scitt":
            out.update(status="not_supported", findings=["a transparency log that names no format: this version reads nothing from it"])
            return out
        if src.get("kind") == "third_party":
            out.update(status="not_supported", findings=["a third party as a source: this version defines none"])
            return out
        if P.is_scitt(src):
            out.update(findings=["a plain checkpoint given by a SCITT source, which gives signed statements"])
            return out
    if s.get("algorithm") != "Ed25519":
        out.update(status="not_supported", findings=["signature algorithm %r is not Ed25519" % (s.get("algorithm"),)])
        return out
    k = P.key(pol, key_ref)
    if k is None:
        out.update(findings=["the key %r is not in the trust policy" % (key_ref,)])
        return out
    if k.get("role") != "witness":
        out.update(findings=["the key %s is in role %s: only a witness key signs a checkpoint" % (key_ref, k.get("role"))])
        return out
    why = _key_listing_rule(ctx, key_ref, src, "dps")
    if why:
        out.update(findings=[why])
        return out
    try:
        data = checkpoint_signed_bytes(cp, key_ref)
    except CannotEncode as e:
        out.update(findings=["the shared rule cannot encode a value: %s" % e])
        return out
    if sv is None:
        out.update(findings=["the signature value is not padded base64"])
        return out
    ok, why = _ed25519_verify(k, sv, data)
    if not ok:
        out.update(findings=[why])
        return out
    return {"status": "verified", "key_ref": key_ref, "reference_source": "trust_policy"}


def _check_statement(ctx, src, sref, ofrom, item, internal):
    """The SCITT signed statement. Returns sig, values, refused_values, statement_read, internal."""
    pol = ctx["policy"]
    values = {}
    out = {"status": "failed"}
    stb = item.get("statement")
    internal["statement_bytes"] = stb
    try:
        if stb is None:
            raise cb.CborError("statement_b64 is not padded base64")
        st = cb.loads(stb)
        if not isinstance(st, cb.Tag) or st.tag != 18:
            raise cb.CborError("not tagged 18 (COSE_Sign1)")
        arr = st.value
        if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and isinstance(arr[1], dict)
                and isinstance(arr[2], bytes) and isinstance(arr[3], bytes)):
            raise cb.CborError("not a COSE_Sign1 with an attached payload")
        prot = cb.loads(arr[0]) if arr[0] else {}
        if not isinstance(prot, dict):
            raise cb.CborError("protected header is not a map")
    except cb.CborError as e:
        out["findings"] = ["the statement is not read: %s" % e]
        return out, values, False, False, internal
    payload, sigv = arr[2], arr[3]
    internal["sig_value"] = sigv
    try:
        f = parse_signed_bytes(payload, 8)
        prof, ver, typ = (x.decode("utf-8") for x in f[0:3])
        if (prof, ver, typ) != ("dps-anchoring", "0.2.0", "checkpoint"):
            raise ValueError("profile, version or assertion type is not dps-anchoring 0.2.0 checkpoint")
        key_ref = f[3].decode("utf-8")
        chain_id = f[4].decode("utf-8")
        if len(f[5]) != 8 or len(f[6]) != 32:
            raise ValueError("count is not 8 bytes or head_link not 32")
        count = int.from_bytes(f[5], "big")
        head = f[6].hex()
        ctime = f[7].decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        out["findings"] = ["the payload is not a checkpoint's signed bytes under the shared rule, not read: %s" % e]
        return out, values, False, False, internal
    values = {"chain_id": chain_id, "count": count, "head_link": head, "checkpoint_time": ctime}
    statement_read = True
    out["_statement_read"] = True
    # held to the checkpoint schema's rules
    refusals = []
    if not (1 <= len(chain_id) <= 256):
        refusals.append("chain_id of %d characters, not 1 to 256" % len(chain_id))
        values["chain_id"] = None
    if not signed_time_form(ctime):
        refusals.append("checkpoint_time %r is not in the form YYYY-MM-DDTHH:MM:SSZ" % ctime)
        values["checkpoint_time"] = None
    if not (1 <= count <= MAX_SAFE):
        refusals.append("count %d is not from 1 to 2^53 - 1" % count)
        values["count"] = None
    if not (1 <= len(key_ref) <= 256):
        refusals.append("key_ref (kid) of %d characters, not 1 to 256" % len(key_ref))
        key_ref = None
    if key_ref is not None:
        out["key_ref"] = key_ref
    if not ctx["policy_ok"]:
        out.update(findings=[_refused(ctx["policy_reason"])], _policy_refused=True)
        return out, values, bool(refusals), statement_read, internal
    if src is not None and not P.is_scitt(src):
        if src.get("kind") == "transparency_log":
            out.update(status="not_supported", findings=["a transparency log that names no format: this version reads nothing from it"])
        else:
            out.update(findings=["a SCITT statement is not what a %s source gives" % src.get("kind")])
        out["_wrong_source"] = True
        return out, values, bool(refusals), statement_read, internal
    if refusals:
        out["findings"] = ["the payload is outside the checkpoint schema's rules: " + "; ".join(refusals)]
        return out, values, True, statement_read, internal
    alg = prot.get(1)
    if alg == -8:
        out.update(status="not_supported", findings=["alg -8 (EdDSA), deprecated by RFC 9864: a statement is pinned to -19"])
        return out, values, False, statement_read, internal
    if alg != -19:
        out["findings"] = ["alg %r is not -19 (Ed25519)" % (alg,)]
        return out, values, False, statement_read, internal
    if 2 in prot:
        out["findings"] = ["a crit header this check does not know"]
        return out, values, False, statement_read, internal
    kid = prot.get(4)
    if isinstance(kid, bytes):
        try:
            kid = kid.decode("utf-8")
        except UnicodeDecodeError:
            kid = None
    if kid != key_ref:
        out["findings"] = ["kid is not the payload's key_ref"]
        return out, values, False, statement_read, internal
    claims = prot.get(15)
    k = P.key(pol, key_ref)
    if k is None:
        out["findings"] = ["the key %r is not in the trust policy" % key_ref]
        return out, values, False, statement_read, internal
    if not isinstance(claims, dict) or not isinstance(claims.get(1), str) or claims.get(1) != k.get("holder"):
        out["findings"] = ["iss is missing or is not the key's holder as the policy names it"]
        return out, values, False, statement_read, internal
    if claims.get(2) != chain_id:
        out["findings"] = ["sub is not the payload's chain_id"]
        return out, values, False, statement_read, internal
    if k.get("role") != "witness":
        out["findings"] = ["the key %s is in role %s: only a witness key signs a statement" % (key_ref, k.get("role"))]
        return out, values, False, statement_read, internal
    why = _key_listing_rule(ctx, key_ref, src, "scitt")
    if why:
        out["findings"] = [why]
        return out, values, False, statement_read, internal
    ok, why = _ed25519_verify(k, sigv, cb.sig_structure(arr[0], payload))
    if not ok:
        out["findings"] = [why + " (Sig_structure)"]
        return out, values, False, statement_read, internal
    return ({"status": "verified", "key_ref": key_ref, "reference_source": "trust_policy", "_statement_read": True},
            values, False, statement_read, internal)


def _inclusion_root(leaf_hash, leaf_index, tree_size, path):
    """RFC 9162 2.1.3.2: verify an inclusion proof and return the root, or None."""
    if leaf_index >= tree_size:
        return None
    fn, sn, r = leaf_index, tree_size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None
    return r


def _check_receipt(ctx, src, ofrom, item, statement_read, internal):
    pol = ctx["policy"]
    if not statement_read:
        return {"status": "not_checked", "findings": ["the statement is not read"]}
    if ofrom == "configured_source" and (src is None or not P.is_scitt(src)):
        return {"status": "not_checked", "findings": ["the source is not a SCITT transparency service"]}
    rb = item.get("receipt")
    if rb is None:
        return {"status": "unavailable", "findings": ["no receipt held: the registration is not shown"]}
    out = {"status": "failed"}
    findings = []
    try:
        r = cb.loads(rb)
        if not isinstance(r, cb.Tag) or r.tag != 18:
            raise cb.CborError("not tagged 18")
        arr = r.value
        if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and isinstance(arr[1], dict)
                and arr[2] is None and isinstance(arr[3], bytes)):
            raise cb.CborError("not a COSE_Sign1 with a detached payload")
        prot = cb.loads(arr[0]) if arr[0] else {}
        if not isinstance(prot, dict):
            raise cb.CborError("protected header is not a map")
    except cb.CborError as e:
        out["findings"] = ["the receipt is not read: %s" % e]
        return out
    alg = prot.get(1)
    if alg == -8:
        findings.append("alg -8 (EdDSA), deprecated by RFC 9864 in favour of -19: verified as -19")
    elif alg != -19:
        return {"status": "not_supported", "findings": ["receipt alg %r is not supported" % (alg,)]}
    if prot.get(395) != 1:
        return {"status": "not_supported" if 395 in prot else "failed",
                "findings": ["verifiable data structure %r is not the RFC 9162 SHA-256 tree (1)" % (prot.get(395),)]}
    kid = prot.get(4)
    if isinstance(kid, bytes):
        try:
            kid = kid.decode("utf-8")
        except UnicodeDecodeError:
            kid = None
    k = P.key(pol, kid) if isinstance(kid, str) else None
    if k is None:
        return {"status": "failed", "findings": findings + ["the receipt's kid %r is not a key in the trust policy" % (kid,)]}
    if k.get("role") != "transparency_service":
        return {"status": "failed", "findings": findings + ["the key %s is in role %s: it signs no receipt" % (kid, k.get("role"))]}
    if ofrom == "configured_source":
        listed = kid in (src.get("service_key_refs") or [])
    else:
        listed = any(P.is_scitt(s) and ctx["chain_id"] in (s.get("chain_ids") or []) and kid in (s.get("service_key_refs") or [])
                     for s in pol.get("checkpoint_sources", []) or [])
    if not listed:
        return {"status": "failed", "findings": findings + ["the service key %s is not listed for the source" % kid]}
    if k.get("algorithm") != "Ed25519":
        return {"status": "not_supported", "findings": findings + ["the service key is listed under %r, not Ed25519" % k.get("algorithm")]}
    if "revoked_at" in k:
        return {"status": "unavailable", "findings": findings + ["the service key was revoked (%s): a receipt states no time, so it cannot be shown made before" % k.get("revocation_reason")]}
    try:
        proofs = arr[1].get(396, {}).get(-1) if isinstance(arr[1].get(396), dict) else None
        if not isinstance(proofs, list) or not proofs or not isinstance(proofs[0], bytes):
            return {"status": "failed", "findings": findings + ["no inclusion proof"]}
        pr = cb.loads(proofs[0])
        if not (isinstance(pr, list) and len(pr) == 3 and all(isinstance(x, int) for x in pr[:2])
                and isinstance(pr[2], list) and all(isinstance(x, bytes) and len(x) == 32 for x in pr[2])):
            return {"status": "failed", "findings": findings + ["the inclusion proof is not [tree-size, leaf-index, path]"]}
    except cb.CborError as e:
        return {"status": "failed", "findings": findings + ["the inclusion proof is not read: %s" % e]}
    tree_size, leaf_index, path = pr
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        return {"status": "failed", "findings": findings + ["leaf index %d is not below tree size %d" % (leaf_index, tree_size)]}
    leaf = hashlib.sha256(b"\x00" + internal["statement_bytes"]).digest()
    root = _inclusion_root(leaf, leaf_index, tree_size, path)
    if root is None:
        return {"status": "failed", "findings": findings + ["the path does not lead from the leaf to a root"]}
    ok, why = _ed25519_verify(k, arr[3], cb.sig_structure(arr[0], root))
    if not ok:
        return {"status": "failed", "findings": findings + ["the service did not sign the root the path leads to for this statement"]}
    out = {"status": "verified", "service_key_ref": kid, "tree_size": tree_size, "leaf_index": leaf_index}
    if findings:
        out["findings"] = findings
    return out


def conflicts(results):
    """'Two checkpoints of one chain and count, each with its signature and key state verified, that fix
    different last links': one finding naming both, added to each."""
    ok = [r for r in results if r["signature"]["status"] == "verified" and r["key_state"]["status"] == "verified"
          and r.get("_values", {}).get("count") is not None]
    for i in range(len(ok)):
        for j in range(i + 1, len(ok)):
            a, b = ok[i]["_values"], ok[j]["_values"]
            if a.get("chain_id") == b.get("chain_id") and a.get("count") == b.get("count") and a.get("head_link") != b.get("head_link"):
                f = ("conflict: checkpoints %d (key %s) and %d (key %s) fix different last links for chain %s at count %d: "
                     "a witness signed two histories, or the chain was forked" % (
                         ok[i]["checkpoint_index"], ok[i]["signature"]["key_ref"], ok[j]["checkpoint_index"],
                         ok[j]["signature"]["key_ref"], a.get("chain_id"), a.get("count")))
                for r in (ok[i], ok[j]):
                    r.setdefault("findings", []).append(f)
