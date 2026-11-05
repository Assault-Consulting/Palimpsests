"""The verifier's report (anchoring 0.2.0, "The verifier and its report") and a reader that pairs a report with the
documents it covers ('a reader holding both ... checks the counts, the digests, and that each dimension reported as
verified is verified')."""
from . import checkpoint as C
from . import policy as P
from . import timestamp as TS
from .common import b64_strict, doc_bytes, sha256_hex

SCOPE = {"covers": "supplied_export_and_attachment_only",
         "not_assessed": ["legal_requirements", "conformance_level", "truth_of_record_content", "time_of_decision",
                          "earliest_existence", "events_never_recorded", "content_reviewed_by_witness"]}


def make_ctx(policy, chain_id, export, held=None, headers=None):
    ok, reason = P.accept(policy)
    return {"policy": policy, "policy_ok": ok, "policy_reason": reason, "chain_id": chain_id, "export": export,
            "held": list(held or []), "headers": headers, "ts_results": []}


def item_from_carrier(c, obtained_from, source_ref=None, attachment_index=None):
    """An attachment's checkpoints item, or a checkpoint/statement given by a source."""
    if c is None:
        return {"type": None, "obtained_from": obtained_from, "source_ref": source_ref}
    if isinstance(c, dict) and c.get("format") == "scitt":
        rb = c.get("receipt_b64")
        return {"type": "scitt", "statement": b64_strict(c.get("statement_b64")),
                "receipt": b64_strict(rb) if rb is not None else None,
                "obtained_from": obtained_from, "source_ref": source_ref, "attachment_index": attachment_index}
    if isinstance(c, dict) and "signature" not in c and obtained_from == "same_export":
        return {"type": "issuer", "checkpoint": c, "obtained_from": obtained_from, "source_ref": source_ref}
    return {"type": "plain", "checkpoint": c, "obtained_from": obtained_from, "source_ref": source_ref,
            "attachment_index": attachment_index}


def strip_internal(x):
    if isinstance(x, dict):
        return {k: strip_internal(v) for k, v in x.items() if not k.startswith("_")}
    if isinstance(x, list):
        return [strip_internal(v) for v in x]
    return x


def verify(attachment, export, policy, chain_id, obtained, headers=None):
    """obtained: list of items (item_from_carrier) the verifier obtained or tried to obtain from its sources.
    Returns (report, internal results)."""
    beside = []
    for i, c in enumerate(attachment.get("checkpoints", []) or []):
        beside.append(item_from_carrier(c, "beside_export", attachment_index=i))
    held = [it["checkpoint"] for it in obtained + beside if it.get("type") == "plain"]
    ctx = make_ctx(policy, chain_id, export, held, headers)
    ts_results = [TS.check(t, i, ctx) for i, t in enumerate(attachment.get("timestamps", []) or [])]
    ctx["ts_results"] = ts_results
    cps = [C.check(it, i, ctx) for i, it in enumerate(obtained + beside)]
    C.conflicts(cps)
    rep = {"profile": "dps-anchoring-report", "profile_version": "0.2.0",
           "trust_policy_ref": policy.get("policy_ref"),
           "trust_policy": {"status": "verified"} if ctx["policy_ok"] else {"status": "failed", "findings": [ctx["policy_reason"]]}}
    if ts_results:
        rep["attachment_digest"] = sha256_hex(doc_bytes(attachment))
    else:
        rep["attachment_digest"] = sha256_hex(doc_bytes(attachment))
    rep["export_digest"] = sha256_hex(doc_bytes(export))
    rep["export_entry_count"] = len(export.get("entries", []))
    rep["chain_id"] = chain_id
    rep["timestamp_count"] = len(ts_results)
    rep["timestamps"] = strip_internal(ts_results)
    rep["checkpoint_count"] = len(cps)
    rep["checkpoints"] = strip_internal(cps)
    rep["scope_of_conclusion"] = SCOPE
    return rep, {"timestamps": ts_results, "checkpoints": cps, "ctx": ctx}


OPTIONAL = {"attachment_index"}


def _norm(x, drop_findings=True):
    if isinstance(x, dict):
        return {k: _norm(v) for k, v in x.items() if not (drop_findings and k == "findings")}
    if isinstance(x, list):
        return [_norm(v) for v in x]
    return x


def strict_equal(a, b, path="", optional=OPTIONAL):
    """Equality that tells 0 from 0.0 and True from 1. Returns the first differing path, or None."""
    if type(a) is not type(b):
        return path or "/"
    if isinstance(a, dict):
        for k in list(a) + [k for k in b if k not in a]:  # report order, so the first difference is stable
            if k in optional and k not in b:
                continue
            if k not in a or k not in b:
                return path + "/" + k
            d = strict_equal(a[k], b[k], path + "/" + k, optional)
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return path + " (length)"
        for i, (x, y) in enumerate(zip(a, b)):
            d = strict_equal(x, y, "%s/%d" % (path, i), optional)
            if d:
                return d
        return None
    return None if a == b else (path or "/")


def pair(report, attachment, export, policy, chain_id, obtained, headers=None):
    """Returns ('consistent'|'inconsistent', first differing path or None). The reader recomputes the report from the
    documents with this verifier and compares every member but findings; attachment_index, which a result MAY
    name, is compared only where the report names it (A21)."""
    mine, _ = verify(attachment, export, policy, chain_id, obtained, headers)
    d = strict_equal(_norm(mine), _norm(report))
    return ("consistent" if d is None else "inconsistent"), d
