"""Action binding 0.3.0: the reference check of one attachment's stages, written from the text
(README "The attachment" items 1-8, "Standing approvals" items 9-13, "The executor",
"The verifier and its report" bullets 1-3, "Rationale provenance")."""
import base64
from dps_common import (strict_loads, Unreadable, sha256_hex, instant, has_offset, is_json_int,
                        strict_eq, kind, JFloat)

KNOWN_WORDS = ("approved", "rejected", "escalated")
BOUND_MEMBERS = {"operation", "target", "policy_version", "input_version_refs", "parameters",
                 "max_requests", "valid_from", "valid_until"}
SPEC_MEMBERS = {"operation", "target", "policy_version", "input_version_refs", "parameters"}


class Dim:
    """One dimension: worst status wins (failed > not_checked/unavailable > verified)."""
    ORDER = {"verified": 0, "unavailable": 1, "not_checked": 1, "failed": 2}

    def __init__(self, status="verified"):
        self.status, self.findings = status, []

    def set(self, status, finding=None):
        if self.ORDER[status] > self.ORDER[self.status] or (
                self.ORDER[status] == self.ORDER[self.status] and status != self.status and status == "not_checked"):
            self.status = status
        if finding:
            self.findings.append(finding)

    def fail(self, f):
        self.set("failed", f)

    def out(self):
        o = {"status": self.status}
        if self.findings:
            o["findings"] = self.findings
        return o


def _content_bytes(content):
    if not isinstance(content, dict) or content.get("availability") != "available":
        return None
    try:
        return base64.b64decode(content["bytes_b64"], validate=True)
    except Exception:
        return None


def _value_ok(v):
    return v is None or isinstance(v, (str, bool)) or is_json_int(v)


def read_bounds(raw):
    """Item 10. Returns (bounds, None) or (None, reason) for not well-formed. Raises Unreadable."""
    b = strict_loads(raw)
    if not isinstance(b, dict):
        return None, "bounds are not a JSON object"
    if set(b) != BOUND_MEMBERS:
        return None, "bounds members are not exactly the eight: %s" % sorted(set(b) ^ BOUND_MEMBERS)
    for m in ("operation", "target", "policy_version"):
        if not _value_ok(b[m]):
            return None, "%s is not a string, JSON integer, boolean or null" % m
    ivr = b["input_version_refs"]
    if not isinstance(ivr, list) or not all(isinstance(x, str) for x in ivr):
        return None, "input_version_refs is not a list of references"
    if not isinstance(b["parameters"], dict):
        return None, "parameters is not an object"
    for name, c in b["parameters"].items():
        if not isinstance(c, dict) or not c:
            return None, "parameter %s: not a constraint" % name
        keys = set(c)
        if keys == {"exact"}:
            if not _value_ok(c["exact"]):
                return None, "parameter %s: exact value is not a string, JSON integer, boolean or null" % name
        elif keys == {"one_of"}:
            lst = c["one_of"]
            if not isinstance(lst, list) or not all(_value_ok(x) for x in lst):
                return None, "parameter %s: one_of is not a list of values" % name
            for i in range(len(lst)):
                for j in range(i + 1, len(lst)):
                    if strict_eq(lst[i], lst[j]):
                        return None, "parameter %s: one_of names a value twice" % name
        elif keys == {"max_length"}:
            if not is_json_int(c["max_length"]) or c["max_length"] < 0:
                return None, "parameter %s: max_length is not a non-negative JSON integer" % name
        elif keys and keys <= {"min", "max"}:
            for k in keys:
                if not is_json_int(c[k]):
                    return None, "parameter %s: %s is not a JSON integer" % (name, k)
        else:
            return None, "parameter %s: not one of the four constraint kinds" % name
    if not is_json_int(b["max_requests"]) or b["max_requests"] < 1:
        return None, "max_requests is not a JSON integer of at least 1"
    vf, r1 = instant(b["valid_from"])
    vu, r2 = instant(b["valid_until"])
    if vf is None or vu is None:
        return None, "period: %s" % (r1 or r2)
    if vf > vu:
        return None, "period inverted"
    return b, None


def inside_bounds(spec, b):
    """Item 11 for one specification object. Returns list of reasons it is outside (empty = inside)."""
    out = []
    if not isinstance(spec, dict):
        return ["specification is not a JSON object"]
    extra = set(spec) - SPEC_MEMBERS
    if extra:
        out.append("member(s) the bounds do not name: %s" % sorted(extra))
    for m in ("operation", "target", "policy_version"):
        if m not in spec or not strict_eq(spec[m], b[m]):
            out.append("%s is not the bounds' exact value" % m)
    ivr = spec.get("input_version_refs")
    if not isinstance(ivr, list):
        out.append("input_version_refs missing or not a list")
    else:
        for r in ivr:
            if not any(strict_eq(r, a) for a in b["input_version_refs"]):
                out.append("input-version reference not allowed: %r" % (r,))
    params = spec.get("parameters")
    if not isinstance(params, dict):
        out.append("parameters missing or not an object")
        return out
    for name in set(params) - set(b["parameters"]):
        out.append("parameter the bounds do not name: %s" % name)
    for name, c in b["parameters"].items():
        if name not in params:
            out.append("parameter the bounds name is missing: %s" % name)
            continue
        v = params[name]
        if "exact" in c:
            if not strict_eq(v, c["exact"]):
                out.append("%s is not the exact value" % name)
        elif "one_of" in c:
            if not any(strict_eq(v, x) for x in c["one_of"]):
                out.append("%s is not in the list" % name)
        elif "max_length" in c:
            if not isinstance(v, str) or len(v) > c["max_length"]:
                out.append("%s is not a string of at most %d code points" % (name, c["max_length"]))
        else:
            if not is_json_int(v):
                out.append("%s is not a JSON integer" % name)
            else:
                if "min" in c and v < c["min"]:
                    out.append("%s is under its minimum" % name)
                if "max" in c and v > c["max"]:
                    out.append("%s is over its maximum" % name)
    return out


def check(att, record_text=None):
    """Returns a dict of dimensions and the per-attachment lists. att: the attachment as read."""
    R = {k: Dim() for k in ("record_statements", "action_binding", "stage_order",
                            "authorisation_recheck", "observed_results", "rationale_provenance")}
    AB, SO = R["action_binding"], R["stage_order"]
    stages = att.get("stages", [])
    specs = att.get("action_specifications", [])
    by_id, pos = {}, {}
    for i, s in enumerate(stages):
        sid = s.get("stage_id")
        if sid in by_id:
            SO.fail("stage_id used twice: %s" % sid)
        else:
            by_id[sid], pos[sid] = s, i
    kind_of = lambda sid: by_id.get(sid, {}).get("kind")

    # ---- time helpers: each comparison with a time that names no instant fails
    def t(s, field="at"):
        return instant(s.get(field))

    def not_before(dim, later, earlier, what, lf="at", ef="at"):
        a, ra = t(later, lf)
        b, rb = t(earlier, ef)
        if a is None or b is None:
            dim.fail("%s: %s" % (what, ra or rb))
            return False
        if a < b:
            dim.fail(what)
            return False
        return True

    # ---- specifications
    spec_res, spec_obj = [], {}
    digests = {}
    for i, sp in enumerate(specs):
        d, st = Dim(), Dim()
        sd = sp.get("spec_digest")
        digests.setdefault(sd, i)
        raw = _content_bytes(sp.get("content"))
        if sp.get("content", {}).get("availability") != "available":
            d.set("unavailable", "the specification's bytes are unavailable")
            st.set("not_checked", "bytes unavailable: the summary is not checked")
        elif raw is None:
            d.fail("bytes_b64 cannot be decoded")
            st.set("not_checked", "bytes cannot be decoded")
        else:
            if sha256_hex(raw) != sd:
                d.fail("the bytes do not match spec_digest")
            mt = (sp.get("representation") or {}).get("media_type", "")
            readable = mt == "application/json" or mt.endswith("+json")
            try:
                if not readable:
                    raise Unreadable("media type %s is not one this check reads" % mt)
                obj = strict_loads(raw)
                spec_obj[sd] = obj if sha256_hex(raw) == sd else spec_obj.get(sd)
                summ = sp.get("summary", {})
                if not isinstance(obj, dict):
                    st.set("not_checked", "the bytes are not a JSON object")
                else:
                    for m in ("operation", "target", "policy_version", "input_version_refs"):
                        if m not in obj:
                            st.fail("summary %s: not in the bytes" % m)
                        elif not strict_eq(obj[m], summ.get(m)):
                            st.fail("summary %s differs from the bytes" % m)
            except Unreadable as e:
                st.set("not_checked", "the bytes cannot be read: %s" % e)
        spec_res.append({"spec_index": i, "spec_digest": sd, "digest": d.out(), "statements": st.out()})
    spec_ok = {r["spec_digest"] for r in spec_res}

    # ---- parties named in the attachment
    proposers, services = set(), set()
    for s in stages:
        if s.get("kind") == "proposal":
            for f in ("actor_ref", "deployer_role_pointer", "system_name"):
                if s.get(f): proposers.add(s[f])
        if s.get("kind") == "request" and s.get("requested_by"): services.add(s["requested_by"])
        if s.get("kind") == "attempt" and s.get("executor_ref"): services.add(s["executor_ref"])
        if s.get("kind") == "recheck" and s.get("authority_source_ref"): services.add(s["authority_source_ref"])

    # ---- generic references: exists, of the right kind, listed earlier, dated not later
    REFS = {"review": [("proposal_ref", ("proposal",))],
            "outcome": [("review_ref", ("review",))],
            "standing_approval": [("review_ref", ("review",))],
            "standing_revocation": [("revokes_ref", ("standing_approval",))],
            "change_authorisation": [("from_ref", ("outcome", "change_authorisation", "standing_approval"))],
            "request": [("authorised_by", ("outcome", "change_authorisation", "standing_approval"))],
            "recheck": [("request_ref", ("request",))],
            "attempt": [("request_ref", ("request",)), ("recheck_ref", ("recheck",))],
            "result": [("attempt_ref", ("attempt",))]}
    OWNER = {"recheck_ref": "authorisation_recheck", "attempt_ref": "observed_results"}
    for i, s in enumerate(stages):
        for field, kinds in REFS.get(s.get("kind"), []):
            ref = s.get(field)
            if ref is None:
                continue
            D = R[OWNER.get(field, "action_binding")] if not (s.get("kind") == "recheck" and field == "request_ref") else R["authorisation_recheck"]
            if ref not in by_id:
                D.fail("%s %s names %s, which the attachment does not record" % (s.get("kind"), s.get("stage_id"), ref))
                continue
            if kind_of(ref) not in kinds:
                D.fail("%s %s: %s names a %s" % (s.get("kind"), s.get("stage_id"), field, kind_of(ref)))
                continue
            if pos[ref] > i:
                SO.fail("%s %s is listed before %s, which it names" % (s.get("kind"), s.get("stage_id"), ref))
            not_before(SO, s, by_id[ref], "%s %s is dated before %s, which it names" % (s.get("kind"), s.get("stage_id"), ref))

    # ---- reviews: shown vs proposal; edited_by
    reviews_out = []
    for s in stages:
        if s.get("kind") != "review":
            continue
        shown = s.get("shown_spec_digest") or s.get("shown_bounds_digest")
        pr = s.get("proposal_ref")
        if pr is None or kind_of(pr) != "proposal":
            reviews_out.append({"review_stage_id": s["stage_id"], "shown": "proposal_not_named"})
        elif by_id[pr].get("spec_digest") == s.get("shown_spec_digest"):
            reviews_out.append({"review_stage_id": s["stage_id"], "shown": "as_proposed"})
        else:
            e = {"review_stage_id": s["stage_id"], "shown": "differs_from_proposal"}
            if s.get("edited_by"):
                e["edited_by"] = s["edited_by"]
            else:
                AB.fail("review %s was shown something other than its proposal and names no editor" % s["stage_id"])
            reviews_out.append(e)

    # ---- outcomes: one per review, by the person shown; approval binds the shown digest
    answers = {}
    rejected_specs = set()
    for s in stages:
        if s.get("kind") in ("outcome", "standing_approval"):
            answers.setdefault(s.get("review_ref"), []).append(s)
    for rid, lst in answers.items():
        if len(lst) > 1:
            AB.fail("review %s has %d outcomes" % (rid, len(lst)))
    for s in stages:
        if s.get("kind") != "outcome":
            continue
        rv = by_id.get(s.get("review_ref"), {})
        if rv.get("kind") == "review" and s.get("actor_ref") != rv.get("reviewer_ref"):
            AB.fail("outcome %s is given by %s, not the person shown (%s)" % (s["stage_id"], s.get("actor_ref"), rv.get("reviewer_ref")))
        if s.get("outcome") == "approved":
            if "shown_bounds_digest" in rv:
                AB.fail("outcome %s approves bounds: an approval of bounds is never an outcome" % s["stage_id"])
            elif s.get("approved_spec_digest") != rv.get("shown_spec_digest"):
                AB.fail("outcome %s approves a digest other than the one its review was shown" % s["stage_id"])
            if s.get("actor_ref") in proposers or s.get("actor_ref") in services:
                AB.fail("outcome %s is given by the proposer or a service named in the attachment" % s["stage_id"])
        else:
            if rv.get("shown_spec_digest"):
                rejected_specs.add(rv["shown_spec_digest"])

    # ---- core fields back at most one outcome
    backs = {}
    for s in stages:
        cr = s.get("core_ref")
        if isinstance(cr, dict):
            key = (cr.get("field"), repr(cr.get("index")))
            if key in backs:
                AB.fail("core field %s backs two outcomes (%s, %s)" % (key[0], backs[key], s["stage_id"]))
            backs[key] = s["stage_id"]

    # ---- standing approvals (items 9-13)
    standing = []
    sa_state = {}
    for s in stages:
        if s.get("kind") != "standing_approval":
            continue
        sid = s["stage_id"]
        rv = by_id.get(s.get("review_ref"), {})
        if rv.get("kind") == "review":
            if "shown_bounds_digest" not in rv:
                AB.fail("standing approval %s answers a review that was shown a specification, not bounds" % sid)
            elif rv["shown_bounds_digest"] != s.get("bounds_digest"):
                AB.fail("standing approval %s: the review was not shown these bounds" % sid)
            if s.get("actor_ref") != rv.get("reviewer_ref"):
                AB.fail("standing approval %s is given by someone other than the person shown the bounds" % sid)
        if s.get("actor_ref") in proposers or s.get("actor_ref") in services:
            AB.fail("standing approval %s is given by the proposer or a service named in the attachment" % sid)
        bd = Dim()
        bounds = None
        content = s.get("bounds", {})
        raw = _content_bytes(content)
        if content.get("availability") != "available":
            bd.set("unavailable", "the bounds' bytes are unavailable")
        elif raw is None:
            bd.fail("bytes_b64 cannot be decoded")
        elif sha256_hex(raw) != s.get("bounds_digest"):
            bd.fail("the bounds' bytes do not match bounds_digest")
        else:
            try:
                bounds, why = read_bounds(raw)
                if bounds is None:
                    bd.fail("not well-formed bounds: %s" % why)
            except Unreadable as e:
                bd.set("not_checked", "the bounds cannot be read: %s" % e)
        reqs = [x for x in stages if x.get("kind") == "request" and x.get("authorised_by") == sid]
        revs = [x for x in stages if x.get("kind") == "standing_revocation" and x.get("revokes_ref") == sid]
        e = {"stage_id": sid, "bounds": bd.out(), "requests_recorded": len(reqs),
             "revocation": "recorded" if revs else "none_recorded"}
        if bd.status == "verified":
            e["max_requests"] = bounds["max_requests"]
            e["valid_from"], e["valid_until"] = bounds["valid_from"], bounds["valid_until"]
        standing.append(e)
        sa_state[sid] = (bd.status, bounds, reqs, revs)

    # ---- changes
    def binder_digest(sid):
        st = by_id.get(sid, {})
        if st.get("kind") == "outcome":
            return st.get("approved_spec_digest")
        if st.get("kind") == "change_authorisation":
            return st.get("spec_digest")
        return None

    uses = {}  # approval/change id -> count of requests + changes resting on it
    for s in stages:
        if s.get("kind") != "change_authorisation":
            continue
        sid, fr = s["stage_id"], s.get("from_ref")
        fk = kind_of(fr)
        if fk == "standing_approval":
            AB.fail("change %s starts from a standing approval" % sid)
        elif fk == "outcome" and by_id[fr].get("outcome") != "approved":
            AB.fail("change %s starts from a %s outcome" % (sid, by_id[fr].get("outcome")))
        if fk in ("outcome", "change_authorisation") and s.get("spec_digest") == binder_digest(fr):
            AB.fail("change %s names the specification it changes" % sid)
        if s.get("actor_ref") in proposers or s.get("actor_ref") in services:
            AB.fail("change %s is authorised by the proposer or a service named in the attachment" % sid)
        if s.get("spec_digest") in rejected_specs:
            AB.fail("change %s reaches a specification a reviewer rejected or escalated" % sid)
        uses[fr] = uses.get(fr, 0) + 1

    # ---- requests
    req_ids = {}
    per_spec = {}
    for i, s in enumerate(stages):
        if s.get("kind") != "request":
            continue
        sid, ab = s["stage_id"], s.get("authorised_by")
        rid = s.get("request_id")
        if rid in req_ids:
            AB.fail("request_id %s is used twice (%s, %s)" % (rid, req_ids[rid], sid))
        req_ids.setdefault(rid, sid)
        if s.get("spec_digest") in rejected_specs:
            AB.fail("request %s reaches a specification a reviewer rejected or escalated" % sid)
        ak = kind_of(ab)
        if ak == "outcome":
            o = by_id[ab]
            if o.get("outcome") != "approved":
                AB.fail("request %s rests on a %s outcome" % (sid, o.get("outcome")))
            elif s.get("spec_digest") != o.get("approved_spec_digest"):
                AB.fail("request %s names a specification other than the one approved" % sid)
            uses[ab] = uses.get(ab, 0) + 1
            per_spec[s.get("spec_digest")] = per_spec.get(s.get("spec_digest"), 0) + 1
        elif ak == "change_authorisation":
            if s.get("spec_digest") != by_id[ab].get("spec_digest"):
                AB.fail("request %s names a specification other than the change's" % sid)
            uses[ab] = uses.get(ab, 0) + 1
            per_spec[s.get("spec_digest")] = per_spec.get(s.get("spec_digest"), 0) + 1
        elif ak == "standing_approval":
            status, bounds, reqs, revs = sa_state[ab]
            if status == "failed":
                AB.fail("request %s rests on bounds that failed" % sid)
            elif status != "verified":
                AB.set("not_checked", "request %s rests on bounds that could not be read: not checked" % sid)
            else:
                obj = spec_obj.get(s.get("spec_digest"))
                spec_entry = next((x for x in specs if x.get("spec_digest") == s.get("spec_digest")), None)
                if spec_entry is None:
                    AB.fail("request %s names a specification the attachment does not carry" % sid)
                elif obj is None:
                    av = spec_entry.get("content", {}).get("availability")
                    raw = _content_bytes(spec_entry.get("content"))
                    if av != "available" or (raw is not None and sha256_hex(raw) == spec_entry.get("spec_digest")):
                        AB.set("not_checked", "request %s: the specification's bytes are unavailable or cannot be read: not checked" % sid)
                    else:
                        AB.fail("request %s: the specification's bytes do not match its digest" % sid)
                else:
                    for why in inside_bounds(obj, bounds):
                        AB.fail("request %s is outside the bounds: %s" % (sid, why))
                # period
                a, ra = instant(s.get("at"))
                vf, vu = instant(bounds["valid_from"])[0], instant(bounds["valid_until"])[0]
                if a is None:
                    AB.fail("request %s: %s" % (sid, ra))
                elif a < vf or a > vu:
                    AB.fail("request %s is outside the period" % sid)
                if reqs.index(s) >= bounds["max_requests"]:
                    AB.fail("request %s is over the count (%d)" % (sid, bounds["max_requests"]))
            # revocations
            for rv in sa_state[ab][3]:
                if pos[rv["stage_id"]] < i:
                    AB.fail("request %s is listed after a recorded revocation (%s)" % (sid, rv["stage_id"]))
                a, ra = instant(s.get("at"))
                b, rb = instant(rv.get("at"))
                if a is None or b is None:
                    AB.fail("request %s against revocation %s: %s" % (sid, rv["stage_id"], ra or rb))
                elif a > b:
                    AB.fail("request %s is dated after a recorded revocation (%s)" % (sid, rv["stage_id"]))
        elif ab in by_id:
            AB.fail("request %s rests on a %s" % (sid, ak))
    # approvals/changes covering more requests than they state
    limits = {}
    for s in stages:
        if s.get("kind") in ("outcome", "change_authorisation") and (s.get("kind") == "change_authorisation" or s.get("outcome") == "approved"):
            lim = s.get("request_limit", 1)
            if uses.get(s["stage_id"], 0) > lim:
                AB.fail("%s %s covers %d requests, more than the %d it states" % (s["kind"], s["stage_id"], uses[s["stage_id"]], lim))
            d = binder_digest(s["stage_id"])
            limits[d] = max(limits.get(d, 0), lim)
    for d, n in per_spec.items():
        if d in limits and n > limits[d]:
            AB.fail("specification %s… is requested %d times, more than the largest request_limit (%d)" % (d[:12], n, limits[d]))

    # ---- rechecks, attempts, results
    attempts = [s for s in stages if s.get("kind") == "attempt"]
    requests = [s for s in stages if s.get("kind") == "request"]
    for s in stages:
        if s.get("kind") != "recheck" or s.get("result") != "authorised":
            continue
        q = by_id.get(s.get("request_ref"), {})
        ab = q.get("authorised_by")
        if kind_of(ab) == "standing_approval":
            for rv in sa_state[ab][3]:
                a, ra = instant(s.get("at"))
                b, rb = instant(rv.get("at"))
                if pos[rv["stage_id"]] < pos[s["stage_id"]] or a is None or b is None or a > b:
                    R["authorisation_recheck"].fail("recheck %s authorised a request after a recorded revocation (%s)" % (s["stage_id"], rv["stage_id"]))
    used_rc = {}
    for x in attempts:
        rc_ = x.get("recheck_ref")
        if rc_ in used_rc:
            R["authorisation_recheck"].fail("attempt %s reuses recheck %s of attempt %s: a retry is a new attempt, with its own recheck" % (x["stage_id"], rc_, used_rc[rc_]))
        used_rc.setdefault(rc_, x["stage_id"])
    executed = {}
    order = []
    for x in attempts:
        xid = x["stage_id"]
        q = by_id.get(x.get("request_ref"), {})
        if q.get("kind") == "request" and x.get("spec_digest") != q.get("spec_digest"):
            AB.fail("attempt %s executes a specification other than the one requested" % xid)
        # recheck
        rc = by_id.get(x.get("recheck_ref"), {})
        if rc.get("kind") != "recheck" or rc.get("request_ref") != x.get("request_ref"):
            R["authorisation_recheck"].fail("attempt %s does not follow a recheck of its request" % xid)
        elif rc.get("result") != "authorised":
            R["authorisation_recheck"].fail("attempt %s follows a recheck that did not authorise it (%s)" % (xid, rc.get("result")))
        else:
            # the latest recheck of the request before the attempt must authorise
            xa, rxa = instant(x.get("at"))
            later = [c for c in stages if c.get("kind") == "recheck" and c.get("request_ref") == x.get("request_ref")
                     and pos[c["stage_id"]] < pos[xid] and c is not rc]
            for c in later:
                ca, rca = instant(c.get("at"))
                ra_, rra = instant(rc.get("at"))
                if ca is None or ra_ is None:
                    R["authorisation_recheck"].fail("attempt %s: recheck times: %s" % (xid, rca or rra))
                elif ca >= ra_ and c.get("result") != "authorised" and (xa is None or ca <= xa):
                    R["authorisation_recheck"].fail("attempt %s: the latest recheck (%s) does not authorise it" % (xid, c["stage_id"]))
            not_before(R["authorisation_recheck"], x, rc, "attempt %s is dated before its recheck" % xid)
        # how the executed specification was reached
        d = x.get("spec_digest")
        how = "unbound"
        ab = q.get("authorised_by")
        if q.get("kind") == "request" and d == q.get("spec_digest"):
            k = kind_of(ab)
            if k == "outcome" and by_id[ab].get("outcome") == "approved" and d == by_id[ab].get("approved_spec_digest") \
                    and by_id.get(by_id[ab].get("review_ref"), {}).get("shown_spec_digest") == d:
                how = "shown_to_reviewer"
            elif k == "change_authorisation" and d == by_id[ab].get("spec_digest"):
                how = "via_change_only"
            elif k == "standing_approval":
                how = "via_standing_approval"
        if d in spec_ok and d not in order:
            order.append(d)
        if d in spec_ok:
            prev = executed.get(d)
            rank = ["unbound", "via_standing_approval", "via_change_only", "shown_to_reviewer"]
            if prev is None or (how == "unbound") or (prev != "unbound" and rank.index(how) > rank.index(prev)):
                executed[d] = how if prev != "unbound" else "unbound"
        else:
            AB.fail("attempt %s executes a specification the attachment does not carry" % xid)
    # a specification reached by change only is never reported shown: if some reviewer was shown it,
    # a shown approval exists and outranks it above.
    exec_out = [{"spec_index": digests[d], "reached_by": executed[d]} for d in order]
    for e in exec_out:
        if e["reached_by"] == "unbound":
            AB.fail("specification %d was executed with no approval, change or standing approval binding it" % e["spec_index"])
    obs = []
    results = [s for s in stages if s.get("kind") == "result"]
    for x in attempts:
        rs = [r for r in results if r.get("attempt_ref") == x["stage_id"]]
        if len(rs) == 1:
            obs.append({"attempt_stage_id": x["stage_id"], "observed": rs[0].get("observed"), "basis": rs[0].get("basis")})
        elif not rs:
            obs.append({"attempt_stage_id": x["stage_id"], "observed": "missing"})
            R["observed_results"].fail("attempt %s has no result" % x["stage_id"])
        else:
            obs.append({"attempt_stage_id": x["stage_id"], "observed": "multiple"})
            R["observed_results"].fail("attempt %s has %d results" % (x["stage_id"], len(rs)))
    if attempts:
        state = "attempted"
    elif requests:
        state = "requested_not_attempted"
    else:
        state = "not_requested"
    if not attempts and not any(s.get("kind") == "recheck" for s in stages):
        R["authorisation_recheck"].set("not_checked", "no recheck or attempt is recorded")
    if not attempts:
        R["observed_results"].set("not_checked", "no execution attempt is recorded")

    # ---- rationale provenance
    for s in stages:
        ra = s.get("rationale")
        if not isinstance(ra, dict):
            continue
        if ra.get("timing") == "contemporaneous":
            a, r1 = instant(s.get("at"))
            b, r2 = instant(ra.get("recorded_at"))
            if a is None or b is None:
                R["rationale_provenance"].fail("%s %s: %s" % (s.get("kind"), s.get("stage_id"), r1 or r2))
            elif b > a:
                R["rationale_provenance"].fail("%s %s: a rationale recorded after the outcome is presented as contemporaneous" % (s.get("kind"), s.get("stage_id")))
        elif ra.get("timing") == "later_supplemented" and "recorded_at" in ra:
            a, r1 = instant(s.get("at"))
            b, r2 = instant(ra.get("recorded_at"))
            if a is None or b is None:
                R["rationale_provenance"].fail("%s %s: %s" % (s.get("kind"), s.get("stage_id"), r1 or r2))
            elif b <= a:
                R["rationale_provenance"].fail("%s %s: a rationale said to be supplemented later is dated no later than the outcome" % (s.get("kind"), s.get("stage_id")))

    # ---- record statements
    RS = R["record_statements"]
    if record_text is None:
        RS.set("not_checked", "the decision record is not held")
    else:
        try:
            rec = strict_loads(record_text)
        except Unreadable as e:
            rec = None
            RS.set("not_checked", "the record cannot be read: %s" % e)
        if rec is not None:
            if rec.get("decision_id") != att.get("decision_id"):
                RS.fail("decision_id differs from the record's")
            da = rec.get("drafting_authority")
            for s in stages:
                if s.get("kind") == "proposal" and s.get("origin") == "ai":
                    if not isinstance(da, dict):
                        RS.fail("proposal %s names an AI worker; the record has no drafting_authority" % s["stage_id"])
                        continue
                    for f in ("deployer_role_pointer", "system_name", "version"):
                        if s.get(f) != da.get(f):
                            RS.fail("proposal %s: %s differs from drafting_authority" % (s["stage_id"], f))
            for s in stages:
                if s.get("kind") not in ("outcome", "standing_approval"):
                    continue
                approval = s.get("kind") == "standing_approval" or s.get("outcome") == "approved"
                cr = s.get("core_ref")
                if not isinstance(cr, dict):
                    if approval:
                        RS.set("not_checked", "%s %s names no core field: the record does not show it" % (s["kind"], s["stage_id"]))
                    continue
                word = "approved" if approval else s.get("outcome")
                if cr.get("field") == "affirmation_record":
                    ar = rec.get("affirmation_record")
                    if not isinstance(ar, dict):
                        RS.fail("%s names affirmation_record; the record has none" % s["stage_id"])
                        continue
                    if not approval:
                        RS.fail("%s %s is a %s, and names the affirmation_record" % (s["kind"], s["stage_id"], word))
                    if s.get("actor_ref") != ar.get("actor_identity"):
                        RS.fail("%s: actor differs from affirmation_record.actor_identity" % s["stage_id"])
                    if s.get("method") != ar.get("method"):
                        RS.fail("%s: method differs from affirmation_record.method" % s["stage_id"])
                    core_t = ar.get("timestamp")
                elif cr.get("field") == "review_log":
                    idx = cr.get("index")
                    rl = rec.get("review_log")
                    if not is_json_int(idx):
                        RS.set("not_checked", "%s: review_log index not written as an integer" % s["stage_id"])
                        continue
                    if not isinstance(rl, list) or idx >= len(rl) or not isinstance(rl[idx], dict):
                        RS.fail("%s: review_log entry %d is not in the record" % (s["stage_id"], idx))
                        continue
                    ent = rl[idx]
                    if ent.get("outcome") not in KNOWN_WORDS:
                        RS.set("not_checked", "%s: review_log outcome word the check does not know: %r" % (s["stage_id"], ent.get("outcome")))
                    elif ent.get("outcome") != word:
                        RS.fail("%s: the record states %s, the stage %s" % (s["stage_id"], ent.get("outcome"), word))
                    if s.get("actor_ref") != ent.get("reviewer"):
                        RS.fail("%s: actor differs from review_log reviewer" % s["stage_id"])
                    core_t = ent.get("reviewed_at")
                else:
                    continue
                if not has_offset(core_t):
                    RS.set("not_checked", "%s: the core time has no offset" % s["stage_id"])
                else:
                    a, r1 = instant(s.get("at"))
                    b, r2 = instant(core_t)
                    if a is None or b is None:
                        RS.fail("%s: %s" % (s["stage_id"], r1 or r2))
                    elif a != b:
                        RS.fail("%s: time differs from the core field's" % s["stage_id"])
    out = {k: v.out() for k, v in R.items()}
    out["observed_results"].update({"execution_state": state, "attempts": obs})
    if state != "attempted":
        exec_out = []
    out.update({"specifications": spec_res, "reviews": reviews_out, "executed_specifications": exec_out,
                "standing_approvals": standing})
    return out
