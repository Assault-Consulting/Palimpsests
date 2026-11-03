"""Action binding 0.3.0: the reference check of one attachment's stages, written from the
extension's text (README at c904372), items 1-13 and 'The verifier and its report'.
Signature, key-state and time dimensions are in sig_check.py."""
import base64, binascii, hashlib
from strictjson import loads, Unreadable, JFloat, jeq, is_jint
from times import instant

REF_FIELDS = ("proposal_ref", "review_ref", "from_ref", "authorised_by", "request_ref",
              "recheck_ref", "attempt_ref", "revokes_ref")
SPEC_DIGEST_FIELDS = ("spec_digest", "shown_spec_digest", "approved_spec_digest")
KNOWN_OUTCOME_WORDS = ("approved", "rejected", "escalated")
READABLE_MEDIA_TYPES = ("application/json",)
BOUNDS_MEMBERS = {"operation", "target", "policy_version", "input_version_refs",
                  "parameters", "max_requests", "valid_from", "valid_until"}
SPEC_MEMBERS = {"operation", "target", "policy_version", "input_version_refs", "parameters"}

def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

def b64decode_strict(s):
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return None

class Dim:
    """One dimension: failed beats not_checked/unavailable beats verified."""
    def __init__(self):
        self.fail = []
        self.nc = []
        self.unav = []
    def failed(self, msg):
        self.fail.append(msg)
    def not_checked(self, msg):
        self.nc.append(msg)
    def unavailable(self, msg):
        self.unav.append(msg)
    def status(self):
        if self.fail:
            return "failed"
        if self.unav:
            return "unavailable"
        if self.nc:
            return "not_checked"
        return "verified"
    def out(self):
        o = {"status": self.status()}
        f = self.fail + self.unav + self.nc
        if f:
            o["findings"] = f
        return o

def _is_scalar_value(v):
    """Item 10: values are strings, JSON integers, booleans or null."""
    return v is None or isinstance(v, str) or type(v) is bool or is_jint(v)

def read_bounds(stage):
    """Item 10 and 13. Returns (status, bounds_or_None, findings)."""
    content = stage.get("bounds")
    digest = stage.get("bounds_digest")
    if not isinstance(content, dict) or content.get("availability") != "available":
        return "unavailable", None, ["the bounds' bytes are unavailable: the requests resting on them are not checked"]
    raw = b64decode_strict(content.get("bytes_b64", ""))
    if raw is None:
        return "failed", None, ["the bounds' bytes are not base64"]
    if sha256_hex(raw) != digest:
        return "failed", None, ["the bounds' bytes do not match bounds_digest"]
    try:
        b = loads(raw)
    except Unreadable as e:
        return "not_checked", None, ["the bounds cannot be read (%s): the requests resting on them are not checked" % e]
    err = bounds_wellformed(b)
    if err:
        return "failed", None, ["the bounds are not well-formed: " + err]
    return "verified", b, []

def bounds_wellformed(b):
    if not isinstance(b, dict):
        return "not an object"
    if set(b) != BOUNDS_MEMBERS:
        extra = sorted(set(b) - BOUNDS_MEMBERS)
        missing = sorted(BOUNDS_MEMBERS - set(b))
        return "members other than the eight (extra %s, missing %s)" % (extra, missing)
    for k in ("operation", "target", "policy_version"):
        if not isinstance(b[k], str):
            return "%s is not a string" % k
    if not isinstance(b["input_version_refs"], list) or not all(isinstance(x, str) for x in b["input_version_refs"]):
        return "input_version_refs is not a list of strings"
    if not is_jint(b["max_requests"]) or b["max_requests"] < 1:
        return "max_requests is not a JSON integer of at least 1"
    vf, vu = instant(b["valid_from"]), instant(b["valid_until"])
    if vf is None or vu is None:
        return "valid_from or valid_until is not a time with an offset"
    if vu < vf:
        return "valid_until is before valid_from"
    if not isinstance(b["parameters"], dict):
        return "parameters is not an object"
    for name, c in b["parameters"].items():
        err = constraint_wellformed(c)
        if err:
            return "parameter %s: %s" % (name, err)
    return None

def constraint_wellformed(c):
    if not isinstance(c, dict) or not c:
        return "a constraint is not an object"
    keys = set(c)
    if keys == {"exact"}:
        return None if _is_scalar_value(c["exact"]) else "exact value is not a string, JSON integer, boolean or null"
    if keys == {"one_of"}:
        vals = c["one_of"]
        if not isinstance(vals, list):
            return "one_of is not a list"
        for v in vals:
            if not _is_scalar_value(v):
                return "a one_of value is not a string, JSON integer, boolean or null"
        for i in range(len(vals)):
            for j in range(i + 1, len(vals)):
                if jeq(vals[i], vals[j]):
                    return "one_of names a value twice"
        return None
    if keys == {"max_length"}:
        n = c["max_length"]
        return None if is_jint(n) and n >= 0 else "max_length is not a non-negative JSON integer"
    if keys and keys <= {"min", "max"}:
        for k in keys:
            if not is_jint(c[k]):
                return "%s is not a JSON integer" % k
        return None
    return "a constraint of no kind, or of two kinds: %s" % sorted(keys)

def satisfies(v, c):
    keys = set(c)
    if keys == {"exact"}:
        return jeq(v, c["exact"])
    if keys == {"one_of"}:
        return any(jeq(v, x) for x in c["one_of"])
    if keys == {"max_length"}:
        return isinstance(v, str) and len(v) <= c["max_length"]
    if not is_jint(v):
        return False
    if "min" in c and v < c["min"]:
        return False
    if "max" in c and v > c["max"]:
        return False
    return True

def spec_inside(spec, b):
    """Item 11: three exact members, every input-version reference allowed, every
    parameter inside its constraint; closed both ways."""
    if not isinstance(spec, dict):
        return "the specification is not an object"
    if set(spec) != SPEC_MEMBERS:
        return "the specification's members are not exactly those the bounds name (%s)" % sorted(set(spec) ^ SPEC_MEMBERS)
    for k in ("operation", "target", "policy_version"):
        if not jeq(spec[k], b[k]):
            return "%s is not the bounds' exact value" % k
    refs = spec["input_version_refs"]
    if not isinstance(refs, list) or not all(isinstance(r, str) and r in b["input_version_refs"] for r in refs):
        return "an input-version reference the bounds do not allow"
    params = spec["parameters"]
    if not isinstance(params, dict):
        return "parameters is not an object"
    if set(params) != set(b["parameters"]):
        return "parameters not exactly those the bounds name (%s)" % sorted(set(params) ^ set(b["parameters"]))
    for k, v in params.items():
        if not satisfies(v, b["parameters"][k]):
            return "parameter %s is outside its constraint" % k
    return None


def check_attachment(att, record_text=None):
    """att: parsed attachment (strict). record_text: the decision record's text or bytes, or None.
    Returns the binding part of a result, plus 'standing' for the cases."""
    specs = att.get("action_specifications", [])
    stages = att.get("stages", [])
    pos = {}
    dup_ids = []
    for i, s in enumerate(stages):
        sid = s.get("stage_id")
        if sid in pos:
            dup_ids.append(sid)
        else:
            pos[sid] = i
    by_id = {sid: stages[i] for sid, i in pos.items()}
    at = [instant(s.get("at")) for s in stages]
    kind = lambda sid: by_id[sid].get("kind") if sid in by_id else None

    # ---- specifications
    spec_index = {}
    spec_obj = {}       # digest -> parsed spec (bytes verified and readable)
    spec_state = {}     # digest -> 'ok' | 'unavailable' | 'unreadable' | 'mismatch'
    spec_results = []
    for i, sp in enumerate(specs):
        d = sp.get("spec_digest")
        spec_index.setdefault(d, i)
        dig, stm = Dim(), Dim()
        content = sp.get("content", {})
        raw = None
        if content.get("availability") == "available":
            raw = b64decode_strict(content.get("bytes_b64", ""))
            if raw is None:
                dig.failed("the bytes are not base64")
            elif sha256_hex(raw) == d:
                pass
            else:
                dig.failed("the bytes do not match spec_digest")
        else:
            dig.unavailable("the specification's bytes are unavailable")
        parsed = None
        if raw is None:
            stm.not_checked("the bytes are unavailable: the summary is not checked")
        elif sp.get("representation", {}).get("media_type") not in READABLE_MEDIA_TYPES:
            stm.not_checked("a media type the check cannot read: the summary is not checked")
        else:
            try:
                parsed = loads(raw)
            except Unreadable as e:
                stm.not_checked("the bytes cannot be read (%s): the summary is not checked" % e)
            if parsed is not None:
                summ = sp.get("summary", {})
                if not isinstance(parsed, dict):
                    stm.failed("the bytes are not a JSON object")
                else:
                    for k in ("operation", "target", "policy_version", "input_version_refs"):
                        if k not in parsed:
                            stm.failed("the summary states %s, which the bytes do not carry" % k)
                        elif not jeq(parsed[k], summ.get(k)):
                            stm.failed("the summary's %s is not the bytes'" % k)
        if d not in spec_state:
            if dig.status() == "verified" and parsed is not None:
                spec_state[d] = "ok"; spec_obj[d] = parsed
            elif dig.status() == "unavailable":
                spec_state[d] = "unavailable"
            elif dig.status() == "failed":
                spec_state[d] = "mismatch"
            else:
                spec_state[d] = "unreadable"
        spec_results.append({"spec_index": i, "spec_digest": d, "digest": dig.out(), "statements": stm.out()})

    ab = Dim(); order = Dim(); recheck = Dim(); obs = Dim(); rat = Dim(); rec = Dim()

    # ---- services and proposer named in the attachment
    services = set()
    proposers = set()
    for s in stages:
        if s.get("kind") == "request" and isinstance(s.get("requested_by"), str):
            services.add(s["requested_by"])
        if s.get("kind") == "attempt" and isinstance(s.get("executor_ref"), str):
            services.add(s["executor_ref"])
        if s.get("kind") == "proposal":
            if s.get("origin") == "ai":
                for k in ("deployer_role_pointer",):
                    if isinstance(s.get(k), str):
                        proposers.add(s[k])
            elif isinstance(s.get("actor_ref"), str):
                proposers.add(s["actor_ref"])

    # ---- every digest a stage names is carried
    for s in stages:
        for f in SPEC_DIGEST_FIELDS:
            if f in s and s[f] not in spec_index:
                ab.failed("stage %s names a specification the attachment does not carry (%s)" % (s.get("stage_id"), f))

    # ---- reviews
    reviews_out = []
    rejected_specs = set()
    answered = {}
    for s in stages:
        if s.get("kind") != "review":
            continue
        sid = s.get("stage_id")
        pr = s.get("proposal_ref")
        if pr is None:
            reviews_out.append({"review_stage_id": sid, "shown": "proposal_not_named"})
        elif kind(pr) != "proposal":
            ab.failed("review %s names a proposal the attachment does not carry" % sid)
            reviews_out.append({"review_stage_id": sid, "shown": "proposal_not_named"})
        else:
            if "shown_bounds_digest" in s:
                ab.failed("review %s of bounds names a proposal: a proposal proposes a specification, not bounds" % sid)
            if s.get("shown_spec_digest") == by_id[pr].get("spec_digest"):
                reviews_out.append({"review_stage_id": sid, "shown": "as_proposed"})
            else:
                r = {"review_stage_id": sid, "shown": "differs_from_proposal"}
                if s.get("edited_by"):
                    r["edited_by"] = s["edited_by"]
                else:
                    ab.failed("review %s was shown something other than its proposal, with no editor named" % sid)
                reviews_out.append(r)

    # ---- outcomes and standing approvals
    approvals = {}   # stage_id -> approved digest (valid approvals of a specification)
    core_used = {}
    standing = {}    # stage_id -> dict
    for s in stages:
        k = s.get("kind")
        if k not in ("outcome", "standing_approval"):
            continue
        sid = s.get("stage_id")
        rr = s.get("review_ref")
        rv = by_id.get(rr) if kind(rr) == "review" else None
        if rv is None:
            ab.failed("%s %s does not answer a review in the attachment" % (k, sid))
        else:
            if rr in answered:
                ab.failed("review %s has more than one outcome (%s and %s)" % (rr, answered[rr], sid))
            else:
                answered[rr] = sid
            if s.get("actor_ref") != rv.get("reviewer_ref"):
                ab.failed("%s %s is not given by the person shown the review %s" % (k, sid, rr))
        cr = s.get("core_ref")
        if isinstance(cr, dict):
            key = (cr.get("field"), repr(cr.get("index")))
            if key in core_used:
                ab.failed("one core field backs two outcomes (%s and %s)" % (core_used[key], sid))
            else:
                core_used[key] = sid
        if k == "outcome":
            oc = s.get("outcome")
            if oc in ("rejected", "escalated") and rv is not None and "shown_spec_digest" in rv:
                rejected_specs.add(rv["shown_spec_digest"])
            if oc == "approved":
                if rv is not None and "shown_spec_digest" not in rv:
                    ab.failed("outcome %s approves bounds: an approval of bounds is a standing_approval stage" % sid)
                elif rv is not None and s.get("approved_spec_digest") != rv.get("shown_spec_digest"):
                    ab.failed("outcome %s approves another specification than review %s was shown" % (sid, rr))
                elif rv is not None:
                    approvals[sid] = s.get("approved_spec_digest")
        else:
            if rv is not None:
                if "shown_bounds_digest" not in rv:
                    ab.failed("standing approval %s answers a review that was not shown bounds" % sid)
                elif rv.get("shown_bounds_digest") != s.get("bounds_digest"):
                    ab.failed("standing approval %s approves other bounds than review %s was shown" % (sid, rr))
            if s.get("actor_ref") in proposers:
                ab.failed("standing approval %s is given by the proposer" % sid)
            if s.get("actor_ref") in services:
                ab.failed("standing approval %s is given by a service named in the attachment" % sid)
            st, bnd, bf = read_bounds(s)
            standing[sid] = {"status": st, "bounds": bnd, "findings": bf, "requests": 0, "revocations": []}

    # ---- revocations
    for i, s in enumerate(stages):
        if s.get("kind") != "standing_revocation":
            continue
        rr = s.get("revokes_ref")
        if kind(rr) != "standing_approval":
            ab.failed("revocation %s does not name a standing approval" % s.get("stage_id"))
            continue
        standing[rr]["revocations"].append(i)

    # ---- changes
    changes = {}
    uses = {}
    for s in stages:
        if s.get("kind") != "change_authorisation":
            continue
        sid = s.get("stage_id")
        fr = s.get("from_ref")
        fk = kind(fr)
        ok = True
        if fk == "standing_approval":
            ab.failed("change %s starts from a standing approval" % sid); ok = False
        elif fr in approvals:
            prev = approvals[fr]
        elif fr in changes:
            prev = changes[fr]
        else:
            ab.failed("change %s does not name an approval or an authorised change" % sid); ok = False
        if ok and s.get("spec_digest") == prev:
            ab.failed("change %s names the specification it changes" % sid)
        if s.get("actor_ref") in proposers:
            ab.failed("change %s is authorised by the proposer" % sid)
        if s.get("actor_ref") in services:
            ab.failed("change %s is authorised by a service named in the attachment" % sid)
        if s.get("spec_digest") in rejected_specs:
            ab.failed("change %s reaches a specification a reviewer rejected or escalated" % sid)
        if fr in approvals or fr in changes:
            uses[fr] = uses.get(fr, 0) + 1
        changes[sid] = s.get("spec_digest")

    # ---- requests
    req_ids = {}
    requests = {}
    per_spec = {}
    for i, s in enumerate(stages):
        if s.get("kind") != "request":
            continue
        sid = s.get("stage_id")
        rid = s.get("request_id")
        if rid in req_ids:
            ab.failed("request_id %s is used twice" % rid)
        req_ids[rid] = sid
        a = s.get("authorised_by")
        d = s.get("spec_digest")
        requests[sid] = s
        if a in approvals:
            if d != approvals[a]:
                ab.failed("request %s asks for another specification than approval %s binds" % (sid, a))
            uses[a] = uses.get(a, 0) + 1
            per_spec[d] = per_spec.get(d, 0) + 1
        elif a in changes:
            if d != changes[a]:
                ab.failed("request %s asks for another specification than change %s binds" % (sid, a))
            uses[a] = uses.get(a, 0) + 1
            per_spec[d] = per_spec.get(d, 0) + 1
            if d in rejected_specs:
                ab.failed("request %s reaches a specification a reviewer rejected or escalated" % sid)
        elif a in standing:
            sa = standing[a]
            sa["requests"] += 1
            if d in rejected_specs:
                ab.failed("request %s under standing approval %s reaches a specification a reviewer rejected or escalated" % (sid, a))
            # revocation: listed or dated after
            for ri in sa["revocations"]:
                rt, qt = at[ri], at[i]
                if ri < i:
                    ab.failed("request %s is listed after a recorded revocation of %s" % (sid, a))
                elif rt is None or qt is None:
                    ab.failed("request %s: whether it is dated after the revocation %s cannot be checked (a time that names no instant)" % (sid, stages[ri].get("stage_id")))
                elif qt > rt:
                    ab.failed("request %s is dated after a recorded revocation of %s" % (sid, a))
            if sa["status"] == "verified":
                b = sa["bounds"]
                vf, vu, qt = instant(b["valid_from"]), instant(b["valid_until"]), at[i]
                if qt is None:
                    ab.failed("request %s: its place in the period cannot be checked (a time that names no instant)" % sid)
                elif not (vf <= qt <= vu):
                    ab.failed("request %s is outside the period of %s" % (sid, a))
                st = spec_state.get(d)
                if st == "ok":
                    err = spec_inside(spec_obj[d], b)
                    if err:
                        ab.failed("request %s is outside the bounds of %s: %s" % (sid, a, err))
                elif st is None:
                    pass  # not carried: failed above
                elif st == "mismatch":
                    ab.failed("request %s: the specification's bytes do not match its digest" % sid)
                else:
                    ab.not_checked("request %s: the specification's bytes are %s, so it is not checked against the bounds" % (sid, st))
            elif sa["status"] == "failed":
                ab.failed("request %s rests on bounds that fail (%s)" % (sid, "; ".join(sa["findings"])))
            else:
                ab.not_checked("request %s rests on bounds that are %s: not checked against them" % (sid, sa["status"]))
        else:
            ab.failed("request %s does not rest on an approval, an authorised change or a standing approval" % sid)
    for sid, sa in standing.items():
        if sa["status"] == "verified" and sa["requests"] > sa["bounds"]["max_requests"]:
            ab.failed("standing approval %s: %d requests recorded, max_requests %d" % (sid, sa["requests"], sa["bounds"]["max_requests"]))
    for a, n in uses.items():
        st = by_id[a]
        lim = st.get("request_limit", 1)
        if not is_jint(lim):
            lim = 1
        if n > lim:
            ab.failed("%s covers %s request(s), and %d use it" % (a, lim, n))
    for d, n in per_spec.items():
        lims = [by_id[a].get("request_limit", 1) for a, x in approvals.items() if x == d]
        lims += [by_id[c].get("request_limit", 1) for c, x in changes.items() if x == d]
        lims = [l if is_jint(l) else 1 for l in lims]
        if lims and n > max(lims):
            ab.failed("specification %s is requested %d times, more than the largest request_limit (%d)" % (d[:12], n, max(lims)))

    # ---- attempts, executed specifications
    attempts = [(i, s) for i, s in enumerate(stages) if s.get("kind") == "attempt"]
    executed = []
    seen_exec = set()
    for i, s in attempts:
        sid = s.get("stage_id")
        q = requests.get(s.get("request_ref"))
        d = s.get("spec_digest")
        reached = "unbound"
        if q is None:
            ab.failed("attempt %s names no request" % sid)
        elif d != q.get("spec_digest"):
            ab.failed("attempt %s executes another specification than request %s asks for" % (sid, s.get("request_ref")))
        else:
            a = q.get("authorised_by")
            if a in approvals and approvals[a] == d:
                reached = "shown_to_reviewer"
            elif a in changes and changes[a] == d:
                reached = "via_change_only"
            elif a in standing:
                reached = "via_standing_approval"
        if reached == "unbound":
            ab.failed("attempt %s executes a specification no approval, change or standing approval binds" % sid)
        if d in spec_index and spec_index[d] not in seen_exec:
            seen_exec.add(spec_index[d])
            executed.append({"spec_index": spec_index[d], "reached_by": reached})

    # ---- stage order
    for sid in dup_ids:
        order.failed("stage id %s is used twice" % sid)
    for i, s in enumerate(stages):
        for f in REF_FIELDS:
            t = s.get(f)
            if f in s and t in pos:
                j = pos[t]
                if j >= i:
                    order.failed("%s is listed before %s, which it names" % (s.get("stage_id"), t))
                if at[i] is None or at[j] is None:
                    bad = s.get("stage_id") if at[i] is None else t
                    order.failed("the order of %s and %s cannot be checked: %s is dated with a time that names no instant" % (s.get("stage_id"), t, bad))
                elif at[j] > at[i]:
                    order.failed("%s is dated before %s, which it names" % (s.get("stage_id"), t))

    # ---- authorisation recheck
    rechecks = [(i, s) for i, s in enumerate(stages) if s.get("kind") == "recheck"]
    if not rechecks and not attempts:
        recheck.not_checked("no recheck or attempt is recorded")
    used_recheck = {}
    for i, s in attempts:
        sid = s.get("stage_id")
        c = s.get("recheck_ref")
        if kind(c) != "recheck":
            recheck.failed("attempt %s does not follow a recheck" % sid)
            continue
        ci = pos[c]
        cs = stages[ci]
        if cs.get("request_ref") != s.get("request_ref"):
            recheck.failed("attempt %s names a recheck of another request" % sid)
        if cs.get("result") != "authorised":
            recheck.failed("attempt %s follows a recheck that did not authorise it" % sid)
        if ci > i or at[ci] is None or at[i] is None or at[ci] > at[i]:
            recheck.failed("attempt %s does not follow its recheck %s" % (sid, c))
        later = [j for j, r in rechecks if r.get("request_ref") == s.get("request_ref") and ci < j < i]
        if later:
            recheck.failed("attempt %s: a later recheck (%s) comes before it" % (sid, stages[later[-1]].get("stage_id")))
        if c in used_recheck:
            recheck.failed("recheck %s authorises two attempts (%s and %s)" % (c, used_recheck[c], sid))
        else:
            used_recheck[c] = sid
    for j, r in rechecks:
        if r.get("result") != "authorised":
            continue
        q = requests.get(r.get("request_ref"))
        if q is None or q.get("authorised_by") not in standing:
            continue
        for ri in standing[q["authorised_by"]]["revocations"]:
            if ri < j:
                recheck.failed("recheck %s authorised a request after a recorded revocation" % r.get("stage_id"))
            elif at[ri] is None or at[j] is None:
                recheck.failed("recheck %s: whether it is dated after the revocation cannot be checked" % r.get("stage_id"))
            elif at[j] > at[ri]:
                recheck.failed("recheck %s authorised a request after a recorded revocation" % r.get("stage_id"))

    # ---- observed results
    results_for = {}
    for s in stages:
        if s.get("kind") == "result":
            a = s.get("attempt_ref")
            if kind(a) != "attempt":
                obs.failed("result %s names a stage that is not an attempt" % s.get("stage_id"))
                continue
            results_for.setdefault(a, []).append(s)
    attempts_out = []
    for i, s in attempts:
        sid = s.get("stage_id")
        rs = results_for.get(sid, [])
        if not rs:
            obs.failed("attempt %s has no result" % sid)
            attempts_out.append({"attempt_stage_id": sid, "observed": "missing"})
        elif len(rs) > 1:
            obs.failed("attempt %s has more than one result" % sid)
            attempts_out.append({"attempt_stage_id": sid, "observed": "multiple"})
        else:
            attempts_out.append({"attempt_stage_id": sid, "observed": rs[0].get("observed"), "basis": rs[0].get("basis")})
    if attempts:
        state = "attempted"
    elif requests:
        state = "requested_not_attempted"
    else:
        state = "not_requested"
    if not attempts:
        obs.not_checked("no execution attempt is recorded")
    obs_out = obs.out()
    obs_out["execution_state"] = state
    obs_out["attempts"] = attempts_out
    if state != "attempted":
        executed = []

    # ---- rationale provenance
    for i, s in enumerate(stages):
        r = s.get("rationale")
        if not isinstance(r, dict):
            continue
        t = r.get("timing")
        if t == "not_recorded":
            continue
        ra = instant(r.get("recorded_at"))
        if ra is None or at[i] is None:
            rat.failed("the rationale of %s: its timing cannot be checked (a time that names no instant)" % s.get("stage_id"))
        elif t == "contemporaneous" and ra > at[i]:
            rat.failed("the rationale of %s is presented as contemporaneous and recorded after the stage" % s.get("stage_id"))
        elif t == "later_supplemented" and ra <= at[i]:
            rat.failed("the rationale of %s is said to be supplemented later and is dated no later than the stage" % s.get("stage_id"))

    # ---- record statements
    if record_text is None:
        rec.not_checked("the decision record is not held")
    else:
        try:
            R = loads(record_text)
            if not isinstance(R, dict):
                raise Unreadable("not an object")
        except Unreadable as e:
            R = None
            rec.not_checked("the decision record cannot be read (%s)" % e)
        if R is not None:
            if R.get("decision_id") != att.get("decision_id"):
                rec.failed("the attachment names another decision record (%s) than the one held (%s)" % (att.get("decision_id"), R.get("decision_id")))
            da = R.get("drafting_authority")
            for s in stages:
                if s.get("kind") == "proposal" and s.get("origin") == "ai":
                    if not isinstance(da, dict):
                        rec.failed("an AI proposal, and the record has no drafting_authority")
                        continue
                    for k in ("deployer_role_pointer", "system_name", "version"):
                        if k in s and s[k] != da.get(k):
                            rec.failed("proposal %s: %s is not the record's drafting_authority" % (s.get("stage_id"), k))
            for i, s in enumerate(stages):
                k = s.get("kind")
                is_approval = (k == "outcome" and s.get("outcome") == "approved") or k == "standing_approval"
                if k not in ("outcome", "standing_approval"):
                    continue
                cr = s.get("core_ref")
                if not isinstance(cr, dict):
                    if is_approval:
                        rec.not_checked("approval %s names no core field: the record does not show it" % s.get("stage_id"))
                    continue
                word = s.get("outcome", "approved")
                if cr.get("field") == "affirmation_record":
                    ar = R.get("affirmation_record")
                    if not isinstance(ar, dict):
                        rec.failed("%s cites an affirmation_record the record does not carry" % s.get("stage_id")); continue
                    if ar.get("actor_identity") != s.get("actor_ref"):
                        rec.failed("%s: the actor is not the affirmation_record's" % s.get("stage_id"))
                    if ar.get("method") != s.get("method"):
                        rec.failed("%s: the method is not the affirmation_record's" % s.get("stage_id"))
                    ct = instant(ar.get("timestamp"))
                    if ct is None:
                        rec.not_checked("%s: the affirmation_record's time has no offset or names no instant" % s.get("stage_id"))
                    elif at[i] is None:
                        rec.failed("%s: its time names no instant" % s.get("stage_id"))
                    elif ct != at[i]:
                        rec.failed("%s: the time is not the affirmation_record's" % s.get("stage_id"))
                elif cr.get("field") == "review_log":
                    idx = cr.get("index")
                    if not is_jint(idx):
                        rec.not_checked("%s: the review_log index is not written as an integer" % s.get("stage_id")); continue
                    rl = R.get("review_log")
                    if not isinstance(rl, list) or idx >= len(rl) or not isinstance(rl[idx], dict):
                        rec.failed("%s cites a review_log entry the record does not carry" % s.get("stage_id")); continue
                    e = rl[idx]
                    if e.get("reviewer") != s.get("actor_ref"):
                        rec.failed("%s: the actor is not the review_log entry's reviewer" % s.get("stage_id"))
                    if e.get("outcome") not in KNOWN_OUTCOME_WORDS:
                        rec.not_checked("%s: the review_log outcome word %r is one the check does not know" % (s.get("stage_id"), e.get("outcome")))
                    elif e.get("outcome") != word:
                        rec.failed("%s: the outcome is not the review_log entry's (%s)" % (s.get("stage_id"), e.get("outcome")))
                    ct = instant(e.get("reviewed_at"))
                    if ct is None:
                        rec.not_checked("%s: the review_log time has no offset or names no instant" % s.get("stage_id"))
                    elif at[i] is None:
                        rec.failed("%s: its time names no instant" % s.get("stage_id"))
                    elif ct != at[i]:
                        rec.failed("%s: the time is not the review_log entry's" % s.get("stage_id"))

    unbound = any(e["reached_by"] == "unbound" for e in executed)
    if unbound and ab.status() != "failed":
        ab.failed("an executed specification is unbound")

    standing_out = []
    for sid, sa in standing.items():
        e = {"stage_id": sid, "bounds": {"status": sa["status"]}, "requests_recorded": sa["requests"],
             "revocation": "recorded" if sa["revocations"] else "none_recorded"}
        if sa["findings"]:
            e["bounds"]["findings"] = sa["findings"]
        if sa["status"] == "verified":
            e["max_requests"] = sa["bounds"]["max_requests"]
            e["valid_from"] = sa["bounds"]["valid_from"]
            e["valid_until"] = sa["bounds"]["valid_until"]
        e["findings"] = ["the count is of requests recorded, not requests run",
                         "the period is checked against the issuer's times",
                         "no revocation recorded means that and nothing more",
                         "no one is shown to have looked at any request",
                         "a standing approval approves nothing in any legal sense"]
        standing_out.append(e)

    so = order.out(); so["time_basis"] = "issuer_assertion"
    out = {
        "specifications": spec_results,
        "reviews": reviews_out,
        "executed_specifications": executed,
        "record_statements": rec.out(),
        "action_binding": ab.out(),
        "stage_order": so,
        "authorisation_recheck": recheck.out(),
        "observed_results": obs_out,
        "rationale_provenance": rat.out(),
    }
    if standing_out:
        out["standing_approvals"] = standing_out
    return out
