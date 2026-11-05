"""VERIFY-ANCHOR of draft-fassbender-scitt-time-anchor-08, Section 4.1, written from the text, on top of reading 2's
parser and replay (dps-reading-2/verifier/dpsr/ots.py: parse, replay, bitcoin_height), whose logic is used unchanged.
Reading 2's verifier is imported by path (load_reading2); nothing in it is copied or modified.

Returns exactly one of valid, invalid, unverifiable (Section 4.3), with the step whose RETURN produced it and, where the
RETURN is step 8's, the step that left the branch unevaluated (5 or 7b). Every step's result is kept in a trace.
"""
import datetime as dt
import hashlib
import os
import re
import sys

import cbor2

O = None      # reading 2's dpsr.ots
R2 = None     # reading 2's ots_replay (constants of Appendix D, header_fields, sha256d, target, chain_checks)

MIN_CONFIRMATIONS = 6           # Section 4.1, step 9: "MIN_CONFIRMATIONS is 6 under this profile"
CLAIMED_HASH_RE = re.compile(r"(sha256:)?[0-9a-f]{64}")   # Section 3.4.3; CDDL .regexp matches the whole string
BUNDLE_KEYS = {"ots_proof", "claimed_hash", "origin_id", "bitcoin_block_height"}


def load_reading2(reading2_dir):
    """Import reading 2's verifier from DIR/verifier, unchanged."""
    global O, R2
    vdir = os.path.join(os.path.abspath(reading2_dir), "verifier")
    if vdir not in sys.path:
        sys.path.insert(0, vdir)
    from dpsr import ots as _ots  # noqa: E402
    import ots_replay as _r2  # noqa: E402
    O, R2 = _ots, _r2
    return O, R2


# ---------------------------------------------------------------- Proof Bundle (Section 3.4.3, Section 2.2)

class BundleError(ValueError):
    pass


def make_bundle(ots_proof, claimed_hash, origin_id=None, bitcoin_block_height=None):
    """A ProofBundle as Section 3.4.3's CDDL defines it, encoded as CBOR (ambiguity log B01, B02)."""
    m = {"ots_proof": bytes(ots_proof), "claimed_hash": claimed_hash}
    if origin_id is not None:
        m["origin_id"] = origin_id
    if bitcoin_block_height is not None:
        m["bitcoin_block_height"] = bitcoin_block_height
    b = cbor2.dumps(m, canonical=True)
    read_bundle(b)  # a bundle this harness builds must match the CDDL
    return b


def read_bundle(b):
    """Decode and hold against the CDDL of Section 3.4.3. Raises BundleError (ambiguity log B03)."""
    try:
        m = cbor2.loads(b)
    except Exception as e:  # noqa: BLE001
        raise BundleError("not CBOR: %s" % e)
    if not isinstance(m, dict):
        raise BundleError("not a map")
    extra = set(m) - BUNDLE_KEYS
    if extra:
        raise BundleError("members the CDDL does not define: %s" % sorted(map(str, extra)))
    if not isinstance(m.get("ots_proof"), bytes):
        raise BundleError("ots_proof missing or not bytes")
    ch = m.get("claimed_hash")
    if not isinstance(ch, str) or not CLAIMED_HASH_RE.fullmatch(ch):
        raise BundleError("claimed_hash missing or not matching (sha256:)?[0-9a-f]{64}")
    if "origin_id" in m and not isinstance(m["origin_id"], str):
        raise BundleError("origin_id not tstr")
    if "bitcoin_block_height" in m and (isinstance(m["bitcoin_block_height"], bool) or
                                        not isinstance(m["bitcoin_block_height"], int) or m["bitcoin_block_height"] < 0):
        raise BundleError("bitcoin_block_height not uint")
    return m


# ---------------------------------------------------------------- Encoding utilities (Section 4.1)

def HEX(b):
    return b.hex()


def STRIP_PREFIX(s):
    return s[len("sha256:"):] if s.startswith("sha256:") else s


# ---------------------------------------------------------------- the procedure

class Outcome:
    __slots__ = ("verdict", "return_step", "cause", "trace")

    def __init__(self, verdict, return_step, cause, trace):
        self.verdict, self.return_step, self.cause, self.trace = verdict, return_step, cause, trace

    def as_dict(self):
        return {"verdict": self.verdict, "return_step": self.return_step, "cause": self.cause, "trace": self.trace}


STEPS = ["1", "2", "3", "4", "5", "6", "7a", "7b", "8", "9", "10", "11"]


def _done(verdict, step, cause, trace):
    for s in STEPS[STEPS.index(step) + 1:]:
        trace.setdefault(s, "not reached")
    return Outcome(verdict, step, cause, trace)


def _has_bitcoin_attestation(node):
    stack = [node]
    while stack:
        n = stack.pop()
        if any(t8 == O.TAG_BITCOIN for (t8, _p) in n.atts):
            return True
        stack.extend(c for (_t, _n, _a, c) in n.ops)
    return False


def verify_anchor(artifact_bytes, proof_bundle, validated_chain, header_source):
    """VERIFY-ANCHOR(artifact_bytes, proof_bundle, validated_chain). proof_bundle is the CBOR bytes of a ProofBundle.
    validated_chain is None (the verifier holds no view) or an object with validate(H, candidate) and
    confirmations(H). header_source is FETCH-BLOCK-HEADER-BY-HEIGHT's source: an object with fetch(H)."""
    t = {}
    pb = read_bundle(proof_bundle)

    # 1. RECOMPUTE HASH
    computed_hash = hashlib.sha256(artifact_bytes).digest()
    t["1"] = {"computed_hash": HEX(computed_hash)}

    # 2. COMPARE HASH
    claimed = STRIP_PREFIX(pb["claimed_hash"])
    if HEX(computed_hash) != claimed:
        t["2"] = {"claimed_hash_stripped": claimed, "equal": False}
        return _done("invalid", "2", "HEX(computed_hash) != STRIP-PREFIX(claimed_hash)", t)
    t["2"] = {"equal": True}

    # 3. PARSE OTS PROOF  (OTS-DESERIALIZE = reading 2's parse; a Bitcoin attestation whose payload is not a height
    #    is a parse failure, ambiguity log B05)
    try:
        file_hash_op, msg, root = O.parse(pb["ots_proof"])
        atts = O.replay(root, computed_hash)  # enumerates every path; also step 5's replay (see below)
        for a in atts:
            if a["tag"] == O.TAG_BITCOIN:
                a["height"] = O.bitcoin_height(a["payload"])
    except O.ProofError as e:
        t["3"] = {"parsed": None, "reason": str(e)}
        return _done("invalid", "3", "OTS-DESERIALIZE returned NULL: %s" % e, t)
    if file_hash_op != "sha256":
        t["3"] = {"file_hash_op": file_hash_op}
        return _done("invalid", "3", "parsed.file_hash_op != SHA-256", t)
    if msg != computed_hash:
        t["3"] = {"parsed_msg": HEX(msg), "equal_to_computed_hash": False}
        return _done("invalid", "3", "parsed.msg != computed_hash", t)
    t["3"] = {"parsed": True, "file_hash_op": "sha256", "msg_equals_computed_hash": True}

    # 4. CHECK PROOF STATUS
    if not _has_bitcoin_attestation(root):
        t["4"] = {"bitcoin_attestation": False}
        return _done("unverifiable", "4", "no Bitcoin attestation", t)
    branches = [a for a in atts if a["tag"] == O.TAG_BITCOIN]
    t["4"] = {"bitcoin_attestation": True, "bitcoin_branches": len(branches),
              "other_attestations": len(atts) - len(branches)}

    # 5. REPLAY EACH BITCOIN BRANCH: OTS-REPLAY(b, computed_hash) is reading 2's replay from computed_hash; it gives
    #    None for a branch with an operation other than append, prepend and sha256 (Section 4.1, OTS-REPLAY).
    t["5"] = [{"operations": len(b["path"]), "digest": HEX(b["digest"]) if b["digest"] is not None else None,
               "unsupported": b["unsupported"]} for b in branches]

    # 6. READ EACH BRANCH'S ATTESTED HEIGHT (decoded at step 3, see above)
    t["6"] = [b["height"] for b in branches]

    # 7a. RETRIEVE A CANDIDATE HEADER, PER BRANCH
    for b in branches:
        b["candidate"] = header_source.fetch(b["height"])
    t["7a"] = [{"H": b["height"], "candidate": HEX(b["candidate"]) if b["candidate"] is not None else None,
                "source": header_source.label} for b in branches]

    # 7b. PLACE EACH CANDIDATE ON THE VALIDATED CHAIN
    for b in branches:
        b["header"] = None if validated_chain is None else validated_chain.validate(b["height"], b["candidate"])
    t["7b"] = [{"H": b["height"], "header": None if b["header"] is None else "the candidate",
                "validated_chain": "none" if validated_chain is None else validated_chain.label} for b in branches]

    # 8. CLASSIFY EACH BRANCH, THEN COMBINE
    for b in branches:
        if b["digest"] is None:
            b["state"] = "unsupported"
        elif b["header"] is None:
            b["state"] = "unavailable"
        elif b["digest"] == b["header"][36:68]:
            b["state"] = "verified"
        else:
            b["state"] = "mismatched"
    t["8"] = {"states": [b["state"] for b in branches]}
    verified = [b for b in branches if b["state"] == "verified"]
    if not verified:
        unevaluated = [b for b in branches if b["state"] in ("unavailable", "unsupported")]
        if unevaluated:
            causes = sorted({"7b" if b["state"] == "unavailable" else "5" for b in unevaluated})
            return _done("unverifiable", "8",
                         "no branch verified; unevaluated: %s (step %s)" % (
                             ", ".join(b["state"] for b in unevaluated), " and ".join(causes)), t)
        return _done("invalid", "8", "every branch evaluated, none replayed to its header's Merkle root", t)
    bstar = min(verified, key=lambda b: b["height"])
    H, header = bstar["height"], bstar["header"]
    t["8"]["selected_H"] = H

    # 9. CHECK CONFIRMATION DEPTH
    k = validated_chain.confirmations(H)
    t["9"] = {"k": k, "MIN_CONFIRMATIONS": MIN_CONFIRMATIONS}
    if k is None or k < MIN_CONFIRMATIONS:
        return _done("unverifiable", "9", "confirmations %s < %d" % (k, MIN_CONFIRMATIONS) if k is not None
                     else "CONFIRMATIONS-ON returned NULL", t)

    # 10. DERIVE THE TEMPORAL VALUES
    f = R2.header_fields(header)
    t["10"] = {"block_height_H": H,
               "block_time_RWCP": dt.datetime.fromtimestamp(f["time"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "median_time_past": "not attempted: OPTIONAL, and the eleven headers before H are not held"}

    # 11. RETURN valid
    t["11"] = "valid"
    return Outcome("valid", "11", "steps 1 to 10 passed", t)
