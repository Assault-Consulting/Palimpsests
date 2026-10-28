"""Independent verification of the PALA-1 SCITT Signed Statement, construction v3.

Bridge run B3. Built from RFC 9052 (COSE), RFC 9597 (CWT claims in COSE
headers), RFC 9679 (COSE Key Thumbprint), RFC 8032 (Ed25519), RFC 8949
(CBOR), RFC 6962 / RFC 9162 (Merkle trees and consistency proofs), the
PALA-1 core text (s1.2, s4.1, s4.3), consistency-proof.md (s1, s2) and
the published vector files. No COSE library, no CBOR library, no crypto
library, no Merkle library: cbor.py, ed25519.py and merkle.py in this
directory are ours (cbor.py and ed25519.py carried over from runs B1/B2).

Usage:
  python scitt_verify_v3.py <v3-vector.json> <v2-vector.json> \
                            <test-vectors.json> <consistency-vectors.json> \
                            <inference-vectors.json> [results.json]
"""

import hashlib
import json
import os
import sys
import time

import cbor
import ed25519
import merkle

# COSE header labels (RFC 9052 s3.1) and CWT claim keys (RFC 8392 s3.1.1).
LBL_ALG, LBL_CONTENT_TYPE, LBL_KID, LBL_CWT_CLAIMS = 1, 3, 4, 15
CWT_ISS, CWT_SUB = 1, 2
ALG_EDDSA = -8
TAG_COSE_SIGN1 = 18
TAG_COSE_SIGN = 98
KTY_OKP = 1
CRV_ED25519 = 6

CT_V2 = "application/vnd.palimpsests.pala1-head+cbor"
CT_V3 = "application/vnd.palimpsests.pala1-head-v3+cbor"
FORMAT_ID = "pala-1/v1.0"

results = []
findings = []
_fail = [0]


def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok:
        _fail[0] += 1
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    return ok


def divergence(tag, name, detail=""):
    """A place where the text, the vector and a standard do not agree.

    The task asks for these as first-class results, not as failures of this
    run: the run reproduces what it reproduces, and records the divergence
    precisely. Counted separately from check() failures.
    """
    findings.append({"tag": tag, "statement": name, "detail": detail})
    print("  [DIVERGENCE %s] %s%s" % (tag, name,
                                      ("\n      " + detail) if detail else ""))


def section(title):
    print("\n== %s ==" % title)


# ------------------------------------------------------------------ helpers

def sig_structure(protected_bstr, payload_bstr, external_aad=b""):
    """RFC 9052 s4.4: Sig_structure for COSE_Sign1 is the CBOR array
    ["Signature1", body_protected, external_aad, payload], assembled by the
    verifier -- never lifted out of the message."""
    return cbor.dumps(["Signature1", protected_bstr, external_aad, payload_bstr])


def thumbprint_bytewise(x):
    """RFC 9679: SHA-256 over the deterministically encoded CBOR map of the
    REQUIRED OKP members kty(1), crv(-1), x(-2). RFC 8949 s4.2.1 orders by
    the bytewise value of the ENCODED key, so 1 (0x01) < -1 (0x20) < -2 (0x21)."""
    enc = cbor.dumps(cbor.sort_keys_deterministic(
        {1: KTY_OKP, -1: CRV_ED25519, -2: x}))
    return hashlib.sha256(enc).digest(), enc


def thumbprint_numeric(x):
    """The other plausible reading: map keys in NUMERIC ascending order."""
    enc = cbor.dumps({-2: x, -1: CRV_ED25519, 1: KTY_OKP})
    return hashlib.sha256(enc).digest(), enc


def parse_sign1(raw, strict=True, require_tag=True):
    """Parse a tagged COSE_Sign1 (RFC 9052 s4.2)."""
    top = cbor.loads(raw, strict=strict)
    if isinstance(top, cbor.Tagged):
        if top.tag == TAG_COSE_SIGN:
            raise ValueError("tag 98 is COSE_Sign (multi-signature), not COSE_Sign1")
        if top.tag != TAG_COSE_SIGN1:
            raise ValueError("unexpected CBOR tag %d, want 18" % top.tag)
        body = top.value
    else:
        if require_tag:
            raise ValueError("untagged COSE_Sign1; expected tag 18 (first byte 0xd2)")
        body = top
    if not isinstance(body, list) or len(body) != 4:
        raise ValueError("COSE_Sign1 body must be a 4-element array")
    protected, unprotected, payload, signature = body
    if not isinstance(protected, bytes):
        raise ValueError("protected header must be a bstr")
    if not isinstance(unprotected, cbor.Map):
        raise ValueError("unprotected header must be a map")
    if not isinstance(signature, bytes):
        raise ValueError("signature must be a bstr")
    return protected, unprotected, payload, signature


# ------------------------------------------------- the construction reader

def read_statement(raw, pub, record_hashes=None):
    """Read a PALA-1 SCITT statement and apply the v2/v3 version rule.

    Returns a dict, never raises: {ok, reason, construction, ...}.
    The version rule (task "Version rule"):
      - the signed content type says which construction the statement is;
      - v2 carries exactly payload keys 1-4;
      - v3 carries exactly payload keys 1-5 with a 32-byte key 5;
      - key 5 under the v2 type, or the v3 type without key 5, is refused.

    record_hashes is the chain, when the caller holds it. It decides the
    difference the task insists on: without it the root is reported as
    CARRIED (the signature covers it, nothing more is known); with it the
    root is RECOMPUTED and compared.
    """
    out = {"ok": False, "reason": None, "construction": None,
           "root_status": None}
    try:
        protected, unprotected, payload, signature = parse_sign1(raw)
    except (ValueError, cbor.CBORError) as exc:
        out["reason"] = "parse: %s" % exc
        return out

    if not isinstance(payload, bytes):
        out["reason"] = "payload is not attached (nil payload)"
        return out
    if len(signature) != 64:
        out["reason"] = "signature is %d bytes, want 64" % len(signature)
        return out
    if not ed25519.verify(pub, sig_structure(protected, payload), signature):
        out["reason"] = "Ed25519 signature does not verify"
        return out
    out["signature_ok"] = True

    try:
        ph = cbor.loads(protected, strict=True)
        pl = cbor.loads(payload, strict=True)
    except cbor.CBORError as exc:
        out["reason"] = "decode: %s" % exc
        return out
    if not isinstance(ph, cbor.Map) or not isinstance(pl, cbor.Map):
        out["reason"] = "protected header and payload must both be CBOR maps"
        return out

    out["protected"], out["payload"] = ph, pl
    out["protected_bytes"], out["payload_bytes"] = protected, payload
    out["unprotected"], out["signature"] = unprotected, signature

    if ph.get(LBL_ALG) != ALG_EDDSA:
        out["reason"] = "alg is %r, want -8 (EdDSA)" % (ph.get(LBL_ALG),)
        return out
    ct = ph.get(LBL_CONTENT_TYPE)
    out["content_type"] = ct
    if ct not in (CT_V2, CT_V3):
        out["reason"] = "unknown content type %r" % (ct,)
        return out
    if not isinstance(ph.get(LBL_KID), bytes):
        out["reason"] = "kid (label 4) missing from the protected header"
        return out

    # ---- the version rule --------------------------------------------
    keys = pl.keys()
    if len(set(keys)) != len(keys):
        out["reason"] = "duplicate payload keys %r (RFC 8949 s5.6)" % (keys,)
        return out
    construction = "v3" if ct == CT_V3 else "v2"
    want = [1, 2, 3, 4, 5] if construction == "v3" else [1, 2, 3, 4]
    if keys != want:
        out["reason"] = ("version rule: content type names %s, which carries "
                         "exactly payload keys %r, but the payload carries %r"
                         % (construction, want, keys))
        return out
    if construction == "v3":
        root = pl.get(5)
        if not isinstance(root, bytes) or len(root) != 32:
            out["reason"] = ("version rule: payload key 5 must be 32 bytes, "
                             "got %r" % (root if not isinstance(root, bytes)
                                         else "%d bytes" % len(root),))
            return out
        out["root"] = root
    out["construction"] = construction

    head, first_seq, last_seq = pl.get(1), pl.get(2), pl.get(3)
    if not isinstance(head, bytes) or len(head) != 32:
        out["reason"] = "payload key 1 must be a 32-byte chain head"
        return out
    if not isinstance(first_seq, int) or isinstance(first_seq, bool) \
            or first_seq < 0:
        out["reason"] = "payload key 2 (first_seq) must be an unsigned integer"
        return out
    if not isinstance(last_seq, int) or isinstance(last_seq, bool) \
            or last_seq < 0:
        out["reason"] = "payload key 3 (last_seq) must be an unsigned integer"
        return out
    if pl.get(4) != FORMAT_ID:
        out["reason"] = "payload key 4 must be %r" % FORMAT_ID
        return out
    # Not stated by the task or the vector; see the ambiguity log (U5).
    if first_seq > last_seq:
        out["reason"] = ("first_seq (%d) > last_seq (%d): the reported range "
                         "is empty or inverted" % (first_seq, last_seq))
        return out

    out.update(head=head, first_seq=first_seq, last_seq=last_seq,
               size=last_seq + 1)

    if construction == "v3":
        if record_hashes is None:
            out["root_status"] = "carried"
        else:
            if len(record_hashes) < last_seq + 1:
                out["root_status"] = "chain-too-short"
            else:
                want_root = merkle.derived_root(record_hashes[:last_seq + 1])
                out["root_status"] = ("recomputed-ok" if want_root == out["root"]
                                      else "recomputed-mismatch")
                out["root_recomputed"] = want_root
                if out["root_status"] == "recomputed-mismatch":
                    out["reason"] = ("root does not match the derived root "
                                     "over records 0..%d" % last_seq)
                    return out

    out["ok"] = True
    out["reason"] = "ok"
    return out


def build_statement(seed, kid, issuer, subject, head, first_seq, last_seq,
                    content_type, root=None, payload_keys_in_order=True):
    """Construct a statement from the inputs. root=None builds a v2 payload."""
    ph = cbor.dumps(cbor.sort_keys_deterministic({
        LBL_ALG: ALG_EDDSA,
        LBL_CONTENT_TYPE: content_type,
        LBL_KID: kid,
        LBL_CWT_CLAIMS: cbor.sort_keys_deterministic(
            {CWT_ISS: issuer, CWT_SUB: subject}),
    }))
    pl_map = {1: head, 2: first_seq, 3: last_seq, 4: FORMAT_ID}
    if root is not None:
        pl_map[5] = root
    if payload_keys_in_order:
        pl = cbor.dumps(cbor.sort_keys_deterministic(pl_map))
    else:
        pl = cbor.dumps(dict(reversed(list(pl_map.items()))))
    sig = ed25519.sign(seed, sig_structure(ph, pl))
    return cbor.dumps(cbor.Tagged(TAG_COSE_SIGN1, [ph, {}, pl, sig]))


# ------------------------------- step 4, deliberately isolated by signature

def chainless_consistency_check(raw_earlier, raw_later, path, pub):
    """The case v3 exists for.

    This function's parameters ARE the claim: two statements, the proof
    path, and the public key. It cannot touch the chain, the vector's
    root_hex fields, or the vector's `first`/`second` -- there is no
    argument through which they could arrive. The two tree sizes are
    derived from each statement's own signed last_seq.

    Returns (ok, detail dict).
    """
    a = read_statement(raw_earlier, pub, record_hashes=None)
    b = read_statement(raw_later, pub, record_hashes=None)
    d = {"earlier": a["reason"], "later": b["reason"]}
    if not (a["ok"] and b["ok"]):
        return False, d
    if a["construction"] != "v3" or b["construction"] != "v3":
        d["why"] = "both statements must be construction v3 to carry roots"
        return False, d

    first, second = a["size"], b["size"]
    first_root, second_root = a["root"], b["root"]
    ok, why = merkle.verify_consistency(first, second, first_root,
                                        second_root, path)
    d.update(first=first, second=second,
             first_root=first_root.hex(), second_root=second_root.hex(),
             root_status=(a["root_status"], b["root_status"]),
             rfc9162=why)
    return ok, d


# --------------------------------------------------------------------- main

def main(argv):
    t0 = time.time()
    v3_path, v2_path, core_path, cons_path, inf_path = argv[1:6]
    out_path = argv[6] if len(argv) > 6 else "results.json"

    with open(v3_path, "rb") as fh:
        raw_v3 = fh.read()
    v = json.loads(raw_v3)
    with open(v2_path, "rb") as fh:
        raw_v2 = fh.read()
    v2 = json.loads(raw_v2)
    with open(core_path, "rb") as fh:
        raw_core = fh.read()
    core = json.loads(raw_core)
    with open(cons_path, "rb") as fh:
        raw_cons = fh.read()
    cons = json.loads(raw_cons)
    with open(inf_path, "rb") as fh:
        raw_inf = fh.read()
    inf = json.loads(raw_inf)

    print("PALA-1 SCITT Signed Statement v3 -- independent verification (B3)")
    print("v3 vector sha256:  %s" % hashlib.sha256(raw_v3).hexdigest())
    print("v2 vector sha256:  %s" % hashlib.sha256(raw_v2).hexdigest())
    print("core vectors:      %s" % hashlib.sha256(raw_core).hexdigest())
    print("consistency vecs:  %s" % hashlib.sha256(raw_cons).hexdigest())
    print("vector format: %s" % v["format"])

    seed = bytes.fromhex(v["key"]["private_seed_hex"])
    pub = bytes.fromhex(v["key"]["public_key_hex"])
    kid = bytes.fromhex(v["construction"]["kid_hex"])
    issuer = v["construction"]["issuer"]
    rh = [bytes.fromhex(x) for x in v["subject_chain"]["record_hashes_hex"]]
    st = v["statements"]

    # -- 0. our own toolchain, before trusting it with anything ------------
    section("0. toolchain self-test")
    check("ed25519.py reproduces RFC 8032 s7.1 TEST 1 and TEST 2",
          ed25519.selftest())
    check("vector public key derives from the vector seed (RFC 8032 s5.1.5)",
          ed25519.public_key(seed) == pub,
          "derived %s" % ed25519.public_key(seed).hex())
    check("merkle.py: PALA-1 s4.3 bottom-up tree == RFC 6962 recursive MTH "
          "for n=0..24, and build/verify round-trips for every 0<m<n<=24",
          merkle.selftest(), "PALA-1 s4.3 asserts the two agree; checked, "
          "not assumed")
    check("empty-tree root is SHA-256(\"\") (PALA-1 s4.3)",
          merkle.EMPTY == hashlib.sha256(b"").digest(), merkle.EMPTY.hex())

    # -- 1. roots ----------------------------------------------------------
    section("1. the derived roots, from the record hashes, with our own code")
    check("vector publishes 12 record hashes (seq 0..11)", len(rh) == 12,
          "%d" % len(rh))
    r8 = merkle.derived_root(rh[:8])
    r12 = merkle.derived_root(rh[:12])
    check("derived root over records 0..7 (8 leaves) == earlier.inputs.root_hex",
          r8.hex() == st["earlier"]["inputs"]["root_hex"], r8.hex())
    check("derived root over records 0..11 (12 leaves) == later.inputs.root_hex",
          r12.hex() == st["later"]["inputs"]["root_hex"], r12.hex())
    check("the two roots differ (the chain grew)", r8 != r12)
    check("earlier.inputs.chain_head_hex == record_hashes_hex[7] "
          "(the head is the last record's hash, PALA-1 s4.1)",
          st["earlier"]["inputs"]["chain_head_hex"] == rh[7].hex())
    check("later.inputs.chain_head_hex == record_hashes_hex[11]",
          st["later"]["inputs"]["chain_head_hex"] == rh[11].hex())

    # stretch: the record hashes themselves, from the published headers
    section("1b. stretch: recompute the record hashes from the headers "
            "(PALA-1 s4.1)")
    recs = core["records"]
    check("core test-vectors.json publishes 12 records", len(recs) == 12,
          "%d" % len(recs))
    n_ok = 0
    for i, r in enumerate(recs):
        hdr = bytes.fromhex(r["header_hex"])
        got = hashlib.sha256(hdr).digest()
        if got.hex() == r["record_hash"] and got == rh[i]:
            n_ok += 1
        else:
            check("record %d: SHA-256(header_bytes) matches" % i, False,
                  "got %s, vector %s" % (got.hex(), r["record_hash"]))
    check("record_hash == SHA-256(header_bytes) for all 12 records, and each "
          "equals the v3 vector's record_hashes_hex", n_ok == 12,
          "%d/12; the v3 vector's leaves are the published core vectors" % n_ok)
    check("header_len field equals the actual header length for all 12",
          all(int.from_bytes(bytes.fromhex(r["header_hex"])[6:8], "little")
              == len(bytes.fromhex(r["header_hex"])) for r in recs))
    check("re-derived chain head == core test-vectors.json chain_head",
          rh[11].hex() == core["chain_head"])

    # stretch: our tree and proof code against the published companion vectors
    section("1c. stretch: our tree/proof code against consistency-vectors.json "
            "(an independent 17-record chain)")
    inf_rh = [bytes.fromhex(r["record_hash"]) for r in inf["records"]]
    check("consistency-vectors source_chain_head == inference record_hash[16] "
          "(the file's tree is the 17-record prefix)",
          cons["source_chain_head"] == inf_rh[16].hex())
    nroots = sum(1 for k, val in cons["roots_by_count"].items()
                 if merkle.derived_root(inf_rh[:int(k)]).hex() == val)
    check("our derived_root reproduces roots_by_count for every count 0..17",
          nroots == len(cons["roots_by_count"]),
          "%d/%d" % (nroots, len(cons["roots_by_count"])))
    in_domain = [p for p in cons["proofs"] if 0 < p["first"] < p["second"]]
    out_domain = [p for p in cons["proofs"] if not 0 < p["first"] < p["second"]]
    pos_fail = []
    for p in in_domain:
        ok, why = merkle.verify_consistency(
            p["first"], p["second"], bytes.fromhex(p["first_root"]),
            bytes.fromhex(p["second_root"]),
            [bytes.fromhex(x) for x in p["path"]])
        if not ok:
            pos_fail.append((p["first"], p["second"], why))
        else:
            built = merkle.consistency_proof(p["first"], inf_rh[:p["second"]])
            check("  rebuilt RFC 6962 PROOF(%d, D[%d]) == published path"
                  % (p["first"], p["second"]),
                  [x.hex() for x in built] == p["path"])
    check("every published proof inside the RFC 9162 s2.1.4.2 input domain "
          "(0 < first < second) verifies, and its path rebuilds from the "
          "chain by RFC 6962 PROOF", not pos_fail,
          "%d of %d proofs are in domain; failures: %r"
          % (len(in_domain), len(cons["proofs"]), pos_fail))
    for p in out_domain:
        ok_d, why_d = merkle.verify_consistency(
            p["first"], p["second"], bytes.fromhex(p["first_root"]),
            bytes.fromhex(p["second_root"]),
            [bytes.fromhex(x) for x in p["path"]], enforce_domain=False)
        divergence(
            "F1",
            "consistency-vectors.json publishes a first == second proof "
            "(%d -> %d, empty path) among its positive cases, but RFC 9162 "
            "s2.1.4.2 cannot verify it" % (p["first"], p["second"]),
            "The RFC states its domain as '0 < first < second' and its step 1 "
            "is 'If consistency_path is an empty array, stop and fail the "
            "proof verification.' With the domain guard removed the algorithm "
            "still returns False: %r. consistency-proof.md s2 asserts both "
            "that the format 'verifies with RFC 9162 s2.1.4.2' and that "
            "'first == second has an empty proof and requires the roots to be "
            "equal'. Both cannot hold. The RFC wins, so the equal-size case is "
            "a PALA-1 pre-check that must be settled BEFORE s2.1.4.2 is "
            "entered -- not a proof that algorithm accepts. Does not affect "
            "the B3 statement vector (8 < 12, one-node path)." % why_d)
    for name, p in cons["negative"].items():
        if not isinstance(p, dict):
            continue
        ok, why = merkle.verify_consistency(
            p["first"], p["second"], bytes.fromhex(p["first_root"]),
            bytes.fromhex(p["second_root"]),
            [bytes.fromhex(x) for x in p["path"]])
        check("negative case %r verifies False" % name, not ok, why)

    # -- 2/3. parse, verify and check both statements ----------------------
    raws = {}
    for name in ("earlier", "later"):
        inp = st[name]["inputs"]
        exp = st[name]["expected"]
        raw = bytes.fromhex(exp["statement_hex"])
        raws[name] = raw
        head = bytes.fromhex(inp["chain_head_hex"])
        root = bytes.fromhex(inp["root_hex"])

        section("2.%s parse and verify the %r statement (v2 task steps 1-4)"
                % (name[0], name))
        check("first byte is 0xd2 (CBOR tag 18, tagged COSE_Sign1)",
              raw[:1] == b"\xd2", "got 0x%02x" % raw[0])
        try:
            protected, unprotected, payload, signature = parse_sign1(raw)
        except (ValueError, cbor.CBORError) as exc:
            check("parses as COSE_Sign1", False, str(exc))
            continue
        check("decodes under a STRICT RFC 8949 s4.2.1 decoder", True,
              "protected=%d B, payload=%d B, sig=%d B; no non-minimal heads, "
              "no indefinite lengths, no trailing bytes"
              % (len(protected), len(payload), len(signature)))
        check("unprotected bucket is empty", len(unprotected) == 0,
              "%d entr(ies)" % len(unprotected))
        check("payload is attached (a bstr, not nil)",
              isinstance(payload, bytes), "%d bytes" % len(payload))
        check("signature is 64 bytes", len(signature) == 64,
              "%d" % len(signature))
        tbs = sig_structure(protected, payload)
        check("Ed25519 signature verifies with key.public_key_hex "
              "over the RFC 9052 s4.4 Sig_structure",
              ed25519.verify(pub, tbs, signature),
              "Sig_structure %d bytes" % len(tbs))

        ph = cbor.loads(protected, strict=True)
        check("protected labels are exactly [1, 3, 4, 15]",
              ph.keys() == [1, 3, 4, 15], "got %r" % (ph.keys(),))
        check("labels are in RFC 8949 s4.2.1 bytewise-on-encoded-key order",
              ph.key_encodings == sorted(ph.key_encodings),
              "%r" % ([e.hex() for e in ph.key_encodings],))
        check("alg (label 1) is EdDSA (-8)", ph.get(LBL_ALG) == ALG_EDDSA,
              "got %r" % (ph.get(LBL_ALG),))
        check("kid (label 4) is in the PROTECTED bucket (RFC 9943 s6 MUST)",
              isinstance(ph.get(LBL_KID), bytes)
              and LBL_KID not in unprotected)
        tp, enc = thumbprint_bytewise(pub)
        tp_num, _ = thumbprint_numeric(pub)
        check("kid == construction.kid_hex", ph.get(LBL_KID) == kid,
              ph.get(LBL_KID).hex())
        check("kid is the RFC 9679 COSE Key Thumbprint (SHA-256) over "
              "{1:1, -1:6, -2:x} in RFC 8949 s4.2.1 order",
              ph.get(LBL_KID) == tp, "encoded key %s" % enc.hex())
        check("the numeric-key-order thumbprint is NOT what the vector used",
              ph.get(LBL_KID) != tp_num,
              "confirms s4.2.1 bytewise ordering (B1/B2 finding)")
        cwt = ph.get(LBL_CWT_CLAIMS)
        check("CWT claims (label 15) present in the protected bucket (RFC 9597)",
              isinstance(cwt, cbor.Map))
        check("CWT iss (claim 1) == construction.issuer",
              cwt.get(CWT_ISS) == issuer, "got %r" % (cwt.get(CWT_ISS),))
        check("CWT sub (claim 2) == inputs.subject",
              cwt.get(CWT_SUB) == inp["subject"], "got %r" % (cwt.get(CWT_SUB),))
        check("CWT sub carries the FULL 64-hex chain head, untruncated",
              cwt.get(CWT_SUB) == "pala-1:chain:" + head.hex())
        check("protected bucket re-encodes to identical bytes",
              cbor.dumps(ph) == protected)
        # RFC 9943 s6 conformance, re-checked for v3 (the B1 finding that
        # produced the kid fix must not regress under the new content type).
        check("RFC 9943 s6: neither x5t (34) nor x5chain (33) is present, "
              "which is exactly what makes kid MUST-present here",
              34 not in ph.keys() and 33 not in ph.keys()
              and 33 not in unprotected.keys())
        check("RFC 9943 s6: the CWT Claims header parameter is present and "
              "includes iss (1) and sub (2) -- both MUST",
              isinstance(cwt, cbor.Map) and CWT_ISS in cwt and CWT_SUB in cwt)
        check("RFC 9943 s6: iss is a string of 1..8192 characters",
              isinstance(cwt.get(CWT_ISS), str)
              and 1 <= len(cwt.get(CWT_ISS)) <= 8192,
              "%d characters" % len(cwt.get(CWT_ISS)))

        pl = cbor.loads(payload, strict=True)
        check("payload[1] == inputs.chain_head_hex (32 bytes)",
              pl.get(1) == head)
        check("payload[2] == first_seq (%d)" % inp["first_seq"],
              pl.get(2) == inp["first_seq"], "got %r" % (pl.get(2),))
        check("payload[3] == last_seq (%d)" % inp["last_seq"],
              pl.get(3) == inp["last_seq"], "got %r" % (pl.get(3),))
        check("payload[4] == 'pala-1/v1.0'", pl.get(4) == FORMAT_ID,
              "got %r" % (pl.get(4),))
        check("payload map keys are in RFC 8949 s4.2.1 deterministic order",
              cbor.dumps(pl) == payload)

        section("3.%s the new parts of v3 in the %r statement"
                % (name[0], name))
        check("content type (label 3) is the v3 string",
              ph.get(LBL_CONTENT_TYPE) == CT_V3,
              "%r" % (ph.get(LBL_CONTENT_TYPE),))
        check("content type is NOT the v2 string",
              ph.get(LBL_CONTENT_TYPE) != CT_V2)
        check("payload has exactly keys [1, 2, 3, 4, 5]",
              pl.keys() == [1, 2, 3, 4, 5], "got %r" % (pl.keys(),))
        check("payload[5] is a 32-byte byte string",
              isinstance(pl.get(5), bytes) and len(pl.get(5)) == 32,
              "%d bytes" % len(pl.get(5)))
        check("payload[5] == inputs.root_hex", pl.get(5) == root,
              pl.get(5).hex())
        own = merkle.derived_root(rh[:inp["last_seq"] + 1])
        check("payload[5] == OUR derived root over records 0..%d "
              "(%d leaves), computed in step 1"
              % (inp["last_seq"], inp["last_seq"] + 1),
              pl.get(5) == own, own.hex())
        if name == "later":
            check("the later root covers 0..11 even though its first_seq is 8 "
                  "(the root does not depend on first_seq)",
                  pl.get(5) == merkle.derived_root(rh[:12])
                  and pl.get(2) == 8,
                  "root over 12 leaves, reported range 8..11")
            check("a root over first_seq..last_seq (8..11) would NOT match",
                  pl.get(5) != merkle.derived_root(rh[8:12]),
                  "that value is %s" % merkle.derived_root(rh[8:12]).hex())

        # the reader, and the carried/recomputed distinction
        chainless = read_statement(raw, pub, record_hashes=None)
        withchain = read_statement(raw, pub, record_hashes=rh)
        check("reader accepts it as construction v3",
              chainless["ok"] and chainless["construction"] == "v3",
              chainless["reason"])
        check("without the chain the root is reported CARRIED, never verified",
              chainless["root_status"] == "carried",
              "root_status=%r" % chainless["root_status"])
        check("with the chain the root is RECOMPUTED and matches",
              withchain["root_status"] == "recomputed-ok",
              "root_status=%r" % withchain["root_status"])

        # -- 5. reproduce ---------------------------------------------------
        section("5.%s reproduce the %r statement byte-for-byte"
                % (name[0], name))
        built = build_statement(seed, kid, issuer, inp["subject"], head,
                                inp["first_seq"], inp["last_seq"], CT_V3,
                                root=root)
        bp, _, bpl, bsig = parse_sign1(built)
        check("independently built protected header == published bytes",
              bp == protected)
        check("independently built payload == published bytes", bpl == payload)
        check("independently produced Ed25519 signature == published signature",
              bsig == signature, "RFC 8032 determinism")
        check("REPRODUCED: whole statement == expected.statement_hex "
              "byte-for-byte", built == raw, "%d bytes" % len(built))
        check("statement_length_bytes == %d" % exp["statement_length_bytes"],
              len(raw) == exp["statement_length_bytes"], "%d" % len(raw))
        check("statement_sha256 matches",
              hashlib.sha256(raw).hexdigest() == exp["statement_sha256"],
              hashlib.sha256(raw).hexdigest())

    # -- 4. the case v3 exists for -----------------------------------------
    section("4. THE MAIN STEP: consistency from the two statements alone")
    path = [bytes.fromhex(x) for x in v["consistency"]["path"]]
    ok, d = chainless_consistency_check(raws["earlier"], raws["later"],
                                        path, pub)
    print("  inputs to chainless_consistency_check(): the two statement byte "
          "strings, the proof path, the public key -- nothing else is in "
          "its signature")
    print("  tree sizes derived from each statement's own signed last_seq: "
          "%r -> %r" % (d.get("first"), d.get("second")))
    print("  roots read out of the signed payloads: %s -> %s"
          % (d.get("first_root"), d.get("second_root")))
    check("BOTH roots were taken from the statements' payloads, not from "
          "the vector's root_hex and not recomputed from the chain",
          d.get("root_status") == ("carried", "carried"),
          "root_status=%r" % (d.get("root_status"),))
    check("prefix consistency VERIFIES by RFC 9162 s2.1.4.2: the 12-record "
          "state extends the 8-record state", ok, d.get("rfc9162", ""))
    check("the sizes derived from the statements match the proof document's "
          "own `first`/`second`",
          d.get("first") == v["consistency"]["first"]
          and d.get("second") == v["consistency"]["second"],
          "statements say %r/%r, document says %r/%r"
          % (d.get("first"), d.get("second"), v["consistency"]["first"],
             v["consistency"]["second"]))
    check("the roots read from the statements match the proof document's "
          "own first_root/second_root",
          d.get("first_root") == v["consistency"]["first_root"]
          and d.get("second_root") == v["consistency"]["second_root"])
    check("this check used NO record hash, NO chain, and NO vector root "
          "field -- two statements, one proof, one public key", ok,
          "%d-node path" % len(path))
    # and the proof path itself is reproducible from the chain, separately
    rebuilt = merkle.consistency_proof(8, rh[:12])
    check("separately, with the chain: RFC 6962 PROOF(8, D[12]) rebuilds the "
          "published path", [x.hex() for x in rebuilt]
          == v["consistency"]["path"],
          "%r" % ([x.hex() for x in rebuilt],))
    check("the single path node is the subtree root over records 8..11",
          rebuilt[0] == merkle.derived_root(rh[8:12]))

    # -- 6. tamper expectations --------------------------------------------
    section("6. tamper_expectations")
    raw_e, raw_l = raws["earlier"], raws["later"]
    pe, _, ple, sige = parse_sign1(raw_e)
    pl_e = cbor.loads(ple, strict=True)
    inp_e, inp_l = st["earlier"]["inputs"], st["later"]["inputs"]

    # T1 flip a bit of the root inside the payload
    off = ple.find(pl_e.get(5))
    t = bytearray(ple)
    t[off] ^= 0x01
    check("T1 flip a bit of the root inside the payload -> signature FAILS",
          not ed25519.verify(pub, sig_structure(pe, bytes(t)), sige),
          "root at payload offset %d" % off)

    # T2 a root that is not the derived root over 0..last_seq
    bad = build_statement(seed, kid, issuer, inp_e["subject"],
                          bytes.fromhex(inp_e["chain_head_hex"]), 0, 7, CT_V3,
                          root=bytes(32))
    r = read_statement(bad, pub, record_hashes=rh)
    check("T2 a wrong root, correctly signed -> chain-holding verifier "
          "REJECTS; the signature itself is valid",
          not r["ok"] and r.get("signature_ok") is True
          and r["root_status"] == "recomputed-mismatch", r["reason"])

    # T3 a root over first_seq..last_seq instead of the prefix
    wrong = merkle.derived_root(rh[8:12])
    bad3 = build_statement(seed, kid, issuer, inp_l["subject"],
                           bytes.fromhex(inp_l["chain_head_hex"]), 8, 11,
                           CT_V3, root=wrong)
    r3 = read_statement(bad3, pub, record_hashes=rh)
    check("T3a a root over first_seq..last_seq (8..11) -> REJECTED against "
          "the chain", not r3["ok"]
          and r3["root_status"] == "recomputed-mismatch", r3["reason"])
    ok3, _ = merkle.verify_consistency(8, 12, bytes.fromhex(
        inp_e["root_hex"]), wrong, path)
    check("T3b that root does not verify in the consistency proof either",
          not ok3)
    check("T3c NOTE: in this vector that wrong root is byte-identical to the "
          "proof's only path node -- the 8..11 subtree is a complete subtree, "
          "so the mistake yields a real node of the tree, not a random value",
          wrong == path[0], wrong.hex())

    # T4 a root over last_seq or last_seq+2 records
    for nrec, label in ((7, "last_seq (7) records"),
                        (9, "last_seq+2 (9) records")):
        badn = build_statement(seed, kid, issuer, inp_e["subject"],
                               bytes.fromhex(inp_e["chain_head_hex"]), 0, 7,
                               CT_V3, root=merkle.derived_root(rh[:nrec]))
        rn = read_statement(badn, pub, record_hashes=rh)
        check("T4 earlier statement with a root over %s instead of "
              "last_seq+1 (8) -> REJECTED" % label,
              not rn["ok"] and rn["root_status"] == "recomputed-mismatch",
              rn["reason"])
    bad11 = build_statement(seed, kid, issuer, inp_l["subject"],
                            bytes.fromhex(inp_l["chain_head_hex"]), 8, 11,
                            CT_V3, root=merkle.derived_root(rh[:11]))
    r11 = read_statement(bad11, pub, record_hashes=rh)
    check("T4 later statement with a root over 11 records instead of 12 "
          "-> REJECTED", not r11["ok"], r11["reason"])

    # T5 the version rule, with statements of our own
    v2_under_v3 = build_statement(seed, kid, issuer, inp_l["subject"],
                                  bytes.fromhex(inp_l["chain_head_hex"]),
                                  8, 11, CT_V3, root=None)
    v3_under_v2 = build_statement(seed, kid, issuer, inp_l["subject"],
                                  bytes.fromhex(inp_l["chain_head_hex"]),
                                  8, 11, CT_V2,
                                  root=bytes.fromhex(inp_l["root_hex"]))
    ra = read_statement(v2_under_v3, pub, record_hashes=rh)
    rb = read_statement(v3_under_v2, pub, record_hashes=rh)
    check("T5a a v2 payload (keys 1-4) under the v3 content type, signed with "
          "the vector's key -> REFUSED",
          not ra["ok"] and ra.get("signature_ok") is True, ra["reason"])
    check("T5b a v3 payload (keys 1-5) under the v2 content type, signed with "
          "the vector's key -> REFUSED",
          not rb["ok"] and rb.get("signature_ok") is True, rb["reason"])
    check("T5c both refusals happen with a VALID signature -- the version rule "
          "is a reading rule, not a crypto one",
          ed25519.verify(pub, sig_structure(*[parse_sign1(v2_under_v3)[i]
                                              for i in (0, 2)]),
                         parse_sign1(v2_under_v3)[3])
          and ed25519.verify(pub, sig_structure(*[parse_sign1(v3_under_v2)[i]
                                                  for i in (0, 2)]),
                             parse_sign1(v3_under_v2)[3]))

    # T6 drop the last path node, or swap the roots
    okd, whyd = merkle.verify_consistency(
        8, 12, bytes.fromhex(inp_e["root_hex"]),
        bytes.fromhex(inp_l["root_hex"]), path[:-1])
    check("T6a drop the last node of the path -> proof does NOT verify",
          not okd, whyd)
    oks, whys = merkle.verify_consistency(
        8, 12, bytes.fromhex(inp_l["root_hex"]),
        bytes.fromhex(inp_e["root_hex"]), path)
    check("T6b swap the two roots -> proof does NOT verify", not oks, whys)
    okz, whyz = merkle.verify_consistency(
        12, 8, bytes.fromhex(inp_l["root_hex"]),
        bytes.fromhex(inp_e["root_hex"]), path)
    check("T6c swap the two sizes as well -> still does NOT verify",
          not okz, whyz)

    # T7 carried vs recomputed, as a reporting discipline
    cl = read_statement(raw_l, pub, record_hashes=None)
    wc = read_statement(raw_l, pub, record_hashes=rh)
    check("T7 without the chain the verifier says CARRIED; only with the "
          "chain does it say RECOMPUTED -- it never says 'verified'",
          cl["root_status"] == "carried"
          and wc["root_status"] == "recomputed-ok"
          and "verified" not in (cl["root_status"], wc["root_status"]),
          "%r / %r" % (cl["root_status"], wc["root_status"]))

    # -- 7. regression: the v2 vector --------------------------------------
    section("7. regression -- the v2 vector still verifies and reads as v2")
    raw_v2st = bytes.fromhex(v2["expected"]["statement_hex"])
    r2 = read_statement(raw_v2st, pub, record_hashes=rh)
    check("v2 statement verifies and reads as construction v2",
          r2["ok"] and r2["construction"] == "v2", r2["reason"])
    check("v2 statement carries NO root (no payload key 5)",
          "root" not in r2 and r2["payload"].keys() == [1, 2, 3, 4],
          "keys %r" % (r2["payload"].keys(),))
    check("v2 root_status is None -- there is no root to call carried",
          r2["root_status"] is None)
    check("v2 statement bytes and sha256 unchanged from the v2 vector",
          hashlib.sha256(raw_v2st).hexdigest() == v2["expected"]["statement_sha256"]
          and len(raw_v2st) == v2["expected"]["statement_length_bytes"],
          "%d bytes" % len(raw_v2st))
    check("v2 and v3 statements of the same head differ in bytes and length",
          raw_v2st != raw_l and len(raw_v2st) != len(raw_l),
          "v2 %d B, v3 %d B, delta %d"
          % (len(raw_v2st), len(raw_l), len(raw_l) - len(raw_v2st)))
    check("a v2-only verifier (content type must be the v2 string) rejects "
          "the v3 statement BY TYPE, before reading the payload",
          cbor.loads(parse_sign1(raw_l)[0], strict=True).get(LBL_CONTENT_TYPE)
          != CT_V2, "the vector's relation_to_v2 claim")

    # -- 8. adversarial, our own design ------------------------------------
    section("8. adversarial cases of our own design")

    # A1 key 5 of the wrong length
    for n in (31, 33):
        b = build_statement(seed, kid, issuer, inp_l["subject"],
                            bytes.fromhex(inp_l["chain_head_hex"]), 8, 11,
                            CT_V3, root=bytes(n))
        ra1 = read_statement(b, pub, record_hashes=rh)
        check("A1 key 5 of %d bytes -> REFUSED on length, before any tree "
              "work" % n, not ra1["ok"], ra1["reason"])

    # A2 payload keys out of order
    oo = build_statement(seed, kid, issuer, inp_l["subject"],
                         bytes.fromhex(inp_l["chain_head_hex"]), 8, 11, CT_V3,
                         root=bytes.fromhex(inp_l["root_hex"]),
                         payload_keys_in_order=False)
    p_oo, _, pl_oo, s_oo = parse_sign1(oo)
    check("A2a payload keys in DESCENDING order: the signature still verifies "
          "(those bytes are what was signed)",
          ed25519.verify(pub, sig_structure(p_oo, pl_oo), s_oo))
    m_oo = cbor.loads(pl_oo, strict=True)
    r_oo = read_statement(oo, pub, record_hashes=rh)
    check("A2b ... but its ENCODED keys are in descending order, the "
          "deterministic re-encode differs from the published bytes, and our "
          "reader refuses it on the key list -- a reader that checked only "
          "the signature would accept it",
          m_oo.key_encodings != sorted(m_oo.key_encodings)
          and cbor.dumps(cbor.sort_keys_deterministic(dict(m_oo.pairs))) != pl_oo
          and oo != raw_l and not r_oo["ok"],
          "encoded keys %r; reader says: %s"
          % ([e.hex() for e in m_oo.key_encodings], r_oo["reason"]))

    # A3 duplicate key 5
    pl_src = cbor.loads(parse_sign1(raw_l)[2], strict=True)
    dup = b"\xa6" + parse_sign1(raw_l)[2][1:] + cbor.dumps(5) \
        + cbor.dumps(bytes(32))
    try:
        m = cbor.loads(dup, strict=True)
        rdup = read_statement(
            build_statement(seed, kid, issuer, inp_l["subject"],
                            bytes.fromhex(inp_l["chain_head_hex"]), 8, 11,
                            CT_V3, root=bytes.fromhex(inp_l["root_hex"])),
            pub, record_hashes=rh)
        check("A3 a payload with key 5 twice: a length-driven decoder accepts "
              "the map; RFC 8949 s5.6 calls it invalid, and which copy a "
              "dict-building decoder keeps decides the root",
              m.keys().count(5) == 2 and rdup["ok"],
              "our decoder surfaces both copies: %r" % (m.keys(),))
    except cbor.CBORError as exc:
        check("A3 duplicate payload key rejected by the decoder", True, str(exc))

    # A4 first_seq > last_seq
    inv = build_statement(seed, kid, issuer, inp_l["subject"],
                          bytes.fromhex(inp_l["chain_head_hex"]), 11, 8,
                          CT_V3, root=merkle.derived_root(rh[:9]))
    rinv = read_statement(inv, pub, record_hashes=rh)
    check("A4 first_seq (11) > last_seq (8): refused by OUR reader, but "
          "neither the task text nor the vector states this constraint",
          not rinv["ok"], rinv["reason"])

    # A5 head/root incoherence -- the chainless gap
    inc = build_statement(seed, kid, issuer, inp_l["subject"],
                          bytes.fromhex(inp_e["chain_head_hex"]),  # head of r7
                          8, 11, CT_V3,
                          root=bytes.fromhex(inp_l["root_hex"]))  # root of 12
    rinc_chainless = read_statement(inc, pub, record_hashes=None)
    rinc_chain = read_statement(inc, pub, record_hashes=rh)
    okinc, _ = chainless_consistency_check(raws["earlier"], inc, path, pub)
    check("A5 a statement whose head (record 7) and root (12 records) do not "
          "correspond: ACCEPTED without the chain, and the consistency proof "
          "still verifies -- nothing in the chainless check binds key 1 to "
          "key 5",
          rinc_chainless["ok"] and okinc,
          "the chainless check is a statement about ROOTS; the head rides "
          "along unchecked")
    check("A5b ... and a chain-holding verifier catches it only if it checks "
          "the head too: the root here IS the right root for last_seq=11",
          rinc_chain["ok"]
          and rinc_chain["head"] != rh[11],
          "root_status=%r, head=record 7 while last_seq=11"
          % rinc_chain["root_status"])

    # A6 first == second -- the RFC 9162 domain question
    oke, whye = merkle.verify_consistency(
        12, 12, bytes.fromhex(inp_l["root_hex"]),
        bytes.fromhex(inp_l["root_hex"]), [])
    check("A6a first == second with an empty path: our faithful RFC 9162 "
          "s2.1.4.2 returns False (see finding F1)", not oke, whye)
    oke2, whye2 = merkle.verify_consistency(
        12, 12, bytes.fromhex(inp_l["root_hex"]),
        bytes.fromhex(inp_l["root_hex"]), [], enforce_domain=False)
    check("A6b ... and still False with the domain guard removed, because the "
          "RFC's own step 1 fails an empty consistency_path", not oke2, whye2)

    # A7 a v3 statement with the root of a DIFFERENT chain
    foreign = merkle.derived_root(inf_rh[:12])
    fs = build_statement(seed, kid, issuer, inp_l["subject"],
                         bytes.fromhex(inp_l["chain_head_hex"]), 8, 11, CT_V3,
                         root=foreign)
    rfs_chainless = read_statement(fs, pub, record_hashes=None)
    rfs_chain = read_statement(fs, pub, record_hashes=rh)
    okfs, _ = chainless_consistency_check(raws["earlier"], fs, path, pub)
    check("A7 a root over a different chain entirely: accepted as CARRIED "
          "without the chain, rejected with it, and the consistency proof "
          "fails -- the proof is what catches it when no chain is held",
          rfs_chainless["ok"] and not rfs_chain["ok"] and not okfs,
          rfs_chain["reason"])

    # A8 tag/bytes vs signature, carried over from B1/B2 as a v3 regression
    untagged = raw_l[1:]
    check("A8 strip tag 18: a tag-requiring parser rejects the artifact while "
          "the signature over it is still valid (B1/B2 finding, unchanged "
          "in v3)",
          untagged[0] == 0x84
          and ed25519.verify(pub, sig_structure(*[parse_sign1(untagged,
                                                              require_tag=False)[i]
                                                  for i in (0, 2)]),
                             parse_sign1(untagged, require_tag=False)[3]))

    # A9 empty tree
    check("A9 the task's 'Construction v3' text states leaf/node/promote but "
          "omits the empty-tree root that PALA-1 s4.3 and consistency-proof.md "
          "s1 both give as SHA-256(\"\"); unreachable here because a payload "
          "always has last_seq >= 0, so the tree has >= 1 leaf", True,
          "documentation gap, not a byte divergence; see U3")

    # ------------------------------------------------------------------ done
    elapsed = time.time() - t0
    total = len(results)
    passed = total - _fail[0]
    print("\n== summary ==")
    print("  %d/%d checks passed, %d failed" % (passed, total, _fail[0]))
    print("  %d divergence(s) recorded as findings:" % len(findings))
    for f in findings:
        print("    %s  %s" % (f["tag"], f["statement"]))
    print("  wall clock in-run: %.2f s" % elapsed)

    with open(out_path, "w") as fh:
        json.dump({
            "run": "B3 -- SCITT statement construction v3",
            "v3_vector_sha256": hashlib.sha256(raw_v3).hexdigest(),
            "v2_vector_sha256": hashlib.sha256(raw_v2).hexdigest(),
            "core_vectors_sha256": hashlib.sha256(raw_core).hexdigest(),
            "consistency_vectors_sha256": hashlib.sha256(raw_cons).hexdigest(),
            "passed": passed, "total": total, "failed": _fail[0],
            "divergences": findings,
            "elapsed_seconds": round(elapsed, 3),
            "checks": results,
        }, fh, indent=2)
    print("  results written to %s" % os.path.abspath(out_path))
    return 1 if _fail[0] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
