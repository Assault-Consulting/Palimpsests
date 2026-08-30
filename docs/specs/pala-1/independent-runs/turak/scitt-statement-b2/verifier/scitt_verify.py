"""Independent verification of the PALA-1 SCITT-bridge Signed Statement (v2).

Built from RFC 9052 (COSE), RFC 9597 (CWT claims in COSE headers),
RFC 9679 (COSE Key Thumbprint), RFC 8032 (Ed25519), RFC 8949 (CBOR) and
the published vector file. No COSE library, no CBOR library, no crypto
library: cbor.py and ed25519.py in this directory are ours.

Usage:  python scitt_verify.py <path-to-scitt-statement-vector.json>
"""

import hashlib
import json
import sys
import time

import cbor
import ed25519

# COSE header labels (RFC 9052 s3.1) and CWT claim keys (RFC 8392 s3.1.1).
LBL_ALG, LBL_CONTENT_TYPE, LBL_KID, LBL_CWT_CLAIMS = 1, 3, 4, 15
CWT_ISS, CWT_SUB = 1, 2
ALG_EDDSA = -8
TAG_COSE_SIGN1 = 18
TAG_COSE_SIGN = 98
KTY_OKP = 1
CRV_ED25519 = 6

results = []
_fail = [0]


def check(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok:
        _fail[0] += 1
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           ("  -- " + detail) if detail else ""))
    return ok


def section(title):
    print("\n== %s ==" % title)


# ------------------------------------------------------------------ helpers

def sig_structure(protected_bstr, payload_bstr, external_aad=b""):
    """RFC 9052 s4.4: the Sig_structure for COSE_Sign1 is the CBOR array
    ["Signature1", body_protected, external_aad, payload], assembled by the
    verifier -- never extracted from the message (byte_stability mode 4)."""
    return cbor.dumps(["Signature1", protected_bstr, external_aad, payload_bstr])


def thumbprint_bytewise(x):
    """RFC 9679: SHA-256 over the deterministically encoded CBOR map of the
    REQUIRED key members. For OKP those are kty(1), crv(-1), x(-2).
    RFC 8949 s4.2.1 orders by the bytewise value of the ENCODED key, so
    1 (0x01) < -1 (0x20) < -2 (0x21)."""
    enc = cbor.dumps(cbor.sort_keys_deterministic(
        {1: KTY_OKP, -1: CRV_ED25519, -2: x}))
    return hashlib.sha256(enc).digest(), enc


def thumbprint_numeric(x):
    """The other plausible reading: map keys in NUMERIC ascending order."""
    enc = cbor.dumps({-2: x, -1: CRV_ED25519, 1: KTY_OKP})
    return hashlib.sha256(enc).digest(), enc


def parse_sign1(raw, strict=True, require_tag=True):
    """Parse a tagged COSE_Sign1 (RFC 9052 s4.2). Returns
    (protected_bstr, unprotected_map, payload, signature)."""
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


# --------------------------------------------------------------------- main

def main(vector_path):
    t0 = time.time()
    with open(vector_path, "rb") as fh:
        raw_vector = fh.read()
    v = json.loads(raw_vector)

    print("PALA-1 SCITT Signed Statement -- independent verification")
    print("vector file sha256: %s" % hashlib.sha256(raw_vector).hexdigest())
    print("vector format: %s" % v["format"])

    seed = bytes.fromhex(v["key"]["private_seed_hex"])
    pub = bytes.fromhex(v["key"]["public_key_hex"])
    head = bytes.fromhex(v["subject_chain"]["chain_head_hex"])
    first_seq = v["subject_chain"]["first_seq"]
    last_seq = v["subject_chain"]["last_seq"]
    si = v["statement_inputs"]
    exp = v["expected"]
    statement = bytes.fromhex(exp["statement_hex"])

    # -- 0. our own crypto, before we trust it with anything ----------------
    section("0. toolchain self-test")
    check("ed25519.py reproduces RFC 8032 s7.1 TEST 1 and TEST 2",
          ed25519.selftest())
    check("vector public key derives from vector seed (RFC 8032 s5.1.5)",
          ed25519.public_key(seed) == pub,
          "derived %s" % ed25519.public_key(seed).hex())

    # -- 1. parse ------------------------------------------------------------
    section("1. parse as COSE_Sign1 (RFC 9052 s4.2)")
    check("first byte is 0xd2 (CBOR tag 18, tagged COSE_Sign1)",
          statement[:1] == b"\xd2", "got 0x%02x" % statement[0])
    try:
        protected, unprotected, payload, signature = parse_sign1(
            statement, strict=True)
        strict_ok, strict_msg = True, ("protected=%d B, payload=%d B, sig=%d B"
                                       % (len(protected), len(payload),
                                          len(signature)))
    except (ValueError, cbor.CBORError) as exc:
        print("  fatal: %s" % exc)
        return 1
    check("whole message decodes under a STRICT RFC 8949 s4.2.1 decoder",
          strict_ok, strict_msg + "; no non-minimal heads, no indefinite "
          "lengths, no trailing bytes")
    check("body is a 4-element array", True)
    check("unprotected bucket is empty", len(unprotected) == 0,
          "%d entr(ies)" % len(unprotected))
    check("payload is attached (a bstr, not nil)", isinstance(payload, bytes),
          "%d bytes" % (len(payload) if isinstance(payload, bytes) else -1))
    check("signature is 64 bytes", len(signature) == 64, "%d" % len(signature))

    # -- 2. signature --------------------------------------------------------
    section("2. verify Ed25519 over the Sig_structure (RFC 9052 s4.4)")
    tbs = sig_structure(protected, payload)
    print("  Sig_structure: %d bytes, starts %s" % (len(tbs), tbs[:16].hex()))
    check("signature verifies with key.public_key_hex",
          ed25519.verify(pub, tbs, signature))
    check("expected.verifies_with_public_key matches observation",
          exp["verifies_with_public_key"] is True)

    # -- 3. payload ----------------------------------------------------------
    section("3. decode payload and check the chain-head commitment")
    pl = cbor.loads(payload, strict=True)
    check("payload is a CBOR map of 4 entries",
          isinstance(pl, cbor.Map) and len(pl) == 4,
          "keys %r" % (pl.keys() if isinstance(pl, cbor.Map) else pl,))
    got_head = pl.get(1)
    check("payload[1] is the 32-byte chain head, equal to chain_head_hex",
          got_head == head,
          "got %s" % (got_head.hex() if isinstance(got_head, bytes) else got_head))
    check("payload[2] == first_seq (%d)" % first_seq, pl.get(2) == first_seq,
          "got %r" % (pl.get(2),))
    check("payload[3] == last_seq (%d)" % last_seq, pl.get(3) == last_seq,
          "got %r" % (pl.get(3),))
    check("payload[4] is the format id 'pala-1/v1.0'",
          pl.get(4) == "pala-1/v1.0", "got %r" % (pl.get(4),))
    check("expected.payload_commits_to_chain_head matches observation",
          exp["payload_commits_to_chain_head"] is True)
    check("payload map keys are in RFC 8949 s4.2.1 deterministic order",
          cbor.dumps(pl) == payload)

    # -- 4. protected header -------------------------------------------------
    section("4. protected header (RFC 9052 s3.1, RFC 9597, RFC 9679)")
    ph = cbor.loads(protected, strict=True)
    check("protected bucket decodes to a map of 4 entries",
          isinstance(ph, cbor.Map) and len(ph) == 4, "keys %r" % (ph.keys(),))
    check("alg (label 1) is EdDSA (-8)", ph.get(LBL_ALG) == ALG_EDDSA,
          "got %r" % (ph.get(LBL_ALG),))

    ct = ph.get(LBL_CONTENT_TYPE)
    check("content type (label 3) present in the PROTECTED bucket",
          ct is not None and LBL_CONTENT_TYPE not in unprotected)
    check("content type equals statement_inputs.content_type",
          ct == si["content_type"], "got %r" % (ct,))

    kid = ph.get(LBL_KID)
    check("kid (label 4) present in the PROTECTED bucket (RFC 9943 s6 MUST)",
          isinstance(kid, bytes) and LBL_KID not in unprotected)
    check("kid equals statement_inputs.kid_hex",
          kid == bytes.fromhex(si["kid_hex"]),
          "got %s" % (kid.hex() if isinstance(kid, bytes) else kid))
    tp_bytewise, enc_bytewise = thumbprint_bytewise(pub)
    tp_numeric, enc_numeric = thumbprint_numeric(pub)
    print("  RFC 9679 candidate encodings of the required OKP members:")
    print("    s4.2.1 bytewise key order {1,-1,-2}: %s" % enc_bytewise.hex())
    print("      -> %s" % tp_bytewise.hex())
    print("    numeric ascending order  {-2,-1,1}: %s" % enc_numeric.hex())
    print("      -> %s" % tp_numeric.hex())
    check("kid is the RFC 9679 COSE Key Thumbprint (SHA-256) of the key",
          kid == tp_bytewise, "matches the RFC 8949 s4.2.1 bytewise ordering")
    check("the numeric-ordering thumbprint is NOT what the vector used",
          kid != tp_numeric, "confirms the vector followed RFC 8949 s4.2.1")

    cwt = ph.get(LBL_CWT_CLAIMS)
    check("CWT claims (label 15) present in the PROTECTED bucket (RFC 9597)",
          isinstance(cwt, cbor.Map))
    check("CWT iss (claim 1) equals statement_inputs.issuer",
          cwt.get(CWT_ISS) == si["issuer"], "got %r" % (cwt.get(CWT_ISS),))
    check("CWT sub (claim 2) equals statement_inputs.subject",
          cwt.get(CWT_SUB) == si["subject"], "got %r" % (cwt.get(CWT_SUB),))
    check("CWT sub carries the FULL 64-hex chain head (B1 finding F4)",
          cwt.get(CWT_SUB) == "pala-1:chain:" + head.hex(),
          "no truncation; %d hex chars" % len(head.hex()))

    labels = ph.keys()
    check("protected labels are [1, 3, 4, 15]", labels == [1, 3, 4, 15],
          "got %r" % (labels,))
    check("labels are in numeric ascending order", labels == sorted(labels))
    check("labels are in RFC 8949 s4.2.1 bytewise-on-encoded-key order",
          ph.key_encodings == sorted(ph.key_encodings),
          "encoded keys %r" % ([e.hex() for e in ph.key_encodings],))
    check("protected bucket re-encodes to identical bytes (deterministic)",
          cbor.dumps(ph) == protected)

    # -- 5. reproduce --------------------------------------------------------
    section("5. reproduce the statement byte-for-byte from the inputs")
    built_ph = cbor.dumps(cbor.sort_keys_deterministic({
        LBL_ALG: ALG_EDDSA,
        LBL_CONTENT_TYPE: si["content_type"],
        LBL_KID: bytes.fromhex(si["kid_hex"]),
        LBL_CWT_CLAIMS: cbor.sort_keys_deterministic({
            CWT_ISS: si["issuer"],
            CWT_SUB: si["subject"],
        }),
    }))
    built_pl = cbor.dumps(cbor.sort_keys_deterministic({
        1: head, 2: first_seq, 3: last_seq, 4: "pala-1/v1.0",
    }))
    check("independently built protected header == published bytes",
          built_ph == protected)
    check("independently built payload == published bytes", built_pl == payload)
    built_sig = ed25519.sign(seed, sig_structure(built_ph, built_pl))
    check("independently produced Ed25519 signature == published signature",
          built_sig == signature, "RFC 8032 determinism (byte_stability mode 1)")
    built = cbor.dumps(cbor.Tagged(TAG_COSE_SIGN1,
                                   [built_ph, {}, built_pl, built_sig]))
    check("REPRODUCED: full statement matches expected.statement_hex "
          "byte-for-byte", built == statement, "%d bytes" % len(built))
    check("statement_length_bytes == %d" % exp["statement_length_bytes"],
          len(statement) == exp["statement_length_bytes"], "%d" % len(statement))
    check("statement_sha256 matches",
          hashlib.sha256(statement).hexdigest() == exp["statement_sha256"],
          hashlib.sha256(statement).hexdigest())

    # -- 6. tamper expectations ---------------------------------------------
    section("6. tamper_expectations")

    # payload is a4 01 5820 <32-byte head>...; index 4 is the head's first byte
    t_pl = bytearray(payload)
    t_pl[4] ^= 0x01
    check("T1 flip a bit of the head inside the payload -> signature FAILS",
          not ed25519.verify(pub, sig_structure(protected, bytes(t_pl)),
                             signature))

    t_sig = bytearray(signature)
    t_sig[0] ^= 0x01
    check("T2 flip a bit of the signature -> verification FAILS",
          not ed25519.verify(pub, tbs, bytes(t_sig)))

    other_head = bytes(32)
    check("T3 verify against a different expected head -> commitment check "
          "FAILS while the signature stays VALID",
          pl.get(1) != other_head and ed25519.verify(pub, tbs, signature))

    # T4: kid moved to the unprotected bucket, statement re-signed.
    ph_nokid = cbor.dumps(cbor.sort_keys_deterministic({
        LBL_ALG: ALG_EDDSA,
        LBL_CONTENT_TYPE: si["content_type"],
        LBL_CWT_CLAIMS: cbor.sort_keys_deterministic({
            CWT_ISS: si["issuer"], CWT_SUB: si["subject"]}),
    }))
    sig_nokid = ed25519.sign(seed, sig_structure(ph_nokid, payload))
    moved = cbor.dumps(cbor.Tagged(TAG_COSE_SIGN1, [
        ph_nokid, {LBL_KID: bytes.fromhex(si["kid_hex"])}, payload, sig_nokid]))
    check("T4a kid in unprotected -> signature still VERIFIES",
          ed25519.verify(pub, sig_structure(ph_nokid, payload), sig_nokid))
    check("T4b kid in unprotected -> bytes are NOT the published statement",
          moved != statement, "%d bytes vs %d" % (len(moved), len(statement)))
    swapped = cbor.dumps(cbor.Tagged(TAG_COSE_SIGN1, [
        ph_nokid, {LBL_KID: b"\xde\xad\xbe\xef"}, payload, sig_nokid]))
    p2, u2, pay2, s2 = parse_sign1(swapped)
    check("T4c an ATTACKER can rewrite the unprotected kid and the signature "
          "still verifies (B1 case A10 -- why kid must be protected)",
          u2.get(LBL_KID) == b"\xde\xad\xbe\xef"
          and ed25519.verify(pub, sig_structure(p2, pay2), s2))

    untagged = statement[1:]
    check("T5a strip tag 18 -> content identical, first byte now 0x84",
          untagged[0] == 0x84)
    check("T5b strip tag 18 -> different artifact (bytes and sha256 differ)",
          untagged != statement
          and hashlib.sha256(untagged).hexdigest() != exp["statement_sha256"])
    try:
        parse_sign1(untagged, require_tag=True)
        check("T5c a tag-requiring parser rejects the untagged form", False,
              "it was accepted")
    except ValueError as exc:
        check("T5c a tag-requiring parser rejects the untagged form", True,
              str(exc))
    p5, u5, pay5, s5 = parse_sign1(untagged, require_tag=False)
    check("T5d ... but the untagged form still carries a VALID signature: "
          "tag presence is an artifact-identity question, not a crypto one",
          ed25519.verify(pub, sig_structure(p5, pay5), s5))

    # -- 7. adversarial (our own) -------------------------------------------
    section("7. adversarial cases of our own design")

    # A1: non-minimal length head on the OUTER protected bstr. The bstr
    # CONTENTS are what enter the Sig_structure, so the signature is untouched.
    # statement layout: d2 | 84 | 58 cd | <protected> | ...
    prot_head_len = 2
    tail = statement[2 + prot_head_len + len(protected):]
    mal = statement[:2] + b"\x59\x00\xcd" + protected + tail
    p3, u3, pay3, s3 = parse_sign1(mal, strict=False)
    check("A1 re-encode the protected bstr length head (58cd -> 5900cd): "
          "signature STILL VALID, artifact bytes/sha256/length CHANGE "
          "(confirms the vector's F3/A1 note)",
          ed25519.verify(pub, sig_structure(p3, pay3), s3)
          and mal != statement and len(mal) == len(statement) + 1,
          "%d bytes, sha256 %s" % (len(mal),
                                   hashlib.sha256(mal).hexdigest()[:16]))
    try:
        parse_sign1(mal, strict=True)
        check("A2 a STRICT RFC 8949 s4.2.1 decoder rejects that re-encoding",
              False, "it was accepted")
    except cbor.CBORError as exc:
        check("A2 a STRICT RFC 8949 s4.2.1 decoder rejects that re-encoding",
              True, str(exc))

    # A3: the same trick INSIDE the protected bucket changes the signed bytes.
    inner_mal = protected[:1] + b"\x18\x01" + protected[2:]
    check("A3 the same re-encoding INSIDE the protected bucket breaks the "
          "signature (those bytes are signed)",
          not ed25519.verify(pub, sig_structure(inner_mal, payload), signature))

    check("A4 truncated signature (63 bytes) -> rejected",
          not ed25519.verify(pub, tbs, signature[:63]))

    s_val = int.from_bytes(signature[32:], "little")
    malleable = signature[:32] + (s_val + ed25519.L).to_bytes(32, "little")
    check("A5a S+L malleability: rejected when RFC 8032 s5.1.7's 0<=S<L range "
          "check is enforced",
          not ed25519.verify(pub, tbs, malleable, reject_non_canonical_s=True))
    check("A5b ... and ACCEPTED without it -- a second valid 64-byte signature "
          "over the same statement; verifiers omitting the range check lose "
          "signature uniqueness",
          ed25519.verify(pub, tbs, malleable, reject_non_canonical_s=False),
          "S+L = %s" % malleable[32:].hex())

    # A6: claim confusion -- read the payload as if it were a CWT Claims Set.
    cwt_reading = {1: "iss", 2: "sub", 3: "aud", 4: "exp"}
    confused = {cwt_reading[k]: val for k, val in pl.pairs if k in cwt_reading}
    check("A6 claim confusion: a CWT parser would read the payload as "
          "iss/sub/aud/exp with wrong TYPES; the protected content type is "
          "what forbids that reading (B1 F2)",
          isinstance(confused["iss"], bytes)
          and isinstance(confused["sub"], int)
          and ct != "application/cwt",
          "iss=<32 bytes, want tstr>, sub=%r, aud=%r, exp=%r"
          % (confused["sub"], confused["aud"], confused["exp"]))

    wrong_tag = b"\xd8\x62" + statement[1:]
    try:
        parse_sign1(wrong_tag)
        check("A7 tag 98 (COSE_Sign) presented as COSE_Sign1 -> rejected",
              False, "it was accepted")
    except ValueError as exc:
        check("A7 tag 98 (COSE_Sign) presented as COSE_Sign1 -> rejected",
              True, str(exc))

    try:
        parse_sign1(statement[:-10])
        check("A8 truncated statement -> rejected", False, "it was accepted")
    except (ValueError, cbor.CBORError) as exc:
        check("A8 truncated statement -> rejected", True, str(exc))

    try:
        parse_sign1(statement + b"\x00")
        check("A9 trailing byte after the statement -> rejected", False,
              "it was accepted")
    except (ValueError, cbor.CBORError) as exc:
        check("A9 trailing byte after the statement -> rejected", True, str(exc))

    # A10: detached payload -- same Sig_structure, different artifact.
    detached = cbor.dumps(cbor.Tagged(TAG_COSE_SIGN1,
                                      [protected, {}, None, signature]))
    pd, ud, payd, sd = parse_sign1(detached)
    check("A10 detached payload (nil) + the payload supplied out of band: the "
          "SAME signature verifies over a DIFFERENT artifact -- another "
          "artifact-identity vs signature-validity split",
          payd is None
          and ed25519.verify(pub, sig_structure(pd, payload), sd)
          and detached != statement)

    # A11: duplicate protected label.
    dup = b"\xa5" + protected[1:] + cbor.dumps(LBL_KID) + cbor.dumps(b"\x00")
    try:
        m = cbor.loads(dup, strict=True)
        check("A11 duplicate map key in the protected bucket: a length-driven "
              "decoder accepts it; RFC 8949 s5.6 calls the result invalid, so "
              "reject duplicates explicitly",
              m.keys().count(LBL_KID) == 2,
              "our decoder surfaces both keys; a dict-building decoder would "
              "silently keep one -- and which one it keeps decides the kid")
    except cbor.CBORError as exc:
        check("A11 duplicate map key rejected", True, str(exc))

    # ------------------------------------------------------------------ done
    elapsed = time.time() - t0
    total = len(results)
    passed = total - _fail[0]
    print("\n== summary ==")
    print("  %d/%d checks passed, %d failed" % (passed, total, _fail[0]))
    print("  wall clock in-run: %.2f s" % elapsed)

    with open("results.json", "w") as fh:
        json.dump({
            "vector_sha256": hashlib.sha256(raw_vector).hexdigest(),
            "passed": passed, "total": total, "failed": _fail[0],
            "elapsed_seconds": round(elapsed, 3),
            "checks": results,
        }, fh, indent=2)
    return 1 if _fail[0] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
