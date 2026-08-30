"""Independent verification of the PALA-1 SCITT-bridge Signed Statement.

Carries out docs/interop/SCITT-STATEMENT-VERIFICATION-TASK.md steps 1-7
against docs/interop/scitt-statement-vector.json, using only this
directory's cbor.py and ed25519.py -- both written from the RFCs for this
run. No COSE library, no CBOR library, no crypto library.

    python scitt_verify.py [path/to/scitt-statement-vector.json]

Writes results.json beside the vector's run directory and prints a
transcript. Exit status 0 if every check that the task makes a pass-bar
requirement holds; 1 otherwise. Conformance findings against RFC 9943 are
reported but do not by themselves set the exit status -- they are
findings about the published statement, which is what the task asked for.
"""

import hashlib
import json
import pathlib
import re
import sys

import cbor
import ed25519

# COSE, RFC 9052.
COSE_SIGN1_TAG = 18
COSE_SIGN_TAG = 98
HDR_ALG = 1
HDR_CONTENT_TYPE = 3
HDR_KID = 4
HDR_X5CHAIN = 33
HDR_X5T = 34
HDR_CWT_CLAIMS = 15  # RFC 9597 section 2.
ALG_EDDSA = -8
CWT_ISS = 1
CWT_SUB = 2


class Report:
    """Collects pass/fail checks and free-standing findings."""

    def __init__(self):
        self.checks = []
        self.findings = []
        self.section = None

    def start(self, title):
        self.section = title
        print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")

    def check(self, name, ok, detail="", pass_bar=True):
        self.checks.append(
            {
                "section": self.section,
                "name": name,
                "ok": bool(ok),
                "detail": detail,
                "pass_bar": pass_bar,
            }
        )
        mark = "PASS" if ok else "FAIL"
        suffix = f"  -- {detail}" if detail else ""
        print(f"  [{mark}] {name}{suffix}")
        return ok

    def finding(self, ident, severity, title, detail):
        self.findings.append(
            {
                "id": ident,
                "severity": severity,
                "title": title,
                "detail": detail,
            }
        )
        print(f"  [FINDING {ident}] ({severity}) {title}\n           {detail}")

    @property
    def failed_pass_bar(self):
        return [c for c in self.checks if c["pass_bar"] and not c["ok"]]


def hexb(data, head=16):
    text = data.hex()
    return text if len(text) <= head * 2 else f"{text[: head * 2]}...({len(data)} bytes)"


def sig_structure(protected_bytes, payload_bytes, external_aad=b""):
    """RFC 9052 section 4.4: ["Signature1", body_protected, external_aad, payload]."""
    return cbor.dumps(["Signature1", protected_bytes, external_aad, payload_bytes])


def parse_statement(raw, require_deterministic=False):
    """Parse a tagged COSE_Sign1. Returns a dict of its four parts."""
    value, decoder = cbor.loads(raw, require_deterministic=require_deterministic)
    if not isinstance(value, cbor.Tagged):
        raise cbor.CBORError("top-level item is not tagged")
    if value.tag != COSE_SIGN1_TAG:
        raise cbor.CBORError(
            f"CBOR tag is {value.tag}, not {COSE_SIGN1_TAG} (COSE_Sign1)"
        )
    body = value.value
    if not isinstance(body, list) or len(body) != 4:
        raise cbor.CBORError(
            f"COSE_Sign1 body is not a 4-element array (got {type(body).__name__} "
            f"of length {len(body) if isinstance(body, list) else 'n/a'})"
        )
    protected_bytes, unprotected, payload, signature = body
    if not isinstance(protected_bytes, bytes):
        raise cbor.CBORError("protected header is not a byte string")
    if not isinstance(unprotected, dict):
        raise cbor.CBORError("unprotected header is not a map")
    if payload is not None and not isinstance(payload, bytes):
        raise cbor.CBORError("payload is neither a byte string nor nil")
    if not isinstance(signature, bytes):
        raise cbor.CBORError("signature is not a byte string")

    protected = cbor.loads(protected_bytes)[0] if protected_bytes else {}
    if not isinstance(protected, dict):
        raise cbor.CBORError("protected header bytes do not decode to a map")

    return {
        "protected_bytes": protected_bytes,
        "protected": protected,
        "unprotected": unprotected,
        "payload_bytes": payload,
        "signature": signature,
        "non_shortest_heads": decoder.non_shortest_heads,
    }


def build_statement(issuer, subject, head, first_seq, last_seq, format_id, seed):
    """Construct the statement from the vector's stated inputs alone."""
    protected = {HDR_ALG: ALG_EDDSA, HDR_CWT_CLAIMS: {CWT_ISS: issuer, CWT_SUB: subject}}
    protected_bytes = cbor.dumps(protected)
    payload_bytes = cbor.dumps({1: head, 2: first_seq, 3: last_seq, 4: format_id})
    signature = ed25519.sign(seed, sig_structure(protected_bytes, payload_bytes))
    statement = cbor.dumps(
        cbor.Tagged(COSE_SIGN1_TAG, [protected_bytes, {}, payload_bytes, signature])
    )
    return statement, protected_bytes, payload_bytes, signature


def main(argv):
    here = pathlib.Path(__file__).resolve().parent
    if len(argv) > 1:
        vector_path = pathlib.Path(argv[1])
    else:
        # verifier/ -> scitt-statement/ -> turak/ -> independent-runs/ ->
        # pala-1/ -> specs/ -> docs/  (parents[5] is docs/)
        vector_path = here.parents[5] / "interop" / "scitt-statement-vector.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))

    report = Report()
    print(f"vector file : {vector_path}")
    print(f"vector sha256: {hashlib.sha256(vector_path.read_bytes()).hexdigest()}")

    key = vector["key"]
    seed = bytes.fromhex(key["private_seed_hex"])
    published_public = bytes.fromhex(key["public_key_hex"])
    chain = vector["subject_chain"]
    head = bytes.fromhex(chain["chain_head_hex"])
    first_seq, last_seq = chain["first_seq"], chain["last_seq"]
    inputs = vector["statement_inputs"]
    issuer, subject = inputs["issuer"], inputs["subject"]
    expected = vector["expected"]
    statement = bytes.fromhex(expected["statement_hex"])

    # The payload's format identifier exists only inside an English prose
    # note; pull it from there rather than typing in the answer.
    quoted = re.findall(r"'([^']*)'", inputs["payload_note"])
    format_id = quoted[-1] if quoted else None

    # -- Step 0: key provenance -------------------------------------------
    report.start("0. Key material and provenance")
    derived = ed25519.public_key(seed)
    report.check(
        "public key derives from the published seed",
        derived == published_public,
        f"derived {hexb(derived, 8)}",
    )
    # RFC 8032 section 7.1, TEST 1: signature over the empty message.
    rfc_sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901"
        "555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    report.check(
        "seed reproduces RFC 8032 section 7.1 TEST 1 signature (provenance)",
        ed25519.sign(seed, b"") == rfc_sig,
        "the key really is the published RFC test key",
    )
    report.check(
        "this verifier's Ed25519 verifies RFC 8032 TEST 1",
        ed25519.verify(published_public, b"", rfc_sig)[0],
        "known-answer test on the signature check itself",
    )

    # The vector names its own subject's provenance; check it rather than
    # taking it. Skipped when the run is made from the vector file alone.
    core_vectors = vector_path.parents[1] / "specs" / "pala-1" / "test-vectors.json"
    if core_vectors.is_file():
        core = json.loads(core_vectors.read_text(encoding="utf-8"))
        report.check(
            "chain head is the one published in the core vectors",
            core.get("chain_head") == chain["chain_head_hex"],
            f"{core_vectors.name} sha256 "
            f"{hashlib.sha256(core_vectors.read_bytes()).hexdigest()[:16]}...",
        )
        report.check(
            "the sequence range covers the whole published chain",
            core.get("verify", {}).get("count") == last_seq - first_seq + 1,
            f"seq {first_seq}..{last_seq} is {last_seq - first_seq + 1} records",
        )
    else:
        print(f"  [SKIP] core vectors not present at {core_vectors}")

    # -- Step 1: parse -----------------------------------------------------
    report.start("1. Parse expected.statement_hex as a COSE_Sign1 (RFC 9052)")
    report.check(
        "length is as published",
        len(statement) == expected["statement_length_bytes"],
        f"{len(statement)} bytes",
    )
    digest = hashlib.sha256(statement).hexdigest()
    report.check(
        "SHA-256 is as published", digest == expected["statement_sha256"], digest
    )
    parsed = parse_statement(statement)
    report.check("CBOR tag 18, 4-element array, well-formed", True, "parsed")
    report.check(
        "unprotected header is an empty map",
        parsed["unprotected"] == {},
        "RFC 9943 section 6.3 requires this for registration",
    )
    report.check(
        "payload is attached (a bstr, not nil)", parsed["payload_bytes"] is not None
    )
    report.check(
        "signature is 64 bytes", len(parsed["signature"]) == 64, hexb(parsed["signature"], 8)
    )
    try:
        parse_statement(statement, require_deterministic=True)
        deterministic = True
        det_detail = "shortest-form heads, ordered map keys"
    except cbor.CBORError as exc:
        deterministic = False
        det_detail = str(exc)
    report.check(
        "encoded in RFC 8949 section 4.2.1 deterministic form",
        deterministic,
        det_detail,
        pass_bar=False,
    )

    # -- Step 2: verify ----------------------------------------------------
    report.start("2. Verify the Ed25519 signature over the Sig_structure")
    to_be_signed = sig_structure(parsed["protected_bytes"], parsed["payload_bytes"])
    print(f"  Sig_structure ({len(to_be_signed)} bytes): {hexb(to_be_signed, 12)}")
    ok, reason = ed25519.verify(published_public, to_be_signed, parsed["signature"])
    report.check(
        "signature verifies under key.public_key_hex",
        ok and expected["verifies_with_public_key"],
        reason,
    )

    # -- Step 3: payload ---------------------------------------------------
    report.start("3. Decode the payload and check its commitment")
    payload = cbor.loads(parsed["payload_bytes"])[0]
    report.check("payload is a CBOR map of 4 entries", isinstance(payload, dict) and len(payload) == 4)
    committed = payload.get(1)
    report.check(
        "payload key 1 equals subject_chain.chain_head_hex",
        committed == head and expected["payload_commits_to_chain_head"],
        chain["chain_head_hex"],
    )
    report.check("payload key 2 equals first_seq", payload.get(2) == first_seq, str(first_seq))
    report.check("payload key 3 equals last_seq", payload.get(3) == last_seq, str(last_seq))
    report.check(
        "payload key 4 equals the stated format id",
        format_id is not None and payload.get(4) == format_id,
        repr(payload.get(4)),
    )

    # -- Step 4: protected header ------------------------------------------
    report.start("4. Check the protected header")
    protected = parsed["protected"]
    report.check("alg is EdDSA (-8)", protected.get(HDR_ALG) == ALG_EDDSA, "RFC 9052")
    claims = protected.get(HDR_CWT_CLAIMS)
    report.check(
        "CWT claims are carried in the protected header at label 15",
        isinstance(claims, dict),
        "RFC 9597 section 2",
    )
    report.check("CWT claim 1 (iss) is the stated issuer", claims.get(CWT_ISS) == issuer, issuer)
    report.check("CWT claim 2 (sub) is the stated subject", claims.get(CWT_SUB) == subject, subject)
    report.check(
        "subject names the chain head it commits to",
        subject.endswith(chain["chain_head_hex"][:16]),
        "sub carries the first 8 bytes of the head",
    )

    # RFC 9943 conformance of the published statement.
    has_kid = HDR_KID in protected
    has_x5 = HDR_X5T in protected or HDR_X5CHAIN in protected
    if not report.check(
        "RFC 9943 section 6: kid present when neither x5t nor x5chain is",
        has_kid or has_x5,
        "protected header carries only alg and CWT claims",
        pass_bar=False,
    ):
        report.finding(
            "F1",
            "conformance",
            "The Signed Statement violates a MUST in RFC 9943 section 6.",
            "RFC 9943 section 6 requires the kid header parameter to be present "
            "when neither x5t nor x5chain is in the protected header. This "
            "statement has none of the three, so a conforming SCITT transparency "
            "service has no in-band key identifier with which to resolve the "
            "issuer's verification key.",
        )
    if not report.check(
        "content type (label 3) declares what the payload is",
        HDR_CONTENT_TYPE in protected,
        "absent; optional in the RFC 9943 figure-3 CDDL",
        pass_bar=False,
    ):
        report.finding(
            "F2",
            "ambiguity",
            "Nothing on the wire says the payload is not a CWT Claims Set.",
            "The payload is a CBOR map keyed 1..4. In a COSE object whose "
            "protected header carries CWT claims (RFC 9597), integer keys 1 and 2 "
            "are conventionally iss and sub. A verifier that reads this payload as "
            "a CWT Claims Set gets iss = 32 raw bytes and sub = 0, and RFC 9597 "
            "section 2 then obliges it to compare those against the header's "
            "claims and reject. Declaring content type (label 3) would settle it.",
        )

    # -- Step 5: reproduce -------------------------------------------------
    report.start("5. Reproduce the statement byte-for-byte from the inputs")
    rebuilt, rebuilt_protected, rebuilt_payload, rebuilt_sig = build_statement(
        issuer, subject, head, first_seq, last_seq, format_id, seed
    )
    report.check(
        "rebuilt protected header matches",
        rebuilt_protected == parsed["protected_bytes"],
        f"{len(rebuilt_protected)} bytes",
    )
    report.check(
        "rebuilt payload matches",
        rebuilt_payload == parsed["payload_bytes"],
        f"{len(rebuilt_payload)} bytes",
    )
    report.check(
        "rebuilt signature matches (Ed25519 is deterministic)",
        rebuilt_sig == parsed["signature"],
        hexb(rebuilt_sig, 8),
    )
    if not report.check(
        f"all {expected['statement_length_bytes']} bytes match",
        rebuilt == statement,
        "independent construction agrees with the published bytes",
    ):
        first_diff = next(
            (i for i, (a, b) in enumerate(zip(rebuilt, statement)) if a != b), None
        )
        print(f"       first differing byte at offset {first_diff}")

    # -- Step 6: tamper ----------------------------------------------------
    report.start("6. Tamper expectations from the vector")
    flipped_head = bytearray(head)
    flipped_head[0] ^= 0x01
    t1_payload = cbor.dumps({1: bytes(flipped_head), 2: first_seq, 3: last_seq, 4: format_id})
    t1_ok, t1_reason = ed25519.verify(
        published_public,
        sig_structure(parsed["protected_bytes"], t1_payload),
        parsed["signature"],
    )
    report.check(
        "T1 bit-flip in the payload head breaks the signature", not t1_ok, t1_reason
    )

    bad_sig = bytearray(parsed["signature"])
    bad_sig[0] ^= 0x01
    t2_ok, t2_reason = ed25519.verify(published_public, to_be_signed, bytes(bad_sig))
    report.check("T2 bit-flip in the signature breaks verification", not t2_ok, t2_reason)

    other_head = bytearray(head)
    other_head[31] ^= 0xFF
    t3_sig_ok = ed25519.verify(published_public, to_be_signed, parsed["signature"])[0]
    report.check(
        "T3 commitment check fails against a different head, signature still valid",
        payload.get(1) != bytes(other_head) and t3_sig_ok,
        "a valid signature over the wrong subject is still the wrong subject",
    )

    # -- Step 7: adversarial ------------------------------------------------
    report.start("7. Adversarial cases of this run's own design")

    # A1 -- re-encode the protected bstr head as 59 004c instead of 58 4c.
    protected_len = len(parsed["protected_bytes"])
    long_form = (
        statement[:2]
        + bytes([0x59]) + protected_len.to_bytes(2, "big")
        + statement[4:]
    )
    mangled = parse_statement(long_form)
    a1_ok = ed25519.verify(
        published_public,
        sig_structure(mangled["protected_bytes"], mangled["payload_bytes"]),
        mangled["signature"],
    )[0]
    report.check(
        "A1 non-shortest length prefix still carries a valid signature",
        a1_ok and long_form != statement,
        f"{len(long_form)} bytes, sha256 {hashlib.sha256(long_form).hexdigest()[:16]}...",
        pass_bar=False,
    )
    if a1_ok:
        report.finding(
            "F3",
            "malleability",
            "expected.statement_sha256 is not a signature-bound identity.",
            "RFC 9052 section 9 requires definite lengths and minimum-length "
            "arguments, but says the restriction applies to the Sig_structure, "
            "Enc_structure and MAC_structure -- not to the COSE message that "
            "carries them. So re-encoding the protected header's byte-string "
            "length in the two-byte form leaves the signed Sig_structure "
            "untouched and the signature still verifies, while the message "
            "becomes 203 bytes with a different SHA-256. The vector publishes "
            "statement_sha256 and statement_length_bytes as expectations, which "
            "treats the serialisation as an identity it is not: a verifier that "
            "matches on either must independently enforce RFC 8949 section "
            "4.2.1, because nothing in COSE obliges the encoder to.",
        )
    report.check(
        "A1' a determinism-enforcing parse rejects it",
        _rejects(long_form, require_deterministic=True),
        "which is the mitigation for F3",
    )

    # A2 -- wrong tag.
    report.check(
        "A2 tag 98 (COSE_Sign) is rejected",
        _rejects(bytes([0xD8, COSE_SIGN_TAG]) + statement[1:]),
        "a Sign1 verifier must not accept a multi-signer structure",
    )

    # A3 -- untagged.
    report.check(
        "A3 untagged COSE_Sign1 is rejected by this verifier",
        _rejects(statement[1:]),
        "accepted only where the content type establishes the type out of band",
        pass_bar=False,
    )

    # A4 -- truncated signature.
    truncated = cbor.dumps(
        cbor.Tagged(
            COSE_SIGN1_TAG,
            [
                parsed["protected_bytes"],
                {},
                parsed["payload_bytes"],
                parsed["signature"][:63],
            ],
        )
    )
    t = parse_statement(truncated)
    report.check(
        "A4 63-byte signature is rejected on length, not on the curve",
        not ed25519.verify(published_public, to_be_signed, t["signature"])[0],
        ed25519.verify(published_public, to_be_signed, t["signature"])[1],
    )

    # A5 -- non-canonical S (S + L).
    s = int.from_bytes(parsed["signature"][32:], "little")
    malleable = parsed["signature"][:32] + (s + ed25519.L).to_bytes(32, "little")
    strict_ok = ed25519.verify(published_public, to_be_signed, malleable)[0]
    lax_ok = ed25519.verify(
        published_public, to_be_signed, malleable, enforce_canonical_s=False
    )[0]
    report.check("A5 S+L is rejected with the RFC 8032 range check", not strict_ok)
    report.check(
        "A5' the same bytes verify without it -- a second valid signature",
        lax_ok,
        "why RFC 8032 section 5.1.7 requires 0 <= S < L",
        pass_bar=False,
    )

    # A6 -- duplicate map key in the protected header.
    dup = bytes([0xA3, 0x01, 0x27, 0x01, 0x27]) + parsed["protected_bytes"][3:]
    report.check(
        "A6 duplicate map key in the protected header is rejected",
        _rejects_map(dup),
        "RFC 8949 section 5.6",
    )

    # A7 -- detached payload carrying the attached payload's signature.
    detached = cbor.dumps(
        cbor.Tagged(COSE_SIGN1_TAG, [parsed["protected_bytes"], {}, None, parsed["signature"]])
    )
    d = parse_statement(detached)
    report.check(
        "A7 payload stripped to nil cannot be verified as-is",
        d["payload_bytes"] is None,
        "no payload to place in the Sig_structure; must fail closed, not skip",
    )

    # A8 -- claim confusion.
    as_cwt_iss = payload.get(CWT_ISS)
    report.check(
        "A8 reading the payload as a CWT Claims Set contradicts the header",
        as_cwt_iss != claims.get(CWT_ISS),
        f"payload[1] is {type(as_cwt_iss).__name__}, header iss is a text string",
        pass_bar=False,
    )

    # A9 -- the truncated subject does not identify the chain.
    collide = bytearray(head)
    collide[20] ^= 0xFF
    other_statement, _, _, _ = build_statement(
        issuer, subject, bytes(collide), first_seq, last_seq, format_id, seed
    )
    other_parsed = parse_statement(other_statement)
    other_claims = other_parsed["protected"][HDR_CWT_CLAIMS]
    report.check(
        "A9 a different chain head yields an identical CWT subject",
        other_claims[CWT_SUB] == subject and bytes(collide) != head,
        "sub is only the first 8 bytes of the head",
        pass_bar=False,
    )
    if other_claims[CWT_SUB] == subject:
        report.finding(
            "F4",
            "design",
            "The CWT subject truncates the chain head to 8 bytes.",
            "sub is 'pala-1:chain:' plus the first 16 hex characters of the head, "
            "so two different chains collide in the SCITT subject at a 64-bit "
            "birthday bound (~2^32 work). A transparency service that indexes or "
            "authorises by sub -- which is what sub is for -- cannot distinguish "
            "them. Verified here by signing a second statement over a head "
            "differing in byte 20: same sub, valid signature. The payload still "
            "commits to the full head, so this is an indexing and authorisation "
            "hazard rather than a forgery.",
        )

    # A10 -- the unprotected bucket is not signed.
    injected = cbor.dumps(
        cbor.Tagged(
            COSE_SIGN1_TAG,
            [parsed["protected_bytes"], {HDR_KID: b"attacker"}, parsed["payload_bytes"], parsed["signature"]],
        )
    )
    i = parse_statement(injected)
    inj_ok = ed25519.verify(
        published_public, sig_structure(i["protected_bytes"], i["payload_bytes"]), i["signature"]
    )[0]
    report.check(
        "A10 an injected unprotected header does not disturb the signature",
        inj_ok and i["unprotected"] != {},
        "so a kid added later would be unauthenticated -- it belongs in protected",
        pass_bar=False,
    )

    # A11 -- trailing bytes.
    report.check(
        "A11 trailing bytes after the statement are rejected",
        _rejects(statement + b"\x00"),
        "no silent truncation of the input",
    )

    # -- Summary ------------------------------------------------------------
    report.start("Summary")
    total = len(report.checks)
    failed = [c for c in report.checks if not c["ok"]]
    print(f"  checks run       : {total}")
    print(f"  checks passed    : {total - len(failed)}")
    print(f"  pass-bar failures: {len(report.failed_pass_bar)}")
    print(f"  findings         : {len(report.findings)}")
    for finding in report.findings:
        print(f"    {finding['id']} ({finding['severity']}) {finding['title']}")

    results = {
        "vector_file": str(vector_path),
        "vector_sha256": hashlib.sha256(vector_path.read_bytes()).hexdigest(),
        "statement_sha256": digest,
        "statement_length_bytes": len(statement),
        "reproduced_byte_for_byte": rebuilt == statement,
        "checks": report.checks,
        "findings": report.findings,
        "pass_bar_failures": len(report.failed_pass_bar),
    }
    out = here.parent / "output" / "results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"\n  wrote {out}")

    return 1 if report.failed_pass_bar else 0


def _rejects(raw, require_deterministic=False):
    try:
        parse_statement(raw, require_deterministic=require_deterministic)
        return False
    except cbor.CBORError:
        return True


def _rejects_map(raw):
    try:
        cbor.loads(raw)
        return False
    except cbor.CBORError:
        return True


if __name__ == "__main__":
    sys.exit(main(sys.argv))
