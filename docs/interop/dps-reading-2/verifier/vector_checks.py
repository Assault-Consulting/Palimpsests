"""The vector cases of cases.json (V01 to V25): each recomputes values in vectors.json."""
import base64
import io
import hashlib
import json
import traceback

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from asn1crypto import cms, tsp as a1tsp

from dpsr import cbor_strict as cb, ots as O
from dpsr.common import (checkpoint_signed_bytes, links, lp, sha256, signed_bytes, checkpoint_fields,
                         strict_loads, DuplicateMember, DPS_SIG)
from dpsr.checkpoint import _inclusion_root

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _seed(text):
    return hashlib.sha256(text.encode("utf-8")).digest()


def _ed_pub(seed):
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def v_known(env, c):
    return [] if hashlib.sha256(c["text"].encode()).hexdigest() == c["digest"] else ["digest differs"]


def v_lp(env, c):
    return ["%r" % t for t, h in c["vectors"] if lp(t.encode("utf-8")).hex() != h]


def v_records(env, c):
    return [n for n, r in env.V["records"].items() if hashlib.sha256(r["text"].encode("utf-8")).hexdigest() != r["seal_hash"]]


def v_chain(env, c):
    bad = []
    L = env.V["chain"]["links"]
    for name, ch in c["chains"].items():
        prev = b"\x00" * 32
        for rec, ln in zip(ch["records"], ch["links"]):
            prev = sha256(prev + bytes.fromhex(env.V["records"][rec]["seal_hash"]))
            if prev.hex() != L[ln]:
                bad.append("%s %s" % (name, ln))
    return bad


def v_exports(env, c):
    bad = []
    texts = {r["text"].encode("utf-8"): r["seal_hash"] for r in env.V["records"].values()}
    for name, e in env.V["exports"].items():
        prev = None
        ls = links(e)
        for i, en in enumerate(e["entries"]):
            b = base64.b64decode(en["content"]["covered_bytes_b64"])
            if b not in texts or texts[b] != en["seal"]["seal_hash"]:
                bad.append("%s entry %d bytes/seal" % (name, i))
            if name in c["chained"]:
                ch = en.get("chain")
                want_prev = None if i == 0 else ls[i - 1].hex()
                if not ch or ch.get("sequence") != i or ch.get("previous_link") != want_prev:
                    bad.append("%s entry %d chain" % (name, i))
    return bad


def v_keys(env, c):
    bad = []
    for name, k in env.V["test_keys"].items():
        if "seed_text" in k:
            s = _seed(k["seed_text"])
            if k["algorithm"] == "Ed25519":
                pub = _ed_pub(s).hex()
            else:
                d = int.from_bytes(s, "big") % (P256_N - 1) + 1
                from cryptography.hazmat.primitives import serialization
                pub = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
            if pub != k["public_key_hex"]:
                bad.append(name)
        else:
            n = int(k["modulus_hex"], 16)
            if n.bit_length() != 2048 or int(k["public_exponent_hex"], 16) != 65537:
                bad.append(name)
    return bad


def v_certs(env, c):
    bad = []
    for name, cert in env.V["tsa_certificates"].items():
        der = base64.b64decode(cert["certificate_b64"])
        if hashlib.sha256(der).hexdigest() != cert["sha256"]:
            bad.append(name + " sha256")
        pub = x509.load_der_x509_certificate(der).public_key()
        k = env.V["test_keys"][name]
        if isinstance(pub, rsa.RSAPublicKey):
            n = pub.public_numbers()
            if n.n != int(k["modulus_hex"], 16) or n.e != int(k["public_exponent_hex"], 16):
                bad.append(name + " key")
        else:
            from cryptography.hazmat.primitives import serialization
            if pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex() != k["public_key_hex"]:
                bad.append(name + " key")
    return bad


def v_signed_bytes(env, c):
    bad = []
    for name, cp in env.V["checkpoints"].items():
        x = cp["checkpoint"]
        try:
            b = checkpoint_signed_bytes(x, x["signature"]["key_ref"])
        except Exception as e:
            bad.append("%s: %s" % (name, e))
            continue
        if b.hex() != cp["signed_bytes_hex"]:
            bad.append(name)
    return bad


def v_fields(env, c):
    x = env.V["checkpoints"][c["checkpoint"]]["checkpoint"]
    f = checkpoint_fields(x["signature"]["key_ref"], x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"])
    return [] if [h.hex() for h in f] == c["fields_hex"] else ["fields differ"]


def v_signatures(env, c):
    bad = []
    keys = env.V["test_keys"]
    for name, cp in env.V["checkpoints"].items():
        k = keys[cp["signed_with"]]
        over = bytes.fromhex(cp.get("signature_made_over_hex", cp["signed_bytes_hex"]))
        sig = Ed25519PrivateKey.from_private_bytes(_seed(k["seed_text"])).sign(over)
        same = base64.b64encode(sig).decode() == cp["checkpoint"]["signature"]["value_b64"]
        if same == (name in c["altered_after_signing"]):
            bad.append(name)
    # SCITT statements and receipts (change C10): over to_be_signed_hex; a statement carrying a signature made
    # under the shared rule (st_a_dps_value) is reproduced over its payload instead
    for name, st in env.V["scitt"]["statements"].items():
        if "seed_text" not in keys.get(st["signed_with"], {}):
            continue
        sk = Ed25519PrivateKey.from_private_bytes(_seed(keys[st["signed_with"]]["seed_text"]))
        try:
            item = cb.loads(base64.b64decode(st["statement_b64"])).value
            sigv = item[3]
        except Exception:
            continue  # the five the strict reader refuses; V23 leaves them out too
        if sk.sign(bytes.fromhex(st["to_be_signed_hex"])) != sigv and sk.sign(bytes.fromhex(st["payload_hex"])) != sigv:
            bad.append(name + " statement")
        if "receipt_b64" in st:
            rk = Ed25519PrivateKey.from_private_bytes(_seed(keys[st["receipt_signed_with"]]["seed_text"]))
            r = cb.loads(base64.b64decode(st["receipt_b64"])).value
            if rk.sign(bytes.fromhex(st["receipt_to_be_signed_hex"])) != r[3]:
                bad.append(name + " receipt")
    return bad


def v_domain(env, c):
    x = env.V["checkpoints"][c["checkpoint"]]["checkpoint"]
    kr = x["signature"]["key_ref"]
    base = checkpoint_signed_bytes(x, kr)
    sig = base64.b64decode(x["signature"]["value_b64"])
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env.V["test_keys"][kr]["public_key_hex"]))
    bad = []
    p, v, a, k = c["others"]
    variants = [signed_bytes(checkpoint_fields(kr, x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"], profile=p)),
                signed_bytes(checkpoint_fields(kr, x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"], version=v)),
                signed_bytes(checkpoint_fields(kr, x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"], assertion=a)),
                signed_bytes(checkpoint_fields(k, x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"]))]
    for i, vb in enumerate(variants):
        if vb == base:
            bad.append("variant %d equal" % i)
        try:
            pub.verify(sig, vb)
            bad.append("variant %d verifies" % i)
        except Exception:
            pass
    return bad


_HASH = {"2.16.840.1.101.3.4.2.1": hashlib.sha256, "2.16.840.1.101.3.4.2.3": hashlib.sha512}


def v_imprints(env, c):
    bad = []
    for name, t in env.V["tokens"].items():
        if name in c["not_tokens"]:
            continue
        try:
            ci = cms.ContentInfo.load(base64.b64decode(t["token_b64"]))
            tst = a1tsp.TSTInfo.load(ci["content"]["encap_content_info"]["content"].contents)
            mi = tst["message_imprint"]
            alg = c["true_algorithm"].get(name)
            h = hashlib.new(alg) if alg else _HASH[mi["hash_algorithm"]["algorithm"].dotted]()
            h.update(bytes.fromhex(t["imprint_of_hex"]))
            if h.digest() != mi["hashed_message"].native:
                bad.append(name)
        except Exception as e:
            bad.append("%s: %s" % (name, type(e).__name__))
    return bad


def v_counting(env, c):
    x = env.V["checkpoints"][c["checkpoint"]]["checkpoint"]
    kr = x["signature"]["key_ref"]
    good = checkpoint_signed_bytes(x, kr)
    f = checkpoint_fields(kr, x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"])
    wrong = DPS_SIG + b"".join((len(fi.decode("utf-8", "ignore")) if i == 4 else len(fi)).to_bytes(4, "big") + fi for i, fi in enumerate(f))
    bad = []
    if c["chain_id_prefix"] not in good.hex() or c["chain_id_prefix_counting_characters"] not in wrong.hex():
        bad.append("prefixes")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env.V["test_keys"][kr]["public_key_hex"]))
    sig = base64.b64decode(x["signature"]["value_b64"])
    try:
        pub.verify(sig, wrong)
        bad.append("verifies over character-counted bytes")
    except Exception:
        pass
    try:
        pub.verify(sig, good)
    except Exception:
        bad.append("does not verify over byte-counted bytes")
    return bad


def v_rsa(env, c):
    k = env.V["test_keys"][c["key"]]
    m = k["modulus_hex"]
    bad = []
    if not m.startswith(c["modulus_starts_with"]) or not m.endswith(c["modulus_ends_with"]):
        bad.append("modulus ends")
    if hashlib.sha256(bytes.fromhex(m)).hexdigest() != c["modulus_sha256"]:
        bad.append("modulus sha256")
    if k["public_exponent_hex"] != c["public_exponent_hex"] or int(m, 16).bit_length() != c["bits"]:
        bad.append("exponent or bits")
    return bad


def v_inline(env, c):
    a = env.schemas["attachment"]["$defs"]["checkpoint"]
    s = {k: v for k, v in env.schemas["checkpoint"].items() if k not in ("$schema", "$id", "$comment", "title")}
    return [] if a == s else ["the inline checkpoint differs from the checkpoint schema"]


def v_dup(env, c):
    t = env.V["texts"][c["text"]]
    bad = []
    try:
        strict_loads(t["attachment_text"])
        bad.append("the strict reader read it")
    except DuplicateMember:
        pass
    last = json.loads(t["attachment_text"])["checkpoints"][0]

    def first_hook(pairs):
        d = {}
        for k, v in pairs:
            d.setdefault(k, v)
        return d
    first = json.loads(t["attachment_text"], object_pairs_hook=first_hook)["checkpoints"][0]
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(env.V["test_keys"][c["key"]]["public_key_hex"]))
    for cp, should in ((last, True), (first, False)):
        try:
            pub.verify(base64.b64decode(cp["signature"]["value_b64"]), checkpoint_signed_bytes(cp, cp["signature"]["key_ref"]))
            ok = True
        except Exception:
            ok = False
        if ok != should:
            bad.append("count %r: verifies=%s" % (cp["count"], ok))
    if first["count"] != t["first_member"] or last["count"] != t["last_member"]:
        bad.append("members")
    return bad


def _cbor_items(env):
    """Every statement, receipt and inclusion proof, and each protected header."""
    out = []
    for name, s in env.V["scitt"]["statements"].items():
        out.append((name + "/statement_b64", base64.b64decode(s["statement_b64"])))
        if "receipt_b64" in s:
            out.append((name + "/receipt_b64", base64.b64decode(s["receipt_b64"])))
    return out


def _cbor2_plain(x):
    if isinstance(x, cbor2.CBORTag):
        return ("tag", x.tag, _cbor2_plain(x.value))
    if isinstance(x, (list, tuple)):
        return ("list", tuple(_cbor2_plain(y) for y in x))
    if hasattr(x, "items"):
        return ("map", tuple(sorted(((repr(type(k)), repr(k)), _cbor2_plain(v)) for k, v in x.items())))
    return (type(x).__name__, x)


def v_cbor(env, c):
    bad = []
    cbor2_reads_refused = 0
    def read(b):
        # the statement or receipt as the check reads it: the item, tag 18, and its protected header
        x = cb.loads(b)
        if not isinstance(x, cb.Tag) or x.tag != 18:
            raise cb.CborError("not tagged 18")
        if isinstance(x.value, list) and x.value and isinstance(x.value[0], bytes) and x.value[0]:
            cb.loads(x.value[0])
        return x

    def cbor2_read(b):
        # counted as read only when cbor2 consumes every byte: cbor2.loads returns for st_a_trailing with one byte
        # left unread (change C05 in out/changes.md)
        f = io.BytesIO(b)
        x = cbor2.CBORDecoder(f).decode()
        if f.tell() != len(b):
            raise ValueError("cbor2 left %d bytes unread" % (len(b) - f.tell()))
        v = x.value if isinstance(x, cbor2.CBORTag) else x
        if isinstance(v, (list, tuple)) and v and isinstance(v[0], bytes) and v[0]:
            cbor2.loads(v[0])
        return x

    for name, b in _cbor_items(env):
        try:
            mine = read(b)
        except cb.CborError as e:
            want = c["refused"].get(name)
            if want is None or want not in str(e):
                bad.append("%s refused: %s" % (name, e))
            try:
                cbor2_read(b)
                cbor2_reads_refused += 1
            except Exception:
                pass
            continue
        if name in c["refused"]:
            bad.append("%s read, expected refused" % name)
            continue
        theirs = cbor2.loads(b)
        if cb.to_plain(mine) != _cbor2_plain(theirs):
            bad.append("%s differs from cbor2" % name)
        if cbor2.dumps(theirs) != b:
            bad.append("%s cbor2 writes other bytes" % name)
        # protected headers and inclusion proofs
        arr = mine.value
        if isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and arr[0]:
            ph = arr[0]
            if cb.to_plain(cb.loads(ph)) != _cbor2_plain(cbor2.loads(ph)) or cbor2.dumps(cbor2.loads(ph)) != ph:
                bad.append("%s protected header" % name)
            p = arr[1].get(396) if isinstance(arr[1], dict) else None
            if isinstance(p, dict):
                for pb in p.get(-1, []):
                    if cb.to_plain(cb.loads(pb)) != _cbor2_plain(cbor2.loads(pb)) or cbor2.dumps(cbor2.loads(pb)) != pb:
                        bad.append("%s proof" % name)
    if cbor2_reads_refused != 4:
        bad.append("cbor2 reads %d of the refused, expected 4" % cbor2_reads_refused)
    return bad


def v_payload(env, c):
    bad = []
    for name, s in env.V["scitt"]["statements"].items():
        if name in c["refused"]:
            continue
        st = cb.loads(base64.b64decode(s["statement_b64"]))
        prot, payload = st.value[0], st.value[2]
        if payload.hex() != s["payload_hex"]:
            bad.append(name + " payload_hex")
        if cb.sig_structure(prot, payload).hex() != s["to_be_signed_hex"]:
            bad.append(name + " to_be_signed")
        if name in c["other_payload"]:
            continue
        x = s["checkpoint"]
        try:
            rebuilt = signed_bytes(checkpoint_fields(s["key_ref"], x["chain_id"], x["count"], x["head_link"], x["checkpoint_time"]))
        except Exception as e:
            bad.append("%s: %s" % (name, e))
            continue
        if rebuilt != payload:
            bad.append(name + " rebuilt")
        kid = cb.loads(prot).get(4)
        if (kid.decode() if isinstance(kid, bytes) else kid) != s["key_ref"]:
            bad.append(name + " kid")
    return bad


def _mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def v_log(env, c):
    bad = []
    S = env.V["scitt"]
    log = S["log"]
    lh = []
    for i, n in enumerate(log["leaves"]):
        h = hashlib.sha256(b"\x00" + base64.b64decode(S["statements"][n]["statement_b64"])).digest()
        lh.append(h)
        if h.hex() != log["leaf_hashes_hex"][i]:
            bad.append("leaf " + n)
    if _mth(lh).hex() != log["root_hex"]:
        bad.append("root")
    for n in c["reaching"]:
        s = S["statements"][n]
        r = cb.loads(base64.b64decode(s["receipt_b64"])).value
        ts, li, path = cb.loads(r[1][396][-1][0])
        root = _inclusion_root(hashlib.sha256(b"\x00" + base64.b64decode(s["statement_b64"])).digest(), li, ts, path)
        if root is None or root.hex() != log["root_hex"]:
            bad.append("path " + n)
    return bad


def v_prefixes(env, c):
    s = env.V["scitt"]["statements"][c["statement"]]
    tbs = bytes.fromhex(s["to_be_signed_hex"])
    ok = tbs.startswith(bytes.fromhex("846a") + b"Signature1") and bytes.fromhex(s["payload_hex"]).startswith(DPS_SIG)
    return [] if ok else ["prefixes"]


def v_stsig(env, c):
    bad = []
    keys = env.V["test_keys"]
    for name, s in env.V["scitt"]["statements"].items():
        if name in c["refused"]:
            continue
        st = cb.loads(base64.b64decode(s["statement_b64"])).value
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[s["signed_with"]]["public_key_hex"]))
        try:
            pub.verify(st[3], cb.sig_structure(st[0], st[2]))
            ok = True
        except Exception:
            ok = False
        if ok == (name in c["not_verifying"]):
            bad.append(name)
        if "receipt_b64" in s:
            r = cb.loads(base64.b64decode(s["receipt_b64"])).value
            rpub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[s["receipt_signed_with"]]["public_key_hex"]))
            try:
                rpub.verify(r[3], cb.sig_structure(r[0], bytes.fromhex(s["root_hex"])))
            except Exception:
                bad.append(name + " receipt")
    return bad


def v_ots_real(env, c):
    o = env.V["opentimestamps"]
    t = o["timestamps"][c["proof"]]["timestamp"]
    _op, digest, root = O.parse(base64.b64decode(t["proof_b64"]))
    bad = []
    if digest != hashlib.sha256(bytes.fromhex(t["subject"]["value_hex"])).digest():
        bad.append("start digest")
    got = {}
    for a in O.replay(root, digest):
        if a["tag"] == O.TAG_BITCOIN:
            got[O.bitcoin_height(a["payload"])] = a["digest"]
    if sorted(got) != sorted(c["heights"]):
        bad.append("heights %s" % sorted(got))
    for h in c["heights"]:
        hd = o["headers"]["mainnet"][str(h)]
        hb = bytes.fromhex(hd["header_hex"])
        if got.get(h) != hb[36:68]:
            bad.append("%d merkle root" % h)
        if hashlib.sha256(hashlib.sha256(hb).digest()).digest()[::-1].hex() != hd["block_hash"]:
            bad.append("%d hash" % h)
    return bad


def v_ots_refusals(env, c):
    from dpsr import timestamp as TS, report as R
    bad = []
    o = env.V["opentimestamps"]["timestamps"]
    for name, x in o.items():
        t = x["timestamp"]
        ctx = R.make_ctx(env.V["trust_policy"], "urn:example:chain:issuer-1", env.V["exports"]["full"])
        res = TS.check_ots(t, 0, ctx)
        fs = " | ".join(res.get("findings", []))
        refused = res["checks"]["proof"] == "failed" or res["checks"]["operations"] == "not_supported"
        if name in c["refused"]:
            if not refused or c["refused"][name] not in fs:
                bad.append("%s: %s" % (name, fs[:160]))
        elif refused:
            bad.append("%s read refused: %s" % (name, fs[:160]))
    return bad


CHECKS = {"known_vector": v_known, "length_prefix": v_lp, "record_seals": v_records, "chain_links": v_chain,
          "exports": v_exports, "test_keys": v_keys, "tsa_certificates": v_certs, "signed_bytes": v_signed_bytes,
          "signed_bytes_fields": v_fields, "signatures": v_signatures, "domain_separation": v_domain,
          "token_imprints": v_imprints, "counting_characters": v_counting, "published_rsa_key": v_rsa,
          "inline_checkpoint": v_inline, "duplicate_member": v_dup, "scitt_cbor": v_cbor, "scitt_payload": v_payload,
          "scitt_log": v_log, "format_prefixes": v_prefixes, "statement_signatures": v_stsig, "ots_real": v_ots_real,
          "ots_refusals": v_ots_refusals}

NOT_ATTEMPTED = {"reproduction": "needs tests/generate_vectors.py, which the boundary forbids reading or running"}


def run(env):
    out = []
    for c in env.C["vector_cases"]:
        if c["check"] in NOT_ATTEMPTED:
            out.append({"id": c["id"], "agree": "not attempted", "detail": NOT_ATTEMPTED[c["check"]]})
            continue
        try:
            bad = CHECKS[c["check"]](env, c)
            note = None
            if c["check"] == "test_keys":
                note = "the RSA key: 2048 bits and exponent 65537 checked; that it is RFC 9500's was not compared with the RFC's text (not fetched)"
            if c["check"] == "published_rsa_key":
                note = "checked against the values the case states; RFC 9500 itself was not fetched, so the case's values were not compared with the RFC's text"
            out.append({"id": c["id"], "agree": not bad, "detail": bad or note})
        except Exception:
            out.append({"id": c["id"], "agree": False, "detail": "exception: " + traceback.format_exc(limit=3)})
    return out
