"""Replay of interop/umarise/vectors/*.ots from the text of draft-fassbender-scitt-time-anchor-08, with no
OpenTimestamps software and no Bitcoin library. Usage: python ots_replay.py INPUTS_DIR OUT_FILE

Each step is reported on its own; nothing is merged into one result."""
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dpsr import ots as O  # noqa: E402

# Values printed in draft -08, Appendix D (D.1 to D.5), copied here from the text so that the replay can be held
# against them. The D.5 Base64 is read from the draft file itself.
D1 = {
    1: ("a183f624efbbda7d6208b9b5a6f9b0c2c95d90382eb209c44a1131954071f30b", "14ed82e243f4aff3f1794e6754bfae3b",
        "aafc3638a4795c8553b974d36c66aee2a7268ede5535a015fbcc73d01a3b8d52"),
    2: ("0df073a986e5e5141c96ec32303b8552ded255e4404d0aff996936a846b48cff", "b0de8a5526115745c2801d65397db556",
        "7306ab5d2290e681f11699730c07e11a6b7b0b4babe30349f3c74d37ba100728"),
    3: ("d82bf84f17057c0e3d7aa6f249dfc2e80a877b910ce4ce14dc40e653fd5be40b", "f6518213abf9ba8a92c3cb3bcdb82355",
        "d051a6258f904499056f475bfb69eea50a5018bf58144d25121bf5de22fab9dc"),
    4: ("94a86d117047f2af9a2f5635d0c530cc85fc23d20f5d4b42926b94abee7a06ec", "2fb8ccfdfb881b481695a37deeced8e6",
        "8864a03154f5dae2ca5f77aab02ad7fa4ab56129dd1fbe2e2eb2615a5208413d"),
}
D2 = {"node_12": "034dd422ce07afeb555eb7fdbb93418af23455a9c00b79779c8b02d9217778da",
      "node_34": "7c629aed686c15987a7684fd2e3f12d090447c00cb98568b6b9d99069ba008e3",
      "root": "b4d19ae256a6c3bceb27d1a31fbb3dd3e4574616ebe99a367d6ad7224b7e0749"}
D3 = {"height": 957289, "block_hash": "000000000000000000018e5b8c68a63c45b3eeac3a05ecf621a3b3f7890e3534",
      "merkle_root_committed": "81383c9ce0d3174bcc6c352a0a821f9e5151e0bc608322ace6aeecccff3c43ef",
      "merkle_root_displayed": "ef433cffccecaee6ac228360bce051519e1f820a2a356ccc4b17d3e09c3c3881",
      "block_time": "2026-07-09T10:02:59Z"}
D4 = {"size": 1877, "ops_to_bitcoin": 82}
D5_DIGESTS = {1: "2c1ec4cbe4779d8d598b0f9b951d8d2b351b85ab1d9ad4fe0f897f0b8dd7fd97",
              2: "dc630f6039890b988b2de9c51cf5b93915a24488ab69f05b3d3ed4957febb900",
              3: "4e2a3ce0758ab8bef4b1e8311dea6e987b23a718d6eb40b6ed9f239e8cfe1f73",
              4: "4905b48a6d26ed43a12e92c6a75930b2d36ace7889a5937c61de45f6753b450d"}


def constants_in_draft(path):
    """Each value copied from Appendix D into this file is found in the draft's text (a 32-byte value is printed
    in two halves of 32 hex characters, a 16-byte nonce in one), so a transcription error is caught."""
    txt = open(path, encoding="utf-8").read()
    vals = [v for t in D1.values() for v in t] + list(D2.values()) + [D3["block_hash"], D3["merkle_root_committed"],
                                                                      D3["merkle_root_displayed"]] + list(D5_DIGESTS.values())
    missing = []
    for v in vals:
        parts = [v] if len(v) <= 32 else [v[:32], v[32:]]
        if not all(p in txt for p in parts) and v not in txt:
            missing.append(v)
    for t in (D3["block_time"], str(D3["height"])):
        if t not in txt:
            missing.append(t)
    return missing


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def target(bits):
    """The target encoded in nBits: a mantissa of three bytes and an exponent of one (compact form)."""
    exp, mant = bits >> 24, bits & 0x007fffff
    if bits & 0x00800000:
        return None  # negative in the compact form: no valid target
    return mant * (1 << (8 * (exp - 3))) if exp >= 3 else mant >> (8 * (3 - exp))


def header_fields(h):
    return {"version": int.from_bytes(h[0:4], "little"), "prev_hash": h[4:36][::-1].hex(),
            "merkle_root_header_order": h[36:68].hex(), "time": int.from_bytes(h[68:72], "little"),
            "bits": int.from_bytes(h[72:76], "little"), "nonce": int.from_bytes(h[76:80], "little")}


def d5_from_draft(path):
    """The four Base64 blocks of Appendix D.5, read from the draft's text."""
    txt = open(path, encoding="utf-8").read()
    start = txt.index("\nD.5.  Proof Bytes\n")
    end = txt.index("\nD.6.  Negative Test Vector\n", start)
    sec = txt[start:end]
    out = {}
    for n in (1, 2, 3, 4):
        a = sec.index("*Vector %d*" % n)
        b = sec.index("*Vector %d*" % (n + 1)) if n < 4 else len(sec)
        lines = [ln.strip() for ln in sec[a:b].splitlines()]
        b64 = "".join(ln for ln in lines if re.fullmatch(r"[A-Za-z0-9+/=]{4,}", ln))
        out[n] = base64.b64decode(b64)
    return out


def replay_one(n, base, headers, sources, d5):
    ots_path = os.path.join(base, "vectors", "vector%d.ots" % n)
    art = open(os.path.join(base, "vectors", "vector%d.txt" % n), "rb").read()
    data = open(ots_path, "rb").read()
    st = {}
    st["file_size"] = {"value": len(data), "d4_states": D4["size"], "holds": len(data) == D4["size"]}
    st["file_sha256_equals_d5_printed"] = hashlib.sha256(data).hexdigest() == D5_DIGESTS[n]
    st["file_bytes_equal_d5_base64"] = d5.get(n) == data
    h = hashlib.sha256(art).digest()
    st["step1_artifact_sha256"] = h.hex()
    st["artifact_sha256_equals_d1"] = h.hex() == D1[n][0]
    try:
        op, msg, root = O.parse(data)
        st["step3_parse"] = True
    except O.ProofError as e:
        st["step3_parse"] = False
        st["step3_reason"] = str(e)
        return st
    st["step3_file_hash_op_sha256"] = op == "sha256"
    st["step3_msg_equals_artifact_sha256"] = msg == h
    atts = O.replay(root, msg)
    st["attestations"] = [{"kind": "bitcoin" if a["tag"] == O.TAG_BITCOIN else "pending" if a["tag"] == O.TAG_PENDING else a["tag"].hex(),
                           "payload": a["payload"].decode("ascii", "replace") if a["tag"] == O.TAG_PENDING else a["payload"].hex(),
                           "operations_on_the_way": len(a["path"])} for a in atts]
    btc = [a for a in atts if a["tag"] == O.TAG_BITCOIN]
    st["step4_bitcoin_attestation_present"] = bool(btc)
    branches = []
    for a in btc:
        b = {}
        b["step5_operations_only_sha256_append_prepend"] = not a["unsupported"]
        b["step5_operations_count"] = len(a["path"])
        b["operations_count_equals_d4"] = len(a["path"]) == D4["ops_to_bitcoin"]
        b["step5_digest"] = a["digest"].hex() if a["digest"] else None
        # intermediate values against D.1, D.2 and D.4
        m = msg
        seen = []
        for name, arg in a["path"]:
            m = hashlib.sha256(m).digest() if name == "sha256" else (m + arg if name == "append" else arg + m)
            seen.append(m.hex())
        p0 = a["path"][0]
        b["op1_append_nonce_equals_d1"] = p0[0] == "append" and p0[1].hex() == D1[n][1]
        b["leaf_after_op2_equals_d1"] = len(seen) > 1 and seen[1] == D1[n][2]
        b["passes_node_12_or_34"] = (D2["node_12"] in seen) or (D2["node_34"] in seen)
        b["passes_root_d2"] = D2["root"] in seen
        ops = a["path"]
        b["op40_prepend_89_bytes_ending_6a20"] = len(ops) > 39 and ops[39][0] == "prepend" and len(ops[39][1]) == 89 and ops[39][1].endswith(b"\x6a\x20")
        b["op41_append_689b0e00"] = len(ops) > 40 and ops[40][0] == "append" and ops[40][1].hex() == "689b0e00"
        v43 = seen[42] if len(seen) > 42 else ""
        b["value_after_op43_internal_order"] = v43
        b["value_after_op43_begins_3cad384e_as_d4_prints"] = v43.startswith("3cad384e")
        b["value_after_op43_reversed_begins_3cad384e"] = bytes.fromhex(v43)[::-1].hex().startswith("3cad384e") if v43 else False
        b["value_after_op82_begins_81383c9c_as_d4_prints"] = len(seen) > 81 and seen[81].startswith("81383c9c")
        try:
            H = O.bitcoin_height(a["payload"])
            b["step6_height"] = H
            b["height_equals_d3"] = H == D3["height"]
        except O.ProofError as e:
            b["step6_height"] = None
            b["step6_reason"] = str(e)
            branches.append(b)
            continue
        hx = headers.get(str(H), {}).get("header") if isinstance(headers.get(str(H)), dict) else None
        if hx is None:
            b["step7a_candidate_header"] = None
            branches.append(b)
            continue
        hb = bytes.fromhex(hx)
        b["step7a_candidate_header_80_bytes"] = len(hb) == 80
        b["step7a_source"] = "Lemonnier's headers-957289-957300.json (data supplied with the proofs)"
        b["step7b_on_validated_chain"] = "not established: the header set is not validated from the genesis block or from a checkpoint this reader holds (draft -08, 4.1, validated_chain and step 7b)"
        f = header_fields(hb)
        b["step8_merkle_root_equals_digest_header_order"] = hb[36:68] == a["digest"]
        b["merkle_root_equals_d3_committed"] = hb[36:68].hex() == D3["merkle_root_committed"]
        b["d3_displayed_is_reverse_of_committed"] = bytes.fromhex(D3["merkle_root_displayed"]) == bytes.fromhex(D3["merkle_root_committed"])[::-1]
        bh = sha256d(hb)[::-1].hex()
        b["header_double_sha256_block_hash"] = bh
        b["block_hash_equals_d3"] = bh == D3["block_hash"]
        srcs = {k: v.get(str(H), {}).get("hash") for k, v in sources.items()}
        b["block_hash_equals_headers_sources"] = {k: (v == bh) for k, v in srcs.items()}
        b["header_bytes_equal_headers_sources"] = {k: (v.get(str(H), {}).get("header") == hx) for k, v in sources.items()}
        t = target(f["bits"])
        b["bits_hex"] = "%08x" % f["bits"]
        b["proof_of_work_hash_le_target"] = t is not None and int.from_bytes(sha256d(hb), "little") <= t
        b["block_time_ntime"] = dt.datetime.fromtimestamp(f["time"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        b["block_time_equals_d3"] = b["block_time_ntime"] == D3["block_time"]
        branches.append(b)
    st["branches"] = branches
    return st


def chain_checks(headers, start):
    """From the header the proofs start from, each later header: 80 bytes, double SHA-256, proof of work against
    its own bits, and prev_hash equal to the previous header's hash."""
    hs = sorted(int(k) for k in headers)
    out = []
    prev_hash = None
    for h in hs:
        if h < start:
            continue
        hb = bytes.fromhex(headers[str(h)]["header"])
        f = header_fields(hb)
        bh = sha256d(hb)[::-1].hex()
        t = target(f["bits"])
        row = {"height": h, "length_80": len(hb) == 80, "hash": bh, "bits_hex": "%08x" % f["bits"],
               "proof_of_work_hash_le_target": t is not None and int.from_bytes(sha256d(hb), "little") <= t,
               "links_to_previous": None if prev_hash is None else f["prev_hash"] == prev_hash,
               "time": dt.datetime.fromtimestamp(f["time"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        out.append(row)
        prev_hash = bh
    return out


def main():
    inputs, outfile = sys.argv[1], sys.argv[2]
    base = os.path.join(inputs, "lemonnier", "interop", "umarise")
    headers = json.load(open(os.path.join(base, "headers-957289-957300.json")))
    sources = json.load(open(os.path.join(base, "headers-sources.json")))
    d5 = d5_from_draft(os.path.join(inputs, "ietf", "draft-fassbender-scitt-time-anchor-08.txt"))
    res = {"constants_not_found_in_draft": constants_in_draft(os.path.join(inputs, "ietf", "draft-fassbender-scitt-time-anchor-08.txt")),
           "proofs": {"vector%d" % n: replay_one(n, base, headers, sources, d5) for n in (1, 2, 3, 4)},
           "header_chain_from_957289": chain_checks(headers, 957289)}
    hs = res["header_chain_from_957289"]
    res["header_chain_summary"] = {
        "headers": len(hs), "all_80_bytes": all(r["length_80"] for r in hs),
        "all_proof_of_work_hold": all(r["proof_of_work_hash_le_target"] for r in hs),
        "all_link_to_previous": all(r["links_to_previous"] for r in hs[1:]),
        "same_bits_throughout": len({r["bits_hex"] for r in hs}) == 1,
        "blocks_at_or_above_957289_in_the_set": len(hs),
        "step9_confirmations_on_validated_chain": "not established: the set is not a validated chain (see step 7b); "
                                                  "read only as a count of the supplied headers, it is %d" % len(hs)}
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    with open(outfile, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res["header_chain_summary"], indent=1))


if __name__ == "__main__":
    main()
