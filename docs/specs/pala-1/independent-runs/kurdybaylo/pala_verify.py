# PALA-1 independent verifier — freeze-candidate run.
# Written from PALA-1.md (spec commit ff2720a) and test-vectors.json ONLY.
# No reference code, no production codec, no prior runs were read.
#
# Implements:
#   - §2.4 file container walk (self-delimiting records, truncated-tail report)
#   - §7.1 header-only chain verification + §7.4 semantic checks
#   - §7.2 completeness against an anchor
#   - §4.3 RFC 6962 Merkle tree (BOTH constructions, cross-checked) + inclusion proof
#   - §7.5 body digest verification; AES-256-GCM decryption per §4.4 if a library is present
#   - §8 mutation demos (bitflip, unknown type, truncation, stale anchor, seq gap,
#     missing genesis, unknown time with clock)
#
# Documented choices (see ambiguity log in the run record):
#   A1: at index 0, a non-GENESIS first record yields ONE violation and no break/no
#       zero-prev violation — per §4.2 prose ("the links around it may be perfectly
#       sound") and the §8 missing_genesis demo; the §7.1 pseudocode read literally
#       would add a break at h.seq and a second violation. Logged as a defect.
#   A2: breaks/gaps are keyed by h.seq (explicit in §7.1); violations have no stated
#       key — keyed by seq for per-record checks, position 0 for the chain-start check.
#   A3: proof entry ["L", h] means the sibling is the LEFT operand of node(); inferred
#       from the vector data, not stated in the spec text.

import hashlib
import json
import struct
import sys
from pathlib import Path

HDR = struct.Struct('<4sHHHBBQ16s32s16s16sQqII32s')   # 156 bytes, §2.1
assert HDR.size == 156

ZERO32 = b'\x00' * 32
GENESIS = 0x0001
KNOWN_TYPES = {0x0001, 0x0002, 0x0010, 0x0011, 0x0012, 0x0020, 0x0021,
               0x0030, 0x0040, 0x0050, 0x0051, 0x0060}                    # §3
KNOWN_VERSIONS = {1}

sha = lambda b: hashlib.sha256(b).digest()
hx = lambda b: b.hex()


class Record:
    __slots__ = ('offset', 'header_bytes', 'body', 'magic', 'version', 'header_len',
                 'record_type', 'tier', 'time_trust', 'seq', 'boot_id', 'prev_hash',
                 'span_id', 'parent_span_id', 'monotonic_ns', 'wall_clock_ns',
                 'key_id', 'body_len', 'body_digest')

    def __init__(self, buf, off):
        (self.magic, self.version, self.header_len, self.record_type, self.tier,
         self.time_trust, self.seq, self.boot_id, self.prev_hash, self.span_id,
         self.parent_span_id, self.monotonic_ns, self.wall_clock_ns, self.key_id,
         self.body_len, self.body_digest) = HDR.unpack_from(buf, off)
        self.offset = off
        self.header_bytes = bytes(buf[off:off + self.header_len])
        self.body = bytes(buf[off + self.header_len:
                              off + self.header_len + self.body_len])

    @property
    def record_hash(self):
        return sha(self.header_bytes)


# ---------- §2.4 container walk ----------

def walk_container(buf):
    """Records concatenated back-to-back; next = offset + header_len + body_len.
    Returns (records, tail_error). A file whose final record ends exactly at EOF is
    well-formed; anything else is a truncated tail (§2.4), not a chain break."""
    records, off, tail = [], 0, None
    while off < len(buf):
        if len(buf) - off < 156:
            tail = f'truncated tail: {len(buf) - off} byte(s) at offset {off} — not a full fixed header'
            break
        r = Record(buf, off)
        if r.magic != b'PALA':
            tail = f'bad magic at offset {off} — stop (§7.1)'
            break
        if r.header_len < 156 or off + r.header_len > len(buf):
            tail = f'truncated tail: header_len {r.header_len} overruns file at offset {off}'
            break
        if off + r.header_len + r.body_len > len(buf):
            tail = f'truncated tail: body of seq {r.seq} overruns end of file'
            break
        records.append(r)
        off += r.header_len + r.body_len
    return records, tail


# ---------- §2.2 TLV ----------

def parse_tlvs(header_bytes):
    """TLVs from byte 156 to header_len; last item MUST end exactly at header_len."""
    tlvs, pos, end = [], 156, len(header_bytes)
    while pos < end:
        if end - pos < 4:
            return tlvs, 'TLV item header overruns header_len'
        t, ln = struct.unpack_from('<HH', header_bytes, pos)
        if pos + 4 + ln > end:
            return tlvs, 'TLV value overruns header_len'
        tlvs.append((t, header_bytes[pos + 4:pos + 4 + ln]))
        pos += 4 + ln
    return tlvs, None   # pos == end exactly, or no TLVs at all


# ---------- §7.4 semantic checks ----------

def semantic_checks(r, violations):
    if r.time_trust == 0 and r.wall_clock_ns != 0:
        violations.append([r.seq, 'time_trust=UNKNOWN requires wall_clock_ns=0'])
    if r.time_trust > 3:
        violations.append([r.seq, f'time_trust={r.time_trust} undefined in version 1'])
    if (r.body_len == 0) != (r.body_digest == ZERO32):
        violations.append([r.seq, 'body_len==0 iff body_digest==32 zero bytes violated'])
    if r.key_id != 0 and 0 < r.body_len < 28:
        violations.append([r.seq, 'encrypted body shorter than nonce+tag (28 bytes)'])
    _, err = parse_tlvs(r.header_bytes)
    if err:
        violations.append([r.seq, err])


# ---------- §7.1 header-only chain verification ----------

def verify_chain(records):
    prev = ZERO32
    expected = None
    breaks, gaps, violations, uninterpretable = [], [], [], []
    for i, r in enumerate(records):
        if i == 0:
            if r.record_type != GENESIS:
                violations.append([0, 'chain does not start with a GENESIS record'])   # A1/A2
            elif r.prev_hash != ZERO32:
                violations.append([r.seq, 'GENESIS prev_hash is not 32 zero bytes'])
        else:
            if r.record_type == GENESIS:
                violations.append([r.seq, 'GENESIS at a position other than first'])
            if r.prev_hash != prev:
                breaks.append(r.seq)
        if expected is not None and r.seq != expected:
            gaps.append(r.seq)
        expected = r.seq + 1
        if r.version not in KNOWN_VERSIONS or r.record_type not in KNOWN_TYPES:
            uninterpretable.append(r.seq)          # NOT a break, no §7.4 — §7.5/§7.6
        else:
            semantic_checks(r, violations)
        prev = r.record_hash
    return {
        'chain_ok': not (breaks or gaps or violations),
        'count': len(records),
        'breaks': breaks, 'gaps': gaps, 'violations': violations,
        'uninterpretable': uninterpretable,
        'head': hx(prev),
    }


# ---------- §7.2 completeness against an anchor ----------

def completeness(records, head_hex, anchor_hex):
    if anchor_hex == head_hex:
        return {'complete_to_anchor': True}
    hashes = [hx(r.record_hash) for r in records]
    if anchor_hex in hashes:
        lag = len(records) - 1 - hashes.index(anchor_hex)
        return {'complete_to_anchor': False, 'anchor_lag': lag,
                'reason': f'chain extends {lag} record(s) beyond the anchored head — '
                          'an unanchored tail, not a replacement'}
    return {'complete_to_anchor': False,
            'reason': 'the anchored head names no record in this chain — '
                      'the log was replaced, rolled back, or truncated'}


# ---------- §4.3 Merkle (RFC 6962, promotion — both constructions) ----------

def m_leaf(d):
    return sha(b'\x00' + d)

def m_node(l, r):
    return sha(b'\x01' + l + r)

def merkle_root_iterative(leaf_digests):
    if not leaf_digests:
        return sha(b'')
    level = [m_leaf(d) for d in leaf_digests]
    while len(level) > 1:
        nxt = [m_node(level[j], level[j + 1]) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])                 # PROMOTED, never duplicated
        level = nxt
    return level[0]

def merkle_root_recursive(leaf_digests):
    n = len(leaf_digests)
    if n == 0:
        return sha(b'')
    if n == 1:
        return m_leaf(leaf_digests[0])
    k = 1
    while k * 2 < n:                              # largest power of two below n
        k *= 2
    return m_node(merkle_root_recursive(leaf_digests[:k]),
                  merkle_root_recursive(leaf_digests[k:]))

def fold_proof(leaf_digest, proof):
    h = m_leaf(leaf_digest)
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        h = m_node(sib, h) if side == 'L' else m_node(h, sib)   # A3
    return h


# ---------- §7.5 body verification ----------

def body_checks(records):
    out = []
    for r in records:
        if r.body_len == 0:
            continue
        ok = sha(r.body) == r.body_digest
        out.append({'seq': r.seq, 'body_digest_match': ok, 'key_id': r.key_id})
    return out

def try_decrypt(record, key):
    """§4.4: body = nonce(12) || ciphertext || tag(16); nonce = 4 zero bytes || seq LE;
    aad = seq LE || boot_id || record_type LE. Optional — needs an AES-GCM library."""
    derived_nonce = b'\x00' * 4 + struct.pack('<Q', record.seq)
    nonce, ct_tag = record.body[:12], record.body[12:]
    aad = struct.pack('<Q', record.seq) + record.boot_id + struct.pack('<H', record.record_type)
    result = {'seq': record.seq, 'nonce_matches_rule': nonce == derived_nonce}
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        pt = AESGCM(key).decrypt(nonce, ct_tag, aad)
        result['decrypted'] = True
        result['plaintext'] = pt.decode('utf-8', 'replace')
    except ImportError:
        result['decrypted'] = None
        result['note'] = 'no AES-GCM library available; digest layer verified, decryption not run'
    except Exception as e:
        result['decrypted'] = False
        result['note'] = f'decryption failed: {e.__class__.__name__}'
    return result


# ---------- helpers for the mutation demos ----------

def concat(records):
    return b''.join(r.header_bytes + r.body for r in records)

def with_seq(header_bytes, new_seq):
    b = bytearray(header_bytes)
    struct.pack_into('<Q', b, 12, new_seq)
    return bytes(b)

def make_header(prev_hash, seq, rtype, boot_id, time_trust=1, wall_clock_ns=0):
    return HDR.pack(b'PALA', 1, 156, rtype, 0, time_trust, seq, boot_id, prev_hash,
                    b'\x00' * 16, b'\x00' * 16, 99_000_000_000, wall_clock_ns,
                    0, 0, ZERO32)


# ---------- main ----------

def main(vectors_path):
    v = json.loads(Path(vectors_path).read_text(encoding='utf-8'))

    # 1. Build the file container (§2.4): concatenate header_hex + body_hex.
    container = b''.join(bytes.fromhex(rec['header_hex']) + bytes.fromhex(rec.get('body_hex', ''))
                         for rec in v['records'])
    records, tail = walk_container(container)
    assert tail is None, tail

    # 2. §7.1 + §7.2
    chain = verify_chain(records)
    comp = completeness(records, chain['head'], v['anchor_head'])

    # Per-record cross-check against the vectors' own record_hash values (extra).
    per_record_hash_ok = all(hx(r.record_hash) == rec['record_hash']
                             for r, rec in zip(records, v['records']))

    # 3. §4.3 Merkle from published leaves; both constructions must agree.
    leaves = [bytes.fromhex(h) for h in v['merkle']['leaves']]
    root_i = merkle_root_iterative(leaves)
    root_r = merkle_root_recursive(leaves)
    merkle_rec = records[4]
    tlvs, _ = parse_tlvs(merkle_rec.header_bytes)
    tlv = dict((t, val) for t, val in tlvs)
    tlv_root = tlv.get(0x0011, b'')
    tlv_count = struct.unpack('<I', tlv.get(0x0012, b'\x00' * 4))[0]
    proof_root = fold_proof(leaves[v['merkle']['proof_index']], v['merkle']['proof'])

    # §7.5 digests + optional decryption of the seq-3 body.
    bodies = body_checks(records)
    decrypt = try_decrypt(records[3], bytes.fromhex(v['aes_key_hex']))

    results = {
        'chain_head': chain['head'],
        'chain_ok': chain['chain_ok'],
        'record_count': chain['count'],
        'breaks': chain['breaks'],
        'gaps': chain['gaps'],
        'violations': chain['violations'],
        'uninterpretable': chain['uninterpretable'],
        'complete_to_anchor': comp.get('complete_to_anchor'),
        'anchor_head_published': v['anchor_head'],
        'anchor_head_equals_chain_head': v['anchor_head'] == chain['head'],
        'per_record_hashes_match_vectors': per_record_hash_ok,
        'merkle_tree_hash_iterative': hx(root_i),
        'merkle_tree_hash_recursive': hx(root_r),
        'constructions_agree': root_i == root_r,
        'merkle_tree_hash_matches_published': hx(root_i) == v['merkle']['tree_hash'],
        'merkle_tree_hash_matches_record_tlv': root_i == tlv_root,
        'merkle_leaf_count_records_tlv': tlv_count,
        'merkle_leaf_count_matches_leaves': tlv_count == len(leaves),
        'proof_index': v['merkle']['proof_index'],
        'proof_len': len(v['merkle']['proof']),
        'proof_verifies': proof_root == root_i,
        'body_digest_checks': bodies,
        'seq3_decrypt': decrypt,
        'plaintext_matches_published': decrypt.get('plaintext') == v.get('plaintext_utf8')
                                       if decrypt.get('decrypted') else None,
    }

    # ---------- §8 mutation demos (SHOULD) ----------
    demos = {}
    boot_id = records[0].boot_id
    head = bytes.fromhex(chain['head'])

    # body_bitflip: flip one bit in the seq-3 body.
    flipped = list(records[3].body)
    flipped[20] ^= 0x01
    mutated = (concat(records[:3])
               + records[3].header_bytes + bytes(flipped)
               + concat(records[4:]))
    m_recs, _ = walk_container(mutated)
    m_chain = verify_chain(m_recs)
    demos['body_bitflip'] = {
        'detected': sha(m_recs[3].body) != m_recs[3].body_digest,
        'chain_still_verifies': m_chain['chain_ok'],
    }

    # unknown_record_type: append type 0x7fff.
    u_recs, _ = walk_container(container + make_header(head, 12, 0x7FFF, boot_id))
    u = verify_chain(u_recs)
    demos['unknown_record_type'] = {'type': '0x7fff', 'chain_ok': u['chain_ok'],
                                    'count': u['count'],
                                    'uninterpretable_seqs': u['uninterpretable']}

    # tail_truncation: drop the last record; §7.1 blind, §7.2 sees it.
    t_recs, _ = walk_container(concat(records[:-1]))
    t = verify_chain(t_recs)
    t_comp = completeness(t_recs, t['head'], v['anchor_head'])
    demos['tail_truncation'] = {'dropped_seq': 11,
                                'chain_ok_without_anchor': t['chain_ok'],
                                'complete_to_anchor': t_comp['complete_to_anchor'],
                                'anchor_reason': t_comp.get('reason')}

    # stale_anchor: check the full chain against the ANCHOR record's TLV head.
    anchor_tlvs, _ = parse_tlvs(records[9].header_bytes)
    stale = hx(dict(anchor_tlvs)[0x0050])
    s_comp = completeness(records, chain['head'], stale)
    demos['stale_anchor'] = {'anchor_names_seq': 8, 'chain_ok': chain['chain_ok'],
                             'complete_to_anchor': s_comp['complete_to_anchor'],
                             'anchor_lag': s_comp.get('anchor_lag'),
                             'anchor_reason': s_comp.get('reason')}

    # seq_gap: rewrite the last record's seq 11 -> 99; every hash link stays valid.
    g_container = concat(records[:-1]) + with_seq(records[11].header_bytes, 99)
    g_recs, _ = walk_container(g_container)
    g = verify_chain(g_recs)
    demos['seq_gap'] = {'chain_ok': g['chain_ok'], 'gaps': g['gaps'],
                        'breaks': g['breaks']}

    # missing_genesis: drop record 0.
    n_recs, _ = walk_container(concat(records[1:]))
    n = verify_chain(n_recs)
    demos['missing_genesis'] = {'chain_ok': n['chain_ok'], 'breaks': n['breaks'],
                                'violations': n['violations']}

    # unknown_time_with_clock: append a known-type record, time_trust=0, non-zero clock.
    w_recs, _ = walk_container(container + make_header(head, 12, 0x0012, boot_id,
                                                       time_trust=0,
                                                       wall_clock_ns=1_784_000_010_000_000_000))
    w = verify_chain(w_recs)
    demos['unknown_time_with_clock'] = {'chain_ok': w['chain_ok'],
                                        'violations': w['violations']}

    print(json.dumps({'results': results, 'demos': demos}, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'test-vectors.json')
