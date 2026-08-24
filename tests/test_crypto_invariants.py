# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Cryptographic scope and agility — the seams a future suite rides through.

PALA-1 core is frozen at v1.0 with exactly one cryptographic suite: SHA-256
for every integrity purpose (record hash, body digest, Merkle tree) and
AES-256-GCM for encrypted bodies. Agility for a frozen format is therefore
not a second algorithm — it is the small set of *behaviors* through which a
future suite would arrive without an envelope change, and those behaviors
have rested on five implementations agreeing with one another rather than on
a test that pins them. This module pins them.

Provenance, stated because a pin derived from the implementation pins only
the implementation to itself:

- known answers come from the published companion vectors
  (``docs/specs/pala-1/profiles/inference-vectors.json``) — record hashes,
  body digests, the encryption block and its plaintext;
- hand-built records pack the §2.1 field table transcribed below rather than
  the codec's own format string, and the transcription is itself checked
  against a published header before anything is built with it;
- chain links are folded with ``hashlib.sha256`` directly, never with
  ``record_hash``, so a fixture cannot inherit the assumption it exists
  to test.

These tests *describe* the system: they pass against ``main`` with no
production-code change, and they fix nothing. The companion note is
``docs/specs/pala-1/CRYPTO-AGILITY.md``.

Stdlib-only except the two §4.4/§7.5 body assertions, which skip without
the ``[pala]`` extra — the same split the format itself draws.
"""
from __future__ import annotations

import hashlib
import json
import pytest
import struct
from palimpsests.audit.pala import (
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    Header,
    MalformedRecord,
    aad_for,
    body_digest_of,
    codec,
    decode_tlvs,
    encode_tlvs,
    iter_records,
    nonce_for,
    open_body,
    record_hash,
    verify_headers,
)
from palimpsests.audit.pala.codec import (
    RT_EVENT,
    RT_GENESIS,
    RT_WITNESS,
    TLV_WITNESS_RECEIPT,
    ZERO16,
    ZERO32,
)
from palimpsests.audit.pala_writer import PalaWriter
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"
VECTORS = json.loads((SPEC_DIR / "profiles" / "inference-vectors.json").read_text())
RECORDS = {r["label"]: r for r in VECTORS["records"]}
BOOT_ID = bytes.fromhex(VECTORS["boot_id"])

# ── the §2.1 fixed header, transcribed from the specification table ──────
#
# magic 0 (4) | format_version 4 (2) | header_len 6 (2) | record_type 8 (2)
# assurance_tier 10 (1) | time_trust 11 (1) | seq 12 (8) | boot_id 20 (16)
# prev_hash 36 (32) | span_id 68 (16) | parent_span_id 84 (16)
# monotonic_ns 100 (8) | wall_clock_ns 108 (8, signed) | key_id 116 (4)
# body_len 120 (4) | body_digest 124 (32) — 156 bytes, little-endian, no
# padding. §7.6 freezes magic, format_version, header_len, record_type,
# seq, boot_id, prev_hash, body_len and body_digest at these offsets for
# every future version, which is what makes the transcription safe.
LAYOUT = "<4sHHHBBQ16s32s16s16sQqII32s"

OFF_HEADER_LEN = 6
OFF_SEQ = 12
OFF_PREV_HASH = slice(36, 68)
OFF_KEY_ID = 116
OFF_BODY_DIGEST = slice(124, 156)


def _header(
    *,
    record_type: int,
    seq: int,
    prev_hash: bytes,
    version: int = FORMAT_VERSION,
    body_len: int = 0,
    body_digest: bytes = ZERO32,
    tlvs: bytes = b"",
) -> bytes:
    """Pack one header field by field, straight from the §2.1 table."""
    return (
        struct.pack(
            LAYOUT,
            b"PALA",                       # magic
            version,                       # format_version
            FIXED_HEADER_LEN + len(tlvs),  # header_len — the actual byte count
            record_type,                   # record_type
            0,                             # assurance_tier — tier A (§6)
            0,                             # time_trust — UNKNOWN (§5)
            seq,                           # seq
            BOOT_ID,                       # boot_id
            prev_hash,                     # prev_hash
            ZERO16,                        # span_id
            ZERO16,                        # parent_span_id
            0,                             # monotonic_ns
            0,                             # wall_clock_ns — 0, as UNKNOWN requires
            0,                             # key_id — absent or cleartext body
            body_len,                      # body_len
            body_digest,                   # body_digest
        )
        + tlvs
    )


def _linked(specs: list[tuple[dict, bytes]]) -> list[tuple[bytes, bytes]]:
    """Build a chain: each ``prev_hash`` names the header before it (§4.1)."""
    out: list[tuple[bytes, bytes]] = []
    prev = ZERO32
    for spec, body in specs:
        hb = _header(prev_hash=prev, **spec)
        out.append((hb, body))
        prev = hashlib.sha256(hb).digest()
    return out


def _headers(records: list[tuple[bytes, bytes]]) -> list[bytes]:
    return [hb for hb, _ in records]


def test_the_transcribed_layout_is_the_156_byte_header_of_the_spec():
    assert struct.calcsize(LAYOUT) == 156 == FIXED_HEADER_LEN


def test_the_transcribed_layout_parses_a_published_header():
    """The transcription is checked against the vectors, not trusted."""
    rec = RECORDS["boot"]
    hb = bytes.fromhex(rec["header_hex"])
    magic, version, header_len, record_type = struct.unpack_from(LAYOUT, hb, 0)[:4]
    seq, boot_id, prev_hash = struct.unpack_from(LAYOUT, hb, 0)[6:9]
    assert magic == b"PALA"
    assert version == FORMAT_VERSION == 1
    assert header_len == rec["header_len"] == len(hb)
    assert record_type == int(rec["record_type"], 16)
    assert seq == rec["seq"]
    assert boot_id == BOOT_ID
    assert prev_hash.hex() == RECORDS["genesis"]["record_hash"]


# ═══ A1. Known-answer pins for the fixed suite ═══════════════════════════

PINNED = [
    "genesis",
    "boot",
    "guard_refusal",
    "encrypted_content_event",
    "anchor",
    "key_shred_documented",
]


@pytest.mark.parametrize("label", PINNED)
def test_record_hash_reproduces_the_published_value(label):
    """§1.2: SHA-256 over the header bytes, and nothing else."""
    rec = RECORDS[label]
    hb = bytes.fromhex(rec["header_hex"])
    assert len(hb) == rec["header_len"]
    assert record_hash(hb).hex() == rec["record_hash"]
    assert record_hash(hb) == hashlib.sha256(hb).digest()


def test_the_pinned_records_cover_distinct_record_types():
    """Three or more *different* types, not one type six times."""
    types = {RECORDS[label]["record_type"] for label in PINNED}
    assert len(types) == len(PINNED) >= 3


@pytest.mark.parametrize(
    "label", ["guard_refusal", "encrypted_content_event", "incident_candidate"]
)
def test_body_digest_reproduces_the_embedded_header_field(label):
    """§2.1/§4.4: SHA-256 over exactly ``body_len`` bytes, either shape."""
    rec = RECORDS[label]
    hb = bytes.fromhex(rec["header_hex"])
    body = bytes.fromhex(rec["body_hex"])
    assert len(body) == rec["body_len"]
    assert body_digest_of(body) == hb[OFF_BODY_DIGEST]


def test_the_encrypted_body_derivations_round_trip_to_the_published_plaintext():
    """§4.4 end to end: nonce, AAD, key and ciphertext all from the vectors."""
    pytest.importorskip("cryptography", reason="body crypto needs the [pala] extra")
    enc = VECTORS["encryption"]
    rec = RECORDS["encrypted_content_event"]
    hb = bytes.fromhex(rec["header_hex"])
    body = bytes.fromhex(rec["body_hex"])
    seq = rec["seq"]
    record_type = int(rec["record_type"], 16)
    key = bytes.fromhex(enc["key_hex"])

    assert seq == 3  # the record the encryption block publishes a plaintext for
    assert len(key) == 32  # AES-256, the one suite (§4.4)
    assert struct.unpack_from("<I", hb, OFF_KEY_ID)[0] == enc["key_id"] == 9

    # nonce = 4 zero bytes ‖ seq (u64 LE), and it sits INSIDE body_len (§2.3)
    assert nonce_for(seq) == b"\x00\x00\x00\x00" + struct.pack("<Q", seq)
    assert body[:12] == nonce_for(seq)
    assert len(body) == rec["body_len"] >= 12 + 16  # nonce ‖ ciphertext ‖ tag

    # aad = seq (u64 LE) ‖ boot_id (16) ‖ record_type (u16 LE)
    assert aad_for(seq, BOOT_ID, record_type) == (
        struct.pack("<Q", seq) + BOOT_ID + struct.pack("<H", record_type)
    )

    plaintext = open_body(
        key,
        seq=seq,
        boot_id=BOOT_ID,
        record_type=record_type,
        body=body,
        body_digest=hb[OFF_BODY_DIGEST],
    )
    assert plaintext.decode() == enc["seq3_plaintext"]


# ═══ A2. The §7.6 seam — an unknown format_version ═══════════════════════

UNKNOWN_VERSION = 2
SEAM_BODY = b"a future suite's body: opaque bytes to a version-1 reader"


def _seam_records(version: int) -> list[tuple[bytes, bytes]]:
    """GENESIS → one record at ``version`` → EVENT, correctly linked.

    The middle record carries a non-empty body against an all-zero
    ``body_digest``. On a version-1 record that is a §7.4 violation
    (§2.1: ``body_len == 0`` ⟺ ``body_digest`` all zero) — which is exactly
    the deliberately wrong-looking shape §7.6 forbids judging across a
    version the verifier does not claim.
    """
    return _linked(
        [
            ({"record_type": RT_GENESIS, "seq": 0}, b""),
            (
                {
                    "version": version,
                    "record_type": RT_EVENT,
                    "seq": 1,
                    "body_len": len(SEAM_BODY),
                    "body_digest": ZERO32,
                },
                SEAM_BODY,
            ),
            ({"record_type": RT_EVENT, "seq": 2}, b""),
        ]
    )


def test_an_unknown_format_version_is_reported_never_rejected():
    """§7.6's MUSTs, on a chain that is otherwise beyond reproach."""
    res = verify_headers(_headers(_seam_records(UNKNOWN_VERSION)))
    assert res.chain_ok is True
    assert res.breaks == []
    assert res.gaps == []
    assert res.violations == []
    assert res.uninterpretable == [1]
    assert res.count == 3


def test_the_unknown_record_is_hashed_into_the_head_not_skipped():
    headers = _headers(_seam_records(UNKNOWN_VERSION))
    res = verify_headers(headers)

    # §7.1's `prev := SHA-256(h.header_bytes)`, folded by hand.
    assert res.head == hashlib.sha256(headers[2]).digest()
    # …and the last record's prev_hash names the unknown one, so the head
    # summarises a chain that runs *through* it rather than around it.
    assert headers[2][OFF_PREV_HASH] == hashlib.sha256(headers[1]).digest()

    # The counterfactual: drop the unknown record and the chain stops
    # linking — the hash above is load-bearing, not a coincidence.
    skipped = verify_headers([headers[0], headers[2]])
    assert skipped.chain_ok is False
    assert skipped.breaks == [2]
    assert skipped.gaps == [2]


def test_the_container_walk_crosses_an_unknown_record_with_a_body():
    """§7.6 freezes ``body_len`` for a mechanical reason: without it a
    reader cannot find the record after an unknown one that has a body."""
    records = _seam_records(UNKNOWN_VERSION)
    container = b"".join(hb + body for hb, body in records)
    assert list(iter_records(container)) == records


def test_semantic_checks_do_not_cross_the_version_seam():
    """§7.6: §7.4 belongs to the version a verifier claims.

    The control is the same field combination at ``format_version = 1``.
    It *is* flagged there — so what exempts the seam record is its version
    and nothing else about it.
    """
    seam = verify_headers(_headers(_seam_records(UNKNOWN_VERSION)))
    assert seam.violations == []
    assert seam.uninterpretable == [1]

    control = verify_headers(_headers(_seam_records(FORMAT_VERSION)))
    assert control.uninterpretable == []
    assert [seq for seq, _ in control.violations] == [1]
    assert "body_digest" in control.violations[0][1]
    assert control.chain_ok is False
    assert control.breaks == []
    assert control.gaps == []


def test_full_interpretation_stops_at_the_seam_while_the_chain_does_not():
    """``Header.decode`` claims to interpret a record; §7.1 only claims to
    chain it. Both postures meeting the same bytes is §7.6's mechanism."""
    records = _seam_records(UNKNOWN_VERSION)
    with pytest.raises(MalformedRecord):
        Header.decode(records[1][0])
    assert verify_headers(_headers(records)).chain_ok is True


# ═══ A3. The framing seam — wider digests are frameable ══════════════════

WIDER_DIGEST = bytes(range(48))  # 48 bytes: the width of a SHA-384-class suite
UNALLOCATED_TLV = 0x0F48

#: §2.2's header-TLV table, transcribed. "A type the current profile does
#: not allocate" is only checkable against the allocation itself.
SPEC_TLV_TYPES = frozenset(
    {
        0x0001, 0x0002, 0x0003,          # ORIGIN_{ROLE,MODEL_DIGEST,CONFIG_DIGEST}
        0x0011, 0x0012,                  # MERKLE_{TREE_HASH,LEAF_COUNT}
        0x0020, 0x0021, 0x0022,          # SHED_{CLASS,COUNT,WINDOW_NS}
        0x0030, 0x0031, 0x0032, 0x0033,  # WITNESS_{KIND,RANGE_LO,RANGE_HI,RECEIPT}
        0x0040,                          # SHRED_KEY_ID
        0x0050,                          # ANCHOR_HEAD
    }
)


def test_the_chosen_tlv_type_is_unallocated_in_version_1():
    allocated = {v for name, v in vars(codec).items() if name.startswith("TLV_")}
    assert allocated == set(SPEC_TLV_TYPES)  # the codec allocates §2.2's table, no more
    assert UNALLOCATED_TLV not in SPEC_TLV_TYPES


def test_tlv_framing_round_trips_a_48_byte_value():
    """§2.2 carries an explicit length, so value width is not an envelope
    property — a wider digest needs no framing change."""
    buf = encode_tlvs([(UNALLOCATED_TLV, WIDER_DIGEST)])
    assert buf == struct.pack("<HH", UNALLOCATED_TLV, 48) + WIDER_DIGEST
    assert len(buf) == 4 + 48
    assert decode_tlvs(buf) == [(UNALLOCATED_TLV, WIDER_DIGEST)]


def test_a_chain_carrying_a_48_byte_tlv_verifies_with_the_tlv_reported():
    tlvs = encode_tlvs([(UNALLOCATED_TLV, WIDER_DIGEST)])
    headers = _headers(
        _linked(
            [
                ({"record_type": RT_GENESIS, "seq": 0}, b""),
                ({"record_type": RT_EVENT, "seq": 1, "tlvs": tlvs}, b""),
            ]
        )
    )
    res = verify_headers(headers)
    assert res.chain_ok is True
    assert res.violations == []
    assert res.uninterpretable == []  # an unknown TLV type is not an unknown record

    # Hashed in, because header_len covers it (§2.2), and reported as-is.
    assert struct.unpack_from("<H", headers[1], OFF_HEADER_LEN)[0] == FIXED_HEADER_LEN + 4 + 48
    assert (UNALLOCATED_TLV, WIDER_DIGEST) in Header.decode(headers[1]).tlvs


def test_a_witness_receipt_is_opaque_bytes_up_to_the_u16_ceiling():
    """§7.3: a receipt follows the witness's own protocol, so the format
    holds it as opaque bytes. A post-quantum receipt is a longer value,
    not a wire change — until it exceeds what ``header_len`` can count,
    which is the honest bound on that sentence.
    """
    receipt = bytes(49856)  # SPHINCS+-256f signature size, as a scale check
    tlvs = encode_tlvs([(TLV_WITNESS_RECEIPT, receipt)])
    headers = _headers(
        _linked(
            [
                ({"record_type": RT_GENESIS, "seq": 0}, b""),
                ({"record_type": RT_WITNESS, "seq": 1, "tlvs": tlvs}, b""),
            ]
        )
    )
    res = verify_headers(headers)
    assert res.chain_ok is True
    assert res.violations == []
    assert (TLV_WITNESS_RECEIPT, receipt) in Header.decode(headers[1]).tlvs

    # The ceiling: header_len is a u16 (§2.1), so the TLV area stops at
    # 65535 − 156 − 4 bytes. Past it a receipt is not frameable in a
    # header at all — a format-version question, not a longer value.
    assert FIXED_HEADER_LEN + 4 + len(receipt) <= 0xFFFF
    with pytest.raises(struct.error):
        _header(
            record_type=RT_WITNESS,
            seq=0,
            prev_hash=ZERO32,
            tlvs=encode_tlvs([(TLV_WITNESS_RECEIPT, bytes(0xFFFF - FIXED_HEADER_LEN - 3))]),
        )


# ═══ A4. The body-digest boundary, byte-precise ══════════════════════════


def _with_a_body() -> tuple[dict, bytes, bytes]:
    rec = RECORDS["guard_refusal"]
    return rec, bytes.fromhex(rec["header_hex"]), bytes.fromhex(rec["body_hex"])


def _vector_container(mutate: str | None = None) -> bytes:
    """The published chain as a §2.4 container, optionally with one body
    byte flipped. Headers are never touched."""
    parts = []
    for rec in VECTORS["records"]:
        body = bytes.fromhex(rec.get("body_hex", ""))
        if rec["label"] == mutate:
            body = bytes([body[0] ^ 0x01]) + body[1:]
        parts.append(bytes.fromhex(rec["header_hex"]) + body)
    return b"".join(parts)


def test_a_mutated_body_moves_its_digest_but_not_the_record_hash():
    """§1.2: the record hash covers header bytes only."""
    rec, hb, body = _with_a_body()
    mutated = bytes([body[0] ^ 0x01]) + body[1:]
    assert len(mutated) == len(body)
    assert body_digest_of(mutated) != body_digest_of(body)
    assert record_hash(hb).hex() == rec["record_hash"]  # header untouched, hash unmoved
    assert hb[OFF_BODY_DIGEST] == body_digest_of(body)  # still names the original body


def test_mutating_the_embedded_body_digest_moves_the_record_hash():
    """The body is bound *through* that field, so the binding is real."""
    rec, hb, _ = _with_a_body()
    tampered = hb[:124] + bytes([hb[124] ^ 0x01]) + hb[125:]
    assert len(tampered) == len(hb)
    assert tampered[:124] == hb[:124]
    assert tampered[125:] == hb[125:]
    assert record_hash(tampered) != record_hash(hb)
    assert record_hash(hb).hex() == rec["record_hash"]


def test_a_mutated_body_leaves_the_header_only_verdict_untouched():
    """The blindness is the design, not an oversight.

    §7.1/§7.4 are header-only: ``chain_ok`` answers *"are these the bytes,
    in order, complete?"*. A body swap is invisible to it, and the check
    that does see it lives on the body path — the next test. (The issue
    that commissioned this module cited §7.4 for that check; §7.4 is
    body-blind, and the correct citation is §7.5.)
    """
    intact = list(iter_records(_vector_container()))
    swapped = list(iter_records(_vector_container(mutate="guard_refusal")))
    assert _headers(intact) == _headers(swapped)  # headers byte-identical
    assert [b for _, b in intact] != [b for _, b in swapped]

    before = verify_headers(_headers(intact))
    after = verify_headers(_headers(swapped))
    assert before.chain_ok is after.chain_ok is True
    assert before.head == after.head == bytes.fromhex(VECTORS["chain_head"])


def test_the_body_digest_check_catches_the_mutation_where_it_belongs():
    """§7.5: ``SHA-256(body) == header.body_digest``, digest before key."""
    mismatches = [
        struct.unpack_from("<Q", hb, OFF_SEQ)[0]
        for hb, body in iter_records(_vector_container(mutate="guard_refusal"))
        if body and body_digest_of(body) != hb[OFF_BODY_DIGEST]
    ]
    assert mismatches == [RECORDS["guard_refusal"]["seq"]]

    pytest.importorskip("cryptography", reason="body crypto needs the [pala] extra")
    rec = RECORDS["encrypted_content_event"]
    hb = bytes.fromhex(rec["header_hex"])
    body = bytes.fromhex(rec["body_hex"])
    with pytest.raises(ValueError, match="body_digest"):
        open_body(
            bytes.fromhex(VECTORS["encryption"]["key_hex"]),
            seq=rec["seq"],
            boot_id=BOOT_ID,
            record_type=int(rec["record_type"], 16),
            body=bytes([body[0] ^ 0x01]) + body[1:],
            body_digest=hb[OFF_BODY_DIGEST],
        )


# ═══ A5. Width validation at every 32-byte seam ══════════════════════════

#: Every writer entry point that validates a 32-byte value, keyed by the
#: parameter under test. The other parameters are held at valid widths, so
#: a refusal can only be about the one being varied.
WIDTH_SEAMS = {
    "args_digest": lambda w, d: w.tool_call("web.search", args_digest=d),
    "blob_digest": lambda w, d: w.kv_save(d),
    "call_hash": lambda w, d: w.tool_result(0, d, 0),
    "candidate_hash": lambda w, d: w.oversight_ack(0, d, 0, bytes(16)),
    "config_digest": lambda w, d: w.model_load(bytes(32), d),
    "loop_call_hash": lambda w, d: w.guard_tool_loop_limit(8, call_seq=0, call_hash=d),
    "model_digest": lambda w, d: w.model_load(d, bytes(32)),
    "ref_hash": lambda w, d: w.incident_candidate(1, 2, ref_seq=0, ref_hash=d),
    "result_digest": lambda w, d: w.tool_result(0, bytes(32), 0, result_digest=d),
}

#: 48 is deliberate: it is A3's wider digest. TLV framing accepts 48 bytes;
#: a version-1 *field* does not. A wider digest is a new ``format_version``,
#: never a value smuggled into a v1 record.
WRONG_WIDTHS = [b"", bytes(16), bytes(31), bytes(33), bytes(48)]


@pytest.mark.parametrize("seam", sorted(WIDTH_SEAMS))
@pytest.mark.parametrize("bad", WRONG_WIDTHS, ids=lambda v: f"{len(v)}B")
def test_a_wrong_width_digest_is_refused_before_any_byte_is_written(tmp_path, seam, bad):
    path = tmp_path / "chain.pala"
    with PalaWriter(path) as writer:
        writer.genesis()
        before = path.stat().st_size
        with pytest.raises(ValueError):
            WIDTH_SEAMS[seam](writer, bad)
        assert path.stat().st_size == before


@pytest.mark.parametrize("seam", sorted(WIDTH_SEAMS))
def test_the_same_seam_accepts_the_pinned_32_byte_width(tmp_path, seam):
    """The control: the refusals above are about width, not about the call."""
    path = tmp_path / "chain.pala"
    with PalaWriter(path) as writer:
        writer.genesis()
        before = path.stat().st_size
        WIDTH_SEAMS[seam](writer, bytes(32))
        assert path.stat().st_size > before
