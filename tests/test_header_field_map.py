# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The header field map, checked against real encoded bytes.

A field map is a second statement of the layout, and a second statement is
worth nothing unless something compares it to the first. So these tests do
not restate §2.1: they encode a header with distinctive values and confirm
that slicing the bytes by the map recovers exactly what was packed.

That way the map cannot be right about the specification and wrong about the
encoder — the failure mode that matters, because a hex view highlights what
the encoder produced, not what the prose says it should have.
"""
from __future__ import annotations

import pytest
import struct
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    HEADER_FIELDS,
    MAGIC,
    RT_EVENT,
    TIER_B,
    TIME_NTP_SYNCED,
    Header,
    MalformedRecord,
    tlv_region,
)

#: Distinctive values: every field differs from every other, so a map that
#: swapped two of them fails rather than passing by coincidence.
_SAMPLE = Header(
    record_type=RT_EVENT,
    seq=0x1122334455667788,
    boot_id=bytes(range(0x10, 0x20)),
    prev_hash=bytes(range(0x20, 0x40)),
    assurance_tier=TIER_B,
    time_trust=TIME_NTP_SYNCED,
    span_id=bytes(range(0x40, 0x50)),
    parent_span_id=bytes(range(0x50, 0x60)),
    monotonic_ns=0x0102030405060708,
    wall_clock_ns=-42,
    key_id=0xDEADBEEF,
    body_len=1234,
    body_digest=bytes(range(0x60, 0x80)),
)

_EXPECTED = {
    "magic": MAGIC,
    "format_version": 1,
    "header_len": FIXED_HEADER_LEN,
    "record_type": RT_EVENT,
    "assurance_tier": TIER_B,
    "time_trust": TIME_NTP_SYNCED,
    "seq": _SAMPLE.seq,
    "boot_id": _SAMPLE.boot_id,
    "prev_hash": _SAMPLE.prev_hash,
    "span_id": _SAMPLE.span_id,
    "parent_span_id": _SAMPLE.parent_span_id,
    "monotonic_ns": _SAMPLE.monotonic_ns,
    "wall_clock_ns": _SAMPLE.wall_clock_ns,
    "key_id": _SAMPLE.key_id,
    "body_len": _SAMPLE.body_len,
    "body_digest": _SAMPLE.body_digest,
}


@pytest.mark.parametrize("field", HEADER_FIELDS, ids=lambda f: f.name)
def test_each_field_slices_to_what_was_encoded(field) -> None:
    """The map against the encoder, field by field.

    This is the whole point of the map existing: a consumer slices these
    bytes and highlights them, so the slice has to land on the value.
    """
    encoded = _SAMPLE.encode()
    chunk = encoded[field.offset : field.offset + field.length]
    assert len(chunk) == field.length
    (value,) = struct.unpack("<" + field.format, chunk)
    assert value == _EXPECTED[field.name]


def test_the_map_covers_the_fixed_header_exactly() -> None:
    """No gap and no overlap.

    A gap would leave bytes a hex view cannot label; an overlap would label
    one byte twice and make the display disagree with itself.
    """
    offset = 0
    for field in HEADER_FIELDS:
        assert field.offset == offset, f"{field.name} does not follow its predecessor"
        offset += field.length
    assert offset == FIXED_HEADER_LEN


def test_the_map_names_every_field_once() -> None:
    names = [f.name for f in HEADER_FIELDS]
    assert len(names) == len(set(names))


def test_the_map_is_immutable() -> None:
    """A consumer must not be able to edit the layout it was handed.

    HEADER_FIELDS is module-level and shared; a mutable entry would let one
    caller's tweak reach every other caller in the process.
    """
    with pytest.raises((AttributeError, TypeError)):
        HEADER_FIELDS[0].offset = 99  # type: ignore[misc]


# --- the TLV area is a function of the record, not a constant ---------------


def test_tlv_region_is_empty_when_there_are_no_tlvs() -> None:
    offset, length = tlv_region(FIXED_HEADER_LEN)
    assert (offset, length) == (FIXED_HEADER_LEN, 0)


def test_tlv_region_matches_the_bytes_a_header_actually_carries() -> None:
    """Checked against a real encoding rather than arithmetic on its own."""
    with_tlvs = Header(
        record_type=RT_EVENT,
        seq=1,
        boot_id=bytes(16),
        prev_hash=bytes(32),
        tlvs=[(0x0001, b"engine.native"), (0x0002, bytes(32))],
    )
    encoded = with_tlvs.encode()
    header_len = struct.unpack_from("<H", encoded, 6)[0]

    offset, length = tlv_region(header_len)
    assert offset + length == header_len
    assert encoded[offset : offset + length] == encoded[FIXED_HEADER_LEN:header_len]
    assert length > 0


@pytest.mark.parametrize("short", [0, 1, FIXED_HEADER_LEN - 1])
def test_a_header_len_below_the_fixed_part_is_refused(short: int) -> None:
    """Same refusal the decoder gives.

    A caller passing a value read out of a damaged record should not get a
    negative length back, because that renders as an empty highlight — a
    display that quietly shows nothing wrong.
    """
    with pytest.raises(MalformedRecord):
        tlv_region(short)
