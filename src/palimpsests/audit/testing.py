# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Damaged chains, for the tests of whatever reads them.

A consumer has to show what it does with a chain that does not verify: a
broken link, a missing record, a body altered after writing. The writer
cannot produce one — that is its job — so a consumer's tests were left to
rewrite bytes by hand, at offsets copied from the specification, or to go
without the case.

Each function here takes the bytes of a well-formed chain and returns the
bytes of a damaged one. Each is one small, named defect, made through the
package's own layout (:data:`~palimpsests.audit.reader.HEADER_FIELDS`), and
:data:`DAMAGE` says for each what the reader reports — so a test is written
against the expectation published here and fails, visibly, if a release
changes it::

    from palimpsests.audit.testing import DAMAGE

    @pytest.mark.parametrize("kind", DAMAGE)
    def test_my_screen_on_damage(kind, chain_bytes):
        damage = DAMAGE[kind]
        with AuditReader.from_bytes(damage.apply(chain_bytes)) as reader:
            assert reader.verify().diagnosis.pattern == damage.pattern
            ...

Test support: nothing here is used by the package at run time, and nothing
here can make a damaged chain verify. Making damage is not a secret — every
function is a few lines over the published layout; what the format gives is
that the damage is found.

The source chain needs at least four records for every function to apply,
and at least one record with a body for :func:`alter_body`.
"""
from __future__ import annotations

import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala.codec import HEADER_FIELDS
from types import MappingProxyType

__all__ = [
    "DAMAGE",
    "Damage",
    "NOT_A_CONTAINER",
    "alter_body",
    "break_link",
    "cut_mid_record",
    "drop_first_records",
    "drop_last_records",
    "not_a_container",
    "remove_record",
    "violate_must",
]

#: Bytes that were never a chain: no record begins with them.
NOT_A_CONTAINER = b"this is a plain text file; it was never an audit chain.\n" * 4

_FIELD = {f.name: f for f in HEADER_FIELDS}


def _records(data: bytes) -> list[tuple[bytes, bytes]]:
    records = list(iter_records(data))
    if len(records) < 4:
        raise ValueError(
            f"the source chain has {len(records)} record(s); these builders need "
            "a well-formed chain of at least four"
        )
    return records


def _join(records: list[tuple[bytes, bytes]]) -> bytes:
    return b"".join(header + body for header, body in records)


def _index(records: list[tuple[bytes, bytes]], seq: int | None, default: int) -> int:
    """The position of the record with ``seq`` (or the default position)."""
    if seq is None:
        return default % len(records)
    field = _FIELD["seq"]
    for i, (header, _body) in enumerate(records):
        if struct.unpack_from("<Q", header, field.offset)[0] == seq:
            return i
    raise ValueError(f"the source chain has no record with seq {seq}")


def alter_body(data: bytes, *, seq: int | None = None) -> bytes:
    """One bit of one body flipped; every header is untouched.

    The header chain still verifies — ``chain_ok`` is True and there is no
    diagnosis — and the altered record's body no longer matches the digest
    its header binds: ``container_check().body_digest_mismatches`` names its
    seq, and ``is_consistent()`` is False. The defect a check of headers
    alone does not see.

    ``seq`` picks the record; by default the first one that has a body.
    """
    records = _records(data)
    if seq is None:
        i = next((k for k, (_h, body) in enumerate(records) if body), None)
        if i is None:
            raise ValueError("no record in the source chain has a body")
    else:
        i = _index(records, seq, 0)
        if not records[i][1]:
            raise ValueError(f"the record with seq {seq} has no body")
    header, body = records[i]
    records[i] = (header, body[:-1] + bytes([body[-1] ^ 0x01]))
    return _join(records)


def break_link(data: bytes, *, seq: int | None = None) -> bytes:
    """One bit of one record's ``prev_hash`` flipped: ``chain_break``.

    The record no longer names its predecessor — and, its header having
    changed, its own hash has changed too, so the record after it no longer
    names *it*: the reader reports a break at this seq and at the next
    (``chain.breaks``), and diagnoses the first. ``seq`` picks the record;
    by default the third.
    """
    records = _records(data)
    i = _index(records, seq, 2)
    if i == 0:
        raise ValueError("the first record has no predecessor to break from")
    header, body = records[i]
    at = _FIELD["prev_hash"].offset
    records[i] = (header[:at] + bytes([header[at] ^ 0x01]) + header[at + 1:], body)
    return _join(records)


def violate_must(data: bytes) -> bytes:
    """The last record's ``time_trust`` set to a value the format does not
    define: ``record_violation``, code ``time_trust_undefined``.

    The last record, so that no later link is broken as well and the
    violation is the only finding.
    """
    records = _records(data)
    header, body = records[-1]
    at = _FIELD["time_trust"].offset
    records[-1] = (header[:at] + b"\x09" + header[at + 1:], body)
    return _join(records)


def remove_record(data: bytes, *, seq: int | None = None) -> bytes:
    """One record taken out of the middle: ``seq_gap``.

    ``seq`` picks the record; by default the third. Not the first (that is
    :func:`drop_first_records`) and not the last (:func:`drop_last_records`).
    """
    records = _records(data)
    i = _index(records, seq, 2)
    if i in (0, len(records) - 1):
        raise ValueError("remove a record from the middle; see drop_first/last_records")
    del records[i]
    return _join(records)


def drop_first_records(data: bytes, *, count: int = 1) -> bytes:
    """The first ``count`` records removed: ``prefix_absent``.

    The file begins after the beginning of the chain, and nothing in it
    declares that it should.
    """
    records = _records(data)
    if not 0 < count < len(records):
        raise ValueError(f"count must be between 1 and {len(records) - 1}")
    return _join(records[count:])


def drop_last_records(data: bytes, *, count: int = 1) -> bytes:
    """The last ``count`` records removed, at a record boundary.

    **Not detectable without an anchor**: what is left is a well-formed,
    consistent chain, and the reader gives no diagnosis. Read against the
    head the chain had before, the anchor is missed —
    ``complete_to_anchor`` False, diagnosis ``replaced_or_rolled_back``.
    This is the case an anchor exists for.
    """
    records = _records(data)
    if not 0 < count < len(records):
        raise ValueError(f"count must be between 1 and {len(records) - 1}")
    return _join(records[:-count])


def cut_mid_record(data: bytes, *, missing: int = 7) -> bytes:
    """The last ``missing`` bytes removed, cutting the last record short:
    ``truncated_tail``, and a container that is not well-formed.

    What a crash in the middle of a write leaves.
    """
    records = _records(data)
    last = len(records[-1][0]) + len(records[-1][1])
    if not 0 < missing < last:
        raise ValueError(f"missing must be between 1 and {last - 1}")
    return data[:-missing]


def not_a_container(_data: bytes = b"") -> bytes:
    """Bytes that were never a chain: ``not_a_container``.

    Takes and ignores a source so it can stand in :data:`DAMAGE` beside the
    others.
    """
    return NOT_A_CONTAINER


@dataclass(frozen=True)
class Damage:
    """One kind of damage and what the reader says about it, with no anchor.

    ``pattern`` is ``Verification.diagnosis.pattern`` (None: no diagnosis);
    ``code`` is ``diagnosis.code``; ``consistent`` is
    ``AuditReader.is_consistent()``.
    """

    apply: Callable[[bytes], bytes]
    pattern: str | None
    consistent: bool
    code: str | None = None


#: Every builder, by name, with the reader's answer for its default call.
DAMAGE: Mapping[str, Damage] = MappingProxyType({
    "alter_body": Damage(alter_body, None, False),
    "break_link": Damage(break_link, "chain_break", False),
    "violate_must": Damage(violate_must, "record_violation", False, "time_trust_undefined"),
    "remove_record": Damage(remove_record, "seq_gap", False),
    "drop_first_records": Damage(drop_first_records, "prefix_absent", False),
    "drop_last_records": Damage(drop_last_records, None, True),
    "cut_mid_record": Damage(cut_mid_record, "truncated_tail", False),
    "not_a_container": Damage(not_a_container, "not_a_container", False),
})
