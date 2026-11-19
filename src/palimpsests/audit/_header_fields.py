# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Reading one field of the fixed header, by its name.

The layout of the 156-byte header is stated once, in the codec's field
map (``HEADER_FIELDS``), and a contract test holds that map to the
decoder. A module that reads a field without decoding the whole header
takes the field's place from the map through this module — never from an
offset written out again beside the code that uses it, which is a second
statement of the layout that no test reaches.

``field(name)`` returns a reader ``(buffer, base=0) -> value``, built once
at import; calling it costs one ``unpack_from``.
"""
from __future__ import annotations

from collections.abc import Callable
from palimpsests.audit.pala.codec import HEADER_FIELDS
from struct import Struct

__all__ = ["field", "offset", "span"]

_BY_NAME = {f.name: f for f in HEADER_FIELDS}


def offset(name: str) -> int:
    """Where the field starts, from the start of the header."""
    return _BY_NAME[name].offset


def span(name: str, base: int = 0) -> slice:
    """The field's bytes as a slice of a buffer holding a header at ``base``."""
    f = _BY_NAME[name]
    return slice(base + f.offset, base + f.offset + f.length)


def field(name: str) -> Callable[..., object]:
    """A reader of one field: ``reader(buffer, base=0)``.

    An integer field is returned as an ``int``; a byte field (an id, a
    hash) as ``bytes``.
    """
    f = _BY_NAME[name]
    unpack = Struct("<" + f.format).unpack_from
    at = f.offset

    def read(buffer, base: int = 0):
        return unpack(buffer, base + at)[0]

    return read
