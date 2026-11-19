# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A header field is read by its name, from the codec's field map.

The layout of the fixed header is stated once (``HEADER_FIELDS``) and a
contract test holds that map to the decoder. Eleven modules read single
fields without decoding the header, and each wrote the offsets out again:
``struct.unpack_from("<Q", hb, 12)``, ``hb[20:36]``, ``hb[11]`` — a second
statement of the layout that no test reached. A consumer of the bundle
raised it for one module; the pattern was in ten more.
"""
from __future__ import annotations

import pytest
import re
from palimpsests.audit import _header_fields
from palimpsests.audit._header_fields import field, offset, span
from palimpsests.audit.pala.codec import FIXED_HEADER_LEN, HEADER_FIELDS, Header
from pathlib import Path

SRC = Path(_header_fields.__file__).resolve().parent

#: The modules that read header fields in place and now take every one from
#: the map. The reader and the incremental verifier keep their own measured
#: in-place paths and are not on this list.
CONVERTED = [
    "bootstats.py", "timehealth.py", "export.py", "segment_set.py", "tailing.py",
    "pala_writer.py", "pala/proofs.py", "pala/checkpoints.py", "pala/segments.py",
    "pala/bundle.py",
]

HEADER = Header(
    record_type=0x0012, seq=0x0102030405060708, boot_id=bytes(range(16)),
    prev_hash=bytes(range(32, 64)), assurance_tier=1, time_trust=3,
    span_id=bytes(range(64, 80)), parent_span_id=bytes(range(80, 96)),
    monotonic_ns=123456789012345, wall_clock_ns=-42, key_id=9, body_len=77,
    body_digest=bytes(range(96, 128)),
)


@pytest.mark.parametrize("f", HEADER_FIELDS, ids=lambda f: f.name)
def test_every_field_reads_what_the_decoder_decodes(f):
    encoded = HEADER.encode()
    decoded = Header.decode(encoded)
    value = field(f.name)(encoded)
    assert encoded[span(f.name)] == encoded[f.offset:f.offset + f.length]
    assert offset(f.name) == f.offset
    if hasattr(decoded, f.name):
        assert value == getattr(decoded, f.name)
    # and at a base other than zero: a header inside a larger buffer
    padded = b"\xee" * 37 + encoded
    assert field(f.name)(padded, 37) == value
    assert padded[span(f.name, 37)] == encoded[span(f.name)]


def test_the_map_covers_the_fixed_header_without_a_gap():
    end = 0
    for f in HEADER_FIELDS:
        assert f.offset == end
        end += f.length
    assert end == FIXED_HEADER_LEN
    with pytest.raises(KeyError):
        field("no_such_field")


#: A header offset written out: an integer position handed to unpack_from on
#: a header, or a header sliced or indexed by number.
LITERAL = re.compile(
    r"""unpack_from\(\s*["']<[A-Za-z0-9]+["']\s*,\s*\w+\s*,\s*(?:\w+\s*\+\s*)?\d+\s*\)"""
    r"""|\b(?:hb|header|fixed|headers\[\w+\])\[\s*\d+\s*(?::\s*\d+\s*)?\]"""
)


@pytest.mark.parametrize("module", CONVERTED)
def test_no_converted_module_writes_a_header_offset_out_again(module):
    text = (SRC / module).read_text(encoding="utf-8")
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    found = [m.group(0) for m in LITERAL.finditer(code)
             if not m.group(0).endswith("[:4]")]  # the magic, compared with MAGIC
    assert found == [], f"{module}: read these through _header_fields: {found}"


def test_the_scan_would_see_what_was_there():
    for old in ('(seq,) = struct.unpack_from("<Q", hb, 12)', "boot_id = bytes(hb[20:36])",
                "trust = hb[11]", '(blen,) = struct.unpack_from("<I", buf, off + 120)',
                "fixed[36:68].hex() == last", "body_digest_of(body) == hb[124:156]"):
        assert LITERAL.search(old), old
