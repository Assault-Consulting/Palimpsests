"""Minimal CBOR (RFC 8949) decoder + deterministic encoder.

Written from RFC 8949 for the PALA-1 SCITT statement interop run.
No third-party CBOR library is used; the decoder tracks byte offsets so
the caller can recover exact slices (needed to reason about the
protected-header bstr and about non-minimal length heads).
"""


class CBORError(Exception):
    pass


# ---------------------------------------------------------------- decoding

def _head(data, off, strict):
    """Return (major_type, argument, new_offset, indefinite)."""
    if off >= len(data):
        raise CBORError("truncated: head past end of buffer at %d" % off)
    ib = data[off]
    mt = ib >> 5
    ai = ib & 0x1F
    off += 1

    if ai < 24:
        return mt, ai, off, False
    if ai == 31:
        return mt, None, off, True
    if ai in (28, 29, 30):
        raise CBORError("reserved additional information %d at %d" % (ai, off - 1))

    nbytes = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    if off + nbytes > len(data):
        raise CBORError("truncated: %d-byte argument at %d" % (nbytes, off))
    val = int.from_bytes(data[off:off + nbytes], "big")
    off += nbytes

    if strict:
        # RFC 8949 s4.2.1: preferred (shortest) serialisation of the argument.
        minimal = (
            (nbytes == 1 and val >= 24)
            or (nbytes == 2 and val > 0xFF)
            or (nbytes == 4 and val > 0xFFFF)
            or (nbytes == 8 and val > 0xFFFFFFFF)
        )
        if not minimal:
            raise CBORError(
                "non-minimal length head: argument %d encoded in %d bytes at %d"
                % (val, nbytes, off - nbytes - 1)
            )
    return mt, val, off, False


class Tagged:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return "Tagged(%d, %r)" % (self.tag, self.value)


class Map:
    """Order-preserving CBOR map; keeps the encoded key bytes for
    deterministic-order checks (RFC 8949 s4.2.1 is bytewise on encoded keys,
    which is not the same predicate as 'numerically ascending')."""

    __slots__ = ("pairs", "key_encodings")

    def __init__(self, pairs, key_encodings):
        self.pairs = pairs
        self.key_encodings = key_encodings

    def get(self, key, default=None):
        for k, v in self.pairs:
            if k == key:
                return v
        return default

    def __contains__(self, key):
        return any(k == key for k, _ in self.pairs)

    def keys(self):
        return [k for k, _ in self.pairs]

    def __len__(self):
        return len(self.pairs)

    def __repr__(self):
        return "Map(%r)" % (self.pairs,)


def _decode(data, off, strict):
    mt, arg, off, indef = _head(data, off, strict)

    if indef and strict:
        raise CBORError("indefinite-length item at %d (not deterministic)" % (off - 1))

    if mt == 0:
        return arg, off
    if mt == 1:
        return -1 - arg, off
    if mt in (2, 3):
        if indef:
            raise CBORError("indefinite-length string unsupported at %d" % off)
        if off + arg > len(data):
            raise CBORError("truncated string: want %d bytes at %d" % (arg, off))
        raw = data[off:off + arg]
        off += arg
        if mt == 2:
            return raw, off
        return raw.decode("utf-8"), off
    if mt == 4:
        if indef:
            raise CBORError("indefinite-length array unsupported at %d" % off)
        items = []
        for _ in range(arg):
            item, off = _decode(data, off, strict)
            items.append(item)
        return items, off
    if mt == 5:
        if indef:
            raise CBORError("indefinite-length map unsupported at %d" % off)
        pairs = []
        key_encodings = []
        for _ in range(arg):
            kstart = off
            key, off = _decode(data, off, strict)
            key_encodings.append(data[kstart:off])
            val, off = _decode(data, off, strict)
            pairs.append((key, val))
        return Map(pairs, key_encodings), off
    if mt == 6:
        inner, off = _decode(data, off, strict)
        return Tagged(arg, inner), off
    if mt == 7:
        if arg == 20:
            return False, off
        if arg == 21:
            return True, off
        if arg == 22:
            return None, off
        if arg == 23:
            return Ellipsis, off  # undefined
        raise CBORError("unsupported simple/float value %r at %d" % (arg, off))
    raise CBORError("unreachable major type %d" % mt)


def loads(data, strict=True, allow_trailing=False):
    value, off = _decode(data, 0, strict)
    if not allow_trailing and off != len(data):
        raise CBORError("trailing data: %d byte(s) after the top-level item"
                        % (len(data) - off))
    return value


# ---------------------------------------------------------------- encoding

def _enc_head(mt, arg):
    if arg < 24:
        return bytes([(mt << 5) | arg])
    if arg < 0x100:
        return bytes([(mt << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(mt << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([(mt << 5) | 26]) + arg.to_bytes(4, "big")
    return bytes([(mt << 5) | 27]) + arg.to_bytes(8, "big")


def dumps(value):
    """Deterministic encoding (RFC 8949 s4.2.1), preferred serialisation.

    Map keys are emitted in the order given; call sort_keys_deterministic()
    first if you want s4.2.1 bytewise ordering imposed rather than checked.
    """
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _enc_head(0, value)
        return _enc_head(1, -1 - value)
    if isinstance(value, bytes):
        return _enc_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _enc_head(3, len(raw)) + raw
    if isinstance(value, list):
        return _enc_head(4, len(value)) + b"".join(dumps(v) for v in value)
    if isinstance(value, Tagged):
        return _enc_head(6, value.tag) + dumps(value.value)
    if isinstance(value, dict):
        items = list(value.items())
        return _enc_head(5, len(items)) + b"".join(
            dumps(k) + dumps(v) for k, v in items
        )
    if isinstance(value, Map):
        return _enc_head(5, len(value.pairs)) + b"".join(
            dumps(k) + dumps(v) for k, v in value.pairs
        )
    raise CBORError("cannot encode %r" % type(value))


def sort_keys_deterministic(d):
    """RFC 8949 s4.2.1: sort map entries by the bytewise lexicographic order
    of their ENCODED keys."""
    return dict(sorted(d.items(), key=lambda kv: dumps(kv[0])))
