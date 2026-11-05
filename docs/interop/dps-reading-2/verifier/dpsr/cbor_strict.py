"""A strict CBOR reader of its own (anchoring 0.2.0, "Strict CBOR"): it refuses an indefinite length, an integer or
a length not in its shortest form, items nested deeper than 16 levels, a map key named twice, a tag other than 18,
a float or a simple value, and bytes after the item. One exception, recorded as A13: null (0xf6) is read, because a
receipt's payload is detached and RFC 9052 writes a detached payload as nil."""


class CborError(ValueError):
    pass


class Tag:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __eq__(self, o):
        return isinstance(o, Tag) and o.tag == self.tag and o.value == self.value

    def __repr__(self):
        return "Tag(%d, %r)" % (self.tag, self.value)


MAX_DEPTH = 16


def _arg(b, i, ai):
    if ai < 24:
        return ai, i
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if i + n > len(b):
            raise CborError("truncated")
        v = int.from_bytes(b[i:i + n], "big")
        lo = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]
        if v < lo:
            raise CborError("an integer or length not in its shortest form")
        return v, i + n
    if ai == 31:
        raise CborError("an indefinite length")
    raise CborError("reserved additional information %d" % ai)


def _item(b, i, depth):
    if depth > MAX_DEPTH:
        raise CborError("items nested deeper than 16 levels")
    if i >= len(b):
        raise CborError("truncated")
    ib = b[i]
    i += 1
    mt, ai = ib >> 5, ib & 0x1f
    if mt == 7:
        if ai == 22:
            return None, i
        if ai in (25, 26, 27):
            raise CborError("a float")
        raise CborError("a simple value")
    v, i = _arg(b, i, ai)
    if mt == 0:
        return v, i
    if mt == 1:
        return -1 - v, i
    if mt in (2, 3):
        if i + v > len(b):
            raise CborError("truncated")
        s = bytes(b[i:i + v])
        i += v
        if mt == 3:
            try:
                return s.decode("utf-8"), i
            except UnicodeDecodeError:
                raise CborError("a text string that is not UTF-8")
        return s, i
    if mt == 4:
        out = []
        for _ in range(v):
            x, i = _item(b, i, depth + 1)
            out.append(x)
        return out, i
    if mt == 5:
        out = {}
        seen = set()
        for _ in range(v):
            k, i = _item(b, i, depth + 1)
            if isinstance(k, (list, dict, Tag)):
                raise CborError("a map key that is not an integer or a string")
            kk = (type(k).__name__, k)
            if kk in seen:
                raise CborError("a map key named twice")
            seen.add(kk)
            x, i = _item(b, i, depth + 1)
            out[k] = x
        return out, i
    if mt == 6:
        if v != 18:
            raise CborError("a tag other than 18 (%d)" % v)
        x, i = _item(b, i, depth + 1)
        return Tag(v, x), i
    raise CborError("unknown major type")


def loads(b):
    x, i = _item(bytes(b), 0, 1)
    if i != len(b):
        raise CborError("bytes after the item")
    return x


def _head(mt, n):
    if n < 24:
        return bytes([(mt << 5) | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < (1 << (8 * size)):
            return bytes([(mt << 5) | ai]) + n.to_bytes(size, "big")
    raise ValueError("too long")


def enc_bstr(b):
    return _head(2, len(b)) + b


def enc_tstr(s):
    e = s.encode("utf-8")
    return _head(3, len(e)) + e


def sig_structure(protected_bytes, payload, external_aad=b""):
    """Sig_structure = ["Signature1", body_protected, external_aad, payload] (RFC 9052 4.4), every length by
    CBOR's full rule."""
    return _head(4, 4) + enc_tstr("Signature1") + enc_bstr(protected_bytes) + enc_bstr(external_aad) + enc_bstr(payload)


def to_plain(x):
    """A comparable form, used to set this reader against cbor2 (V19)."""
    if isinstance(x, Tag):
        return ("tag", x.tag, to_plain(x.value))
    if isinstance(x, list):
        return ("list", tuple(to_plain(y) for y in x))
    if isinstance(x, dict):
        return ("map", tuple(sorted(((repr(type(k)), repr(k)), to_plain(v)) for k, v in x.items())))
    return (type(x).__name__, x)
