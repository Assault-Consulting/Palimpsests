"""A small CBOR codec, written from RFC 8949 for this run.

Only what the task needs: unsigned and negative integers, byte and text
strings, arrays, maps and tags, all definite-length. Indefinite-length
items, floats and simple values other than the three constants are
rejected rather than guessed at -- a Signed Statement that used them
would be a finding, not a thing to silently accept.

Two properties matter here beyond "can it parse":

  * The decoder is strict. It reports the additional-information form
    each head was written in, so the caller can ask whether the message
    was encoded in the deterministic form of RFC 8949 section 4.2.1
    rather than merely being well-formed.
  * The encoder emits only that deterministic form: shortest-form heads,
    definite lengths, and map keys sorted by their encoded bytes.

Written without reference to any COSE or CBOR library.
"""


class CBORError(ValueError):
    """Malformed, ambiguous, or non-deterministically encoded CBOR."""


class Tagged:
    """A CBOR tag (major type 6) and the item it encloses."""

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __repr__(self):
        return f"Tagged({self.tag}, {self.value!r})"

    def __eq__(self, other):
        return (
            isinstance(other, Tagged)
            and self.tag == other.tag
            and self.value == other.value
        )


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


class _Decoder:
    def __init__(self, data, require_deterministic=False):
        self.data = data
        self.pos = 0
        self.require_deterministic = require_deterministic
        # Every non-shortest head we saw, as (offset, major, argument).
        self.non_shortest_heads = []

    def _take(self, n):
        if self.pos + n > len(self.data):
            raise CBORError(
                f"truncated: wanted {n} bytes at offset {self.pos}, "
                f"only {len(self.data) - self.pos} remain"
            )
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def _head(self):
        """Read one head byte plus its argument. Returns (major, argument)."""
        offset = self.pos
        initial = self._take(1)[0]
        major = initial >> 5
        info = initial & 0x1F

        if info < 24:
            return major, info
        if info == 24:
            arg = self._take(1)[0]
            shortest = arg >= 24
        elif info == 25:
            arg = int.from_bytes(self._take(2), "big")
            shortest = arg > 0xFF
        elif info == 26:
            arg = int.from_bytes(self._take(4), "big")
            shortest = arg > 0xFFFF
        elif info == 27:
            arg = int.from_bytes(self._take(8), "big")
            shortest = arg > 0xFFFFFFFF
        elif info == 31:
            raise CBORError(
                f"indefinite-length item at offset {offset} (major {major}); "
                "not accepted by this verifier"
            )
        else:
            raise CBORError(
                f"reserved additional information {info} at offset {offset}"
            )

        if not shortest:
            self.non_shortest_heads.append((offset, major, arg))
            if self.require_deterministic:
                raise CBORError(
                    f"non-shortest-form head at offset {offset}: major {major}, "
                    f"argument {arg} encoded in {info - 23} extra byte(s) "
                    "(RFC 8949 section 4.2.1)"
                )
        return major, arg

    def decode_item(self):
        major, arg = self._head()

        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self._take(arg)
        if major == 3:
            raw = self._take(arg)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError(f"invalid UTF-8 in text string: {exc}") from exc
        if major == 4:
            return [self.decode_item() for _ in range(arg)]
        if major == 5:
            return self._decode_map(arg)
        if major == 6:
            return Tagged(arg, self.decode_item())
        if major == 7:
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg == 22:
                return None
            raise CBORError(
                f"unsupported simple value or float (major 7, argument {arg})"
            )
        raise CBORError(f"unreachable major type {major}")

    def _decode_map(self, count):
        out = {}
        previous_key_bytes = None
        for _ in range(count):
            key_start = self.pos
            key = self.decode_item()
            key_bytes = self.data[key_start : self.pos]

            if isinstance(key, (bytes, bytearray)):
                hashable = ("bytes", bytes(key))
            elif isinstance(key, (int, str, bool)) or key is None:
                hashable = key
            else:
                raise CBORError(f"unhashable map key of type {type(key).__name__}")

            if hashable in out:
                raise CBORError(f"duplicate map key {key!r} (RFC 8949 section 5.6)")

            if previous_key_bytes is not None and key_bytes <= previous_key_bytes:
                message = (
                    f"map keys not in deterministic order at offset {key_start}: "
                    f"{key_bytes.hex()} does not sort after "
                    f"{previous_key_bytes.hex()} (RFC 8949 section 4.2.1)"
                )
                if self.require_deterministic:
                    raise CBORError(message)
                self.non_shortest_heads.append((key_start, 5, message))
            previous_key_bytes = key_bytes

            out[hashable] = self.decode_item()
        return out


def loads(data, require_deterministic=False, allow_trailing=False):
    """Decode one CBOR item from ``data``.

    Returns ``(value, decoder)``; the decoder carries ``pos`` (bytes
    consumed) and ``non_shortest_heads`` for the determinism report.
    """
    decoder = _Decoder(data, require_deterministic=require_deterministic)
    value = decoder.decode_item()
    if not allow_trailing and decoder.pos != len(data):
        raise CBORError(
            f"{len(data) - decoder.pos} trailing byte(s) after the top-level item"
        )
    return value, decoder


# --------------------------------------------------------------------------
# Encoding (deterministic, RFC 8949 section 4.2.1)
# --------------------------------------------------------------------------


def _head(major, arg):
    if arg < 0:
        raise CBORError("negative argument")
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 0x100:
        return bytes([(major << 5) | 24, arg])
    if arg < 0x10000:
        return bytes([(major << 5) | 25]) + arg.to_bytes(2, "big")
    if arg < 0x100000000:
        return bytes([(major << 5) | 26]) + arg.to_bytes(4, "big")
    if arg < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + arg.to_bytes(8, "big")
    raise CBORError("argument too large for a CBOR head")


def dumps(value):
    """Encode ``value`` in the deterministic form of RFC 8949 section 4.2.1."""
    if isinstance(value, Tagged):
        return _head(6, value.tag) + dumps(value.value)
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(dumps(item) for item in value)
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            if isinstance(key, tuple) and len(key) == 2 and key[0] == "bytes":
                key = key[1]
            items.append((dumps(key), dumps(item)))
        # Deterministic map order: sort by the encoded key bytes.
        items.sort(key=lambda pair: pair[0])
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise CBORError(f"cannot encode {type(value).__name__}")
