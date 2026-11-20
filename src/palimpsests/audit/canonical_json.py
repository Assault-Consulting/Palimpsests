# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""RFC 8785 — the JSON Canonicalization Scheme (JCS).

The one canonical form this package digests JSON values in: tool
arguments and results (``EVT_PAYLOAD_DIGEST``) and the engine's
configuration (``ORIGIN_CONFIG_DIGEST``). A digest is only evidence if
someone else can compute it again from the value, in another language,
without this package — so the form is a published standard and not what
one library's serializer happens to print.

What the standard fixes, and where a serializer's defaults differ:

- **Numbers** are written as ECMAScript writes them (ECMA-262 7.1.12.1):
  ``1.0`` is ``1``, ``1e21`` is ``1e+21``, ``0.000001`` stays, ``1e-7``
  is exponential. A number is an IEEE 754 double. NaN and the
  infinities have no form and are refused — and so is an integer beyond
  ±(2**53 - 1): as a double it is also its neighbours, and a digest that
  stands for two values binds neither (RFC 7493 §2.2).
- **An object that repeats a key** has no form: it reads two ways
  (RFC 7493 §2.3). A repeated key exists only in the text, so it is
  :func:`loads` that keeps it in sight.
- **Object keys** are sorted by UTF-16 code unit, not by code point: the
  two orders differ for a key outside the Basic Multilingual Plane.
- **Strings** are written as they are, with ``"`` and ``\\`` escaped, the
  five short escapes for U+0008–U+000D, and ``\\u00xx`` in lowercase for
  the other control characters. A lone surrogate is refused.
- No whitespace; UTF-8.

One limit the standard leaves to its users, set here: **a value nested
deeper than** :data:`MAX_DEPTH` **containers has no canonical form.**
Canonicalizers disagree past their own limits, and a digest only one
implementation can compute is not evidence; and a value from outside —
a tool's output — must not be able to exhaust the interpreter's stack.

Stdlib only.
"""
from __future__ import annotations

import json
import math
from collections.abc import Mapping
from decimal import Decimal

__all__ = ["MAX_DEPTH", "MAX_SAFE_INTEGER", "DuplicateKeys", "canonical_json",
           "has_duplicate_keys", "loads"]

#: The largest integer whose neighbours are also doubles: 2**53 - 1. An
#: integer beyond it, either way, has no canonical form here.
MAX_SAFE_INTEGER = 2**53 - 1

#: The deepest nesting of arrays and objects that has a canonical form
#: here: a value inside 128 containers is digested, one inside 129 is not.
MAX_DEPTH = 128

class DuplicateKeys(dict):
    """An object whose JSON text gave some key more than once.

    Which value such an object has depends on the reader: most parsers
    keep the last, some the first, some refuse. So the same text is two
    values, and a digest of either would claim more than anyone can check.
    :func:`loads` marks the object instead of silently choosing; it still
    holds the last value for each key, as ``json.loads`` would give, so
    code that only *uses* the object behaves as before — and
    :func:`canonical_json` refuses to give it a form.
    """

    __slots__ = ()


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    obj = dict(pairs)
    return DuplicateKeys(obj) if len(obj) != len(pairs) else obj


def loads(text: str | bytes | bytearray) -> object:
    """``json.loads`` that does not lose a repeated key.

    An object that repeats a key comes back as a :class:`DuplicateKeys`.
    Everything else is as ``json.loads`` gives it, the exceptions included
    (``ValueError`` for text that is not JSON; ``RecursionError`` for text
    nested past the parser's own limit, which differs between interpreters).

    Use it wherever JSON from outside is read and may be digested: a
    repeated key is visible only in the text, and is gone once an ordinary
    parser has returned.
    """
    return json.loads(text, object_pairs_hook=_pairs)


def has_duplicate_keys(value: object) -> bool:
    """Whether a value read by :func:`loads` holds a repeated key anywhere."""
    todo = [value]
    while todo:
        item = todo.pop()
        if isinstance(item, DuplicateKeys):
            return True
        if isinstance(item, Mapping):
            todo.extend(item.values())
        elif isinstance(item, (list, tuple)):
            todo.extend(item)
    return False


_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
          0x22: '\\"', 0x5C: "\\\\"}


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code in _SHORT:
            out.append(_SHORT[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("a lone surrogate has no canonical JSON form (RFC 8785 §3.2.2.2)")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: int | float) -> str:
    """ECMA-262 Number::toString of the double nearest to ``value``."""
    if isinstance(value, int) and not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        # RFC 8785 writes every number as a double, so 2**53 and 2**53 + 1
        # would be the same bytes and the digest would no longer say which
        # was meant. RFC 7493 (I-JSON), which RFC 8785 takes its input
        # from, says not to send such a number; a digest of one is refused
        # rather than made to stand for its neighbours too.
        raise ValueError("an integer beyond ±(2**53 - 1) has no canonical JSON form "
                         "here: as a double it is also its neighbours (RFC 7493 §2.2)")
    try:
        x = float(value)
    except OverflowError as e:
        raise ValueError("a number beyond the range of an IEEE 754 double has no "
                         "canonical JSON form (RFC 8785 §3.2.2.3)") from e
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity have no canonical JSON form (RFC 8785 §3.2.2.3)")
    if x == 0:
        return "0"  # minus zero too
    sign = "-" if x < 0 else ""
    # repr() gives the shortest digits that read back to the same double —
    # the digits ECMAScript requires. Only the layout around them differs.
    _s, digit_tuple, exponent = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0") or "0"
    exponent += len(digit_tuple) - len(digits)
    k = len(digits)
    n = k + exponent  # the value is 0.digits × 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _write(value: object, out: list[str], depth: int = 0) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, (int, float)):
        out.append(_number(value))
    elif isinstance(value, DuplicateKeys):
        raise ValueError("an object whose JSON text gave a key more than once has no "
                         "canonical JSON form: it reads two ways (RFC 7493 §2.3)")
    elif isinstance(value, (Mapping, list, tuple)) and depth >= MAX_DEPTH:
        raise ValueError(f"a value nested deeper than {MAX_DEPTH} arrays and objects "
                         "has no canonical JSON form here")
    elif isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"an object key must be a string, not {type(key).__name__}")
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be",
                                                                    "surrogatepass"))):
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _write(value[key], out, depth + 1)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out, depth + 1)
        out.append("]")
    else:
        raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_json(value: object) -> bytes:
    """``value`` in the RFC 8785 canonical form, as UTF-8 bytes.

    ``value`` is a JSON value as Python holds one: ``None``, ``bool``,
    ``int``, ``float``, ``str``, a list or tuple, or a mapping with
    string keys. Anything else raises ``TypeError``; a value that has no
    canonical form (NaN, an infinity, a lone surrogate, nesting deeper
    than :data:`MAX_DEPTH`) raises ``ValueError``.
    """
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")
