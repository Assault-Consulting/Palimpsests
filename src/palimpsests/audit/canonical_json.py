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
  is exponential. A number is an IEEE 754 double — an integer beyond
  2**53 is written as the double nearest to it, as every JSON reader
  built on doubles would have read it. NaN and the infinities have no
  form and are refused.
- **Object keys** are sorted by UTF-16 code unit, not by code point: the
  two orders differ for a key outside the Basic Multilingual Plane.
- **Strings** are written as they are, with ``"`` and ``\\`` escaped, the
  five short escapes for U+0008–U+000D, and ``\\u00xx`` in lowercase for
  the other control characters. A lone surrogate is refused.
- No whitespace; UTF-8.

Stdlib only.
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from decimal import Decimal

__all__ = ["canonical_json"]

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


def _write(value: object, out: list[str]) -> None:
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
            _write(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_json(value: object) -> bytes:
    """``value`` in the RFC 8785 canonical form, as UTF-8 bytes.

    ``value`` is a JSON value as Python holds one: ``None``, ``bool``,
    ``int``, ``float``, ``str``, a list or tuple, or a mapping with
    string keys. Anything else raises ``TypeError``; a value that has no
    canonical form (NaN, an infinity, a lone surrogate) raises
    ``ValueError``.
    """
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")
