"""Find the span of a string value at a path in JSON text, so the replacement by A acts on the
bytes as received and on the value's characters, not on the writing (signatures, the seal)."""
import json

_WS = " \t\r\n"


def _ws(s, i):
    while i < len(s) and s[i] in _WS:
        i += 1
    return i


def _string(s, i):
    j = i + 1
    while True:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        j += 1


def _value(s, i, path, want, found):
    i = _ws(s, i)
    c = s[i]
    if c == "{":
        i = _ws(s, i + 1)
        if s[i] == "}":
            return i + 1
        while True:
            i = _ws(s, i)
            ke = _string(s, i)
            key = json.loads(s[i:ke])
            i = _ws(s, ke)
            i += 1  # colon
            i = _ws(s, i)
            start = i
            i = _value(s, i, path + (key,), want, found)
            if path + (key,) == want:
                found.append((start, i))
            i = _ws(s, i)
            if s[i] == ",":
                i += 1
                continue
            return i + 1
    if c == "[":
        i = _ws(s, i + 1)
        if s[i] == "]":
            return i + 1
        k = 0
        while True:
            start = _ws(s, i)
            i = _value(s, start, path + (k,), want, found)
            if path + (k,) == want:
                found.append((start, i))
            i = _ws(s, i)
            k += 1
            if s[i] == ",":
                i += 1
                continue
            return i + 1
    if c == '"':
        return _string(s, i)
    j = i
    while j < len(s) and s[j] not in ",]}" + _WS:
        j += 1
    return j


def replace_string_value(text, path, ch="A"):
    """Return text with the string at path replaced by as many ch as the value has characters.
    Raises ValueError if not found exactly once."""
    found = []
    _value(text, 0, (), tuple(path), found)
    if len(found) != 1:
        raise ValueError("value at %r found %d times" % (path, len(found)))
    a, b = found[0]
    val = json.loads(text[a:b])
    if not isinstance(val, str):
        raise ValueError("not a string")
    return text[:a + 1] + ch * len(val) + text[b - 1:]
