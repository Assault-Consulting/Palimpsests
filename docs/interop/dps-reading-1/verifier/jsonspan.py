"""Locate a member's string value inside JSON text, for the replacement rule (signatures 0.2.0,
'Where the signature sits inside what it signs'): the value between its quotes is replaced
by as many 'A' as the value has characters, whatever the writing."""
import json

_dec = json.JSONDecoder()

def _ws(s, i):
    while i < len(s) and s[i] in " \t\n\r":
        i += 1
    return i

def _skip(s, i):
    """Skip one JSON value starting at i; return end index."""
    i = _ws(s, i)
    c = s[i]
    if c == '{':
        i += 1; i = _ws(s, i)
        if s[i] == '}':
            return i + 1
        while True:
            i = _ws(s, i)
            _, i = _dec.raw_decode(s, i)  # key
            i = _ws(s, i); assert s[i] == ':'; i += 1
            i = _skip(s, i); i = _ws(s, i)
            if s[i] == ',':
                i += 1; continue
            assert s[i] == '}'; return i + 1
    if c == '[':
        i += 1; i = _ws(s, i)
        if s[i] == ']':
            return i + 1
        while True:
            i = _skip(s, i); i = _ws(s, i)
            if s[i] == ',':
                i += 1; continue
            assert s[i] == ']'; return i + 1
    _, j = _dec.raw_decode(s, i)
    return j

def member_spans(s, i, path):
    """Return (start, end) spans of the string value at the member path (list of keys)
    inside the object starting at i. All spans if a key repeats (the strict reader
    refuses such a document anyway)."""
    i = _ws(s, i)
    if s[i] != '{':
        return []
    out = []
    i += 1; i = _ws(s, i)
    if s[i] == '}':
        return out
    while True:
        i = _ws(s, i)
        key, i = _dec.raw_decode(s, i)
        i = _ws(s, i); i += 1; i = _ws(s, i)
        start = i
        end = _skip(s, i)
        if key == path[0]:
            if len(path) == 1:
                if s[start] == '"':
                    out.append((start, end))
            else:
                out.extend(member_spans(s, start, path[1:]))
        i = _ws(s, end)
        if s[i] == ',':
            i += 1; continue
        return out

def replace_value_with_A(text, path):
    """text: the document as text. Returns the text with the string value at path replaced
    by 'A' times its decoded length, or None if there is no such member."""
    spans = member_spans(text, 0, path)
    if len(spans) != 1:
        return None
    a, b = spans[0]
    value = json.loads(text[a:b])
    return text[:a + 1] + "A" * len(value) + text[b - 1:]

def replace_written_with_A(text, path):
    spans = member_spans(text, 0, path)
    if len(spans) != 1:
        return None
    a, b = spans[0]
    return text[:a + 1] + "A" * (b - a - 2) + text[b - 1:]
