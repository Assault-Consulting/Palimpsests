"""Shared pieces, written from the texts: strict JSON reading (action binding item 8, signatures
"a document ... that names a member twice ... is not read"), RFC 3339 instants, the shared
signed-bytes rule (anchoring 0.2.0 "Signed bytes (shared rule)"), JSON Pointer patches."""
import base64, hashlib, json, re
from fractions import Fraction
import datetime as _dt


class Unreadable(Exception):
    """A document that is not read: a member named twice, a number that is not finite, too deep."""


class JFloat(float):
    """A JSON number written with a fraction or an exponent: never a JSON integer."""
    def __new__(cls, text):
        v = float(text)
        if v != v or v in (float("inf"), float("-inf")):
            raise Unreadable("a number that is not finite: %s" % text[:40])
        o = float.__new__(cls, v)
        o.text = text
        return o


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Unreadable("member named twice: %r" % k)
        d[k] = v
    return d


def _const(c):
    raise Unreadable("not a JSON number: %s" % c)


def strict_loads(data):
    """Read bytes or text strictly. Raises Unreadable."""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise Unreadable("not UTF-8: %s" % e)
    try:
        return json.loads(data, object_pairs_hook=_pairs, parse_float=JFloat,
                          parse_int=int, parse_constant=_const)
    except Unreadable:
        raise
    except RecursionError:
        raise Unreadable("nested too deep to read")
    except ValueError as e:
        raise Unreadable("not JSON: %s" % e)


IJSON_MAX = 2 ** 53 - 1


def is_json_int(v):
    """A JSON integer as action binding item 10 has it: written without fraction or exponent,
    within +-(2^53-1); never a boolean."""
    return isinstance(v, int) and not isinstance(v, bool) and -IJSON_MAX <= v <= IJSON_MAX


def kind(v):
    if v is None: return "null"
    if isinstance(v, bool): return "bool"
    if isinstance(v, JFloat): return "float"
    if isinstance(v, int): return "int"
    if isinstance(v, float): return "float"
    if isinstance(v, str): return "str"
    if isinstance(v, list): return "list"
    if isinstance(v, dict): return "dict"
    return type(v).__name__


def strict_eq(a, b):
    """Equality where 1, 1.0 and true are three different values."""
    ka, kb = kind(a), kind(b)
    if ka != kb: return False
    if ka == "list":
        return len(a) == len(b) and all(strict_eq(x, y) for x, y in zip(a, b))
    if ka == "dict":
        return set(a) == set(b) and all(strict_eq(a[k], b[k]) for k in a)
    if ka == "float":
        return a.text == b.text if hasattr(a, "text") and hasattr(b, "text") else a == b
    return a == b


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def b64d(s):
    return base64.b64decode(s, validate=True)


def compact(doc):
    """The bytes as received, as the action-binding cases define them: json.dumps with
    separators (',', ':') and ensure_ascii False, in UTF-8."""
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---- times -------------------------------------------------------------------------------
_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_UTC_FORM = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def instant(t):
    """Seconds since 0001-01-01 as a Fraction, or (None, reason) when the text names no instant."""
    if not isinstance(t, str):
        return None, "not a time"
    m = _RFC3339.match(t)
    if not m:
        return None, "not an RFC 3339 time with an offset: %s" % t
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    frac, off = m.group(7), m.group(8)
    if s == 60:
        return None, "a leap second names no instant: %s" % t
    if not (1 <= mo <= 12) or h > 23 or mi > 59 or s > 59 or y == 0:
        return None, "no such time: %s" % t
    try:
        days = _dt.date(y, mo, d).toordinal()
    except ValueError:
        return None, "no such date: %s" % t
    sec = Fraction(days * 86400 + h * 3600 + mi * 60 + s)
    if frac:
        sec += Fraction(frac[1:]) / (10 ** (len(frac) - 1))
    if off != "Z":
        oh, om = int(off[1:3]), int(off[4:6])
        if oh > 23 or om > 59:
            return None, "no such offset: %s" % t
        delta = oh * 3600 + om * 60
        sec -= delta if off[0] == "+" else -delta
    return sec, None


def has_offset(t):
    return isinstance(t, str) and bool(_RFC3339.match(t))


def real_utc(t):
    """A signed time: exactly YYYY-MM-DDTHH:MM:SSZ and a real UTC time (anchoring/signatures)."""
    if not isinstance(t, str) or not _UTC_FORM.match(t):
        return None, "not of the form YYYY-MM-DDTHH:MM:SSZ: %r" % (t,)
    return instant(t)


def utc_text(sec):
    """An instant written YYYY-MM-DDTHH:MM:SSZ (whole seconds; fractions rounded up)."""
    import math
    s = math.ceil(sec)
    days, rem = divmod(int(s), 86400)
    d = _dt.date.fromordinal(days)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (d.year, d.month, d.day, rem // 3600, rem % 3600 // 60, rem % 60)


# ---- the shared signed-bytes rule -------------------------------------------------------
class Unencodable(Exception):
    pass


def f_text(s):
    if not isinstance(s, str):
        raise Unencodable("not text: %r" % (s,))
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        raise Unencodable("a string with no UTF-8 encoding")


def f_digest(h):
    if h is None:
        return b""
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h):
        raise Unencodable("not a digest: %r" % (h,))
    return bytes.fromhex(h)


def f_time(t):
    if not isinstance(t, str) or not _UTC_FORM.match(t):
        raise Unencodable("a time not of the form YYYY-MM-DDTHH:MM:SSZ: %r" % (t,))
    return t.encode("ascii")


def f_int(n):
    if not is_json_int(n) or n < 0:
        raise Unencodable("not a JSON integer: %r" % (n,))
    return n.to_bytes(8, "big")


def signed_bytes(fields):
    out = b"DPS-SIG\x00"
    for f in fields:
        out += len(f).to_bytes(4, "big") + f
    return out


# ---- JSON Pointer patches (the cases' operations) ----------------------------------------
def _tok(t):
    return t.replace("~1", "/").replace("~0", "~")


def _walk(doc, ptr):
    parts = [_tok(p) for p in ptr.split("/")[1:]]
    cur = doc
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    return cur, parts[-1]


def get_ptr(doc, ptr):
    if ptr in ("", "/"):
        return doc
    c, last = _walk(doc, ptr)
    return c[int(last)] if isinstance(c, list) else c[last]


def apply_patch(doc, ops, resolve=lambda v: v):
    import copy
    doc = copy.deepcopy(doc)
    for op in ops:
        if "set" in op:
            c, last = _walk(doc, op["set"])
            v = resolve(op["value"]) if "value" in op else resolve({k: op[k] for k in op if k != "set"})
            if isinstance(c, list):
                c[int(last)] = v
            else:
                c[last] = v
        elif "insert" in op:
            c, last = _walk(doc, op["insert"])
            v = resolve(op["value"]) if "value" in op else resolve({k: op[k] for k in op if k != "insert"})
            if isinstance(c, list):
                c.insert(len(c) if last == "-" else int(last), v)
            else:
                c[last] = v
        elif "remove" in op:
            c, last = _walk(doc, op["remove"])
            if isinstance(c, list):
                del c[int(last)]
            else:
                del c[last]
        elif "move" in op:
            c, last = _walk(doc, op["move"])
            v = c.pop(int(last)) if isinstance(c, list) else c.pop(last)
            c2, last2 = _walk(doc, op["to"])
            if isinstance(c2, list):
                c2.insert(len(c2) if last2 == "-" else int(last2), v)
            else:
                c2[last2] = v
        elif "copy" in op:
            v = copy.deepcopy(get_ptr(doc, op["copy"]))
            c2, last2 = _walk(doc, op["to"])
            if isinstance(c2, list):
                c2.insert(len(c2) if last2 == "-" else int(last2), v)
            else:
                c2[last2] = v
        else:
            raise ValueError("unknown patch op %r" % op)
    return doc
