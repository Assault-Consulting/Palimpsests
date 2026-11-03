"""Strict JSON reading, as action binding 0.3.0 item 8 and signatures 0.2.0 state it:
a document naming a member twice, at any depth, is not read (I-JSON, RFC 7493 s2.3).
A number that is not finite (1e400, NaN, Infinity) makes the document unreadable.
Numbers written with a fraction or an exponent are kept apart from integers (JFloat),
so that 1 and 1.0, and 1 and true, are different values (action binding item 10)."""
import json, math

class Unreadable(Exception):
    pass

class JFloat:
    """A JSON number written with a fraction or an exponent. Never a JSON integer."""
    __slots__ = ("literal", "value")
    def __init__(self, literal):
        self.literal = literal
        self.value = float(literal)
    def __repr__(self):
        return "JFloat(%s)" % self.literal

def _pairs(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        if k in seen:
            raise Unreadable("a member is named twice: %r" % k)
        seen.add(k)
        out[k] = v
    return out

def _float(lit):
    f = JFloat(lit)
    if not math.isfinite(f.value):
        raise Unreadable("a number that is not finite: %s" % lit)
    return f

def _const(name):
    raise Unreadable("not JSON: %s" % name)

def loads(data):
    """Read bytes (UTF-8) or text strictly. Raises Unreadable."""
    try:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8")
        return json.loads(data, object_pairs_hook=_pairs, parse_float=_float,
                          parse_constant=_const)
    except Unreadable:
        raise
    except RecursionError:
        raise Unreadable("nested too deep to read")
    except (ValueError, UnicodeDecodeError) as e:
        raise Unreadable("not JSON: %s" % e)

def to_native(v):
    if isinstance(v, JFloat):
        return v.value
    if isinstance(v, dict):
        return {k: to_native(x) for k, x in v.items()}
    if isinstance(v, list):
        return [to_native(x) for x in v]
    return v

def dumps_compact(v):
    """The bytes-as-received convention of the cases: json.dumps with separators
    (',', ':') and ensure_ascii False, UTF-8."""
    return json.dumps(to_native(v), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def is_jint(v):
    """A JSON integer in I-JSON's range (RFC 7493 s2.2). bool is not an integer."""
    return type(v) is int and -(2**53 - 1) <= v <= 2**53 - 1

def jeq(a, b):
    """JSON value equality with types kept apart: 1 != 1.0, 1 != true."""
    if type(a) is bool or type(b) is bool:
        return type(a) is bool and type(b) is bool and a == b
    if isinstance(a, JFloat) or isinstance(b, JFloat):
        return isinstance(a, JFloat) and isinstance(b, JFloat) and a.value == b.value
    if type(a) is int or type(b) is int:
        return type(a) is int and type(b) is int and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(jeq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(jeq(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b
