"""Common helpers, written from the text of anchoring 0.2.0 (README, "Signed bytes (shared rule)").

Every function here says which sentence it rests on in its docstring.
"""
import base64
import binascii
import datetime as _dt
import hashlib
import json
import re

MAX_SAFE = 2 ** 53 - 1  # "A checkpoint's count is at most 2^53 - 1"

STATUS_ORDER = ["failed", "unavailable", "not_supported", "not_checked", "verified"]


def combine(statuses):
    """Combine check statuses into one dimension status.

    Text: a dimension is verified only when every check is verified. The text gives no
    precedence between failed, unavailable, not_supported and not_checked; the order used here
    (failed, unavailable, not_supported, not_checked) is a choice recorded in the ambiguity log (A05).
    """
    for s in STATUS_ORDER:
        if s in statuses:
            return s
    return "verified"


class DuplicateMember(ValueError):
    pass


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateMember("member %r named twice" % k)
        d[k] = v
    return d


def strict_loads(text):
    """Read JSON refusing a member named twice (portable verification item 8, I-JSON RFC 7493 2.3)."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")
    return json.loads(text, object_pairs_hook=_no_dup,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError("constant " + c)))


def doc_bytes(doc):
    """'A document's bytes as received ... are its JSON with no whitespace, in UTF-8' (vectors.json about)."""
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def is_json_int(x):
    """'An integer is written as a JSON integer, digits only with no fraction or exponent'."""
    return type(x) is int


_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64_strict(s):
    """Padded base64, as the schemas' pattern has it; None when it is not."""
    if not isinstance(s, str) or not _B64.fullmatch(s):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


_HEX_PAIRS = re.compile(r"(?:[0-9a-f]{2})+")


def hex_strict(s):
    """'public_key_hex is read strictly, lowercase hex pairs and nothing else' (re.fullmatch, so no final newline)."""
    if not isinstance(s, str) or not _HEX_PAIRS.fullmatch(s):
        return None
    return bytes.fromhex(s)


def hex_lenient(s):
    """The lenient read the duplicate-key refusal keeps: whitespace removed, case ignored (K68)."""
    if not isinstance(s, str):
        return None
    t = re.sub(r"\s+", "", s).lower()
    if not t or len(t) % 2 or not re.fullmatch(r"[0-9a-f]*", t):
        return None
    return bytes.fromhex(t)


_SIGNED_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def signed_time_form(s):
    """'A time signed as text has exactly the form YYYY-MM-DDTHH:MM:SSZ' (form only)."""
    return isinstance(s, str) and _SIGNED_TIME.fullmatch(s) is not None


def parse_utc(s):
    """A real UTC time in exactly the signed form: the date exists, 00-23 hours, 00-59 minutes and seconds.

    Returns an aware datetime, or None when the time cannot be read (a leap second, 2026-02-30 ...).
    """
    if not signed_time_form(s):
        return None
    try:
        return _dt.datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]),
                            int(s[17:19]), tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


_STATED = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})")


def parse_stated(s):
    """An issuer's stated time (report schema 'stated_time': fraction and offset allowed). None if unreadable."""
    if not isinstance(s, str):
        return None
    m = _STATED.fullmatch(s)
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    try:
        micro = 0
        if frac:
            digits = frac[1:]
            micro = int((digits + "000000")[:6])
        if tz == "Z":
            tzinfo = _dt.timezone.utc
        else:
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[4:6])
            if hh > 23 or mm > 59:
                return None
            tzinfo = _dt.timezone(sign * _dt.timedelta(hours=hh, minutes=mm))
        return _dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), micro, tzinfo=tzinfo)
    except ValueError:
        return None


def fmt_instant(t):
    """Write an aware datetime as the report's 'instant' (UTC, Z, fraction only when non-zero; A06)."""
    t = t.astimezone(_dt.timezone.utc)
    s = t.strftime("%Y-%m-%dT%H:%M:%S")
    if t.microsecond:
        s += ("." + "%06d" % t.microsecond).rstrip("0")
    return s + "Z"


# ---- shared signed-bytes rule ----------------------------------------------------------------

DPS_SIG = b"DPS-SIG\x00"


class CannotEncode(ValueError):
    pass


def lp(b):
    """lp(x) = the length of x as 4 bytes, big-endian, then the bytes of x."""
    if len(b) > 0xFFFFFFFF:
        raise CannotEncode("field longer than 2^32 - 1 bytes")
    return len(b).to_bytes(4, "big") + b


def enc_text(s, name):
    """'A text field is the UTF-8 encoding of the JSON string's value ... A string that has no UTF-8
    encoding, because it holds a lone surrogate such as \\ud800, cannot be signed.'"""
    if not isinstance(s, str):
        raise CannotEncode("%s is not a JSON string" % name)
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        raise CannotEncode("%s has no UTF-8 encoding (lone surrogate)" % name)


def enc_int(n, name):
    """'An integer is written as a JSON integer ... and signed as 8 bytes, big-endian, unsigned.'"""
    if not is_json_int(n):
        raise CannotEncode("%s is not a JSON integer (%r)" % (name, n))
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise CannotEncode("%s does not fit 8 unsigned bytes" % name)
    return n.to_bytes(8, "big")


def enc_digest_hex(h, name):
    """'A digest (a seal, a link) is its 32 raw bytes, never its hex.'"""
    if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h):
        raise CannotEncode("%s is not 64 lowercase hex characters" % name)
    return bytes.fromhex(h)


def enc_time(s, name):
    """'Only the form is the encoder's concern': a time in the form is encoded as the text it is written in."""
    if not signed_time_form(s):
        raise CannotEncode("%s is not in the form YYYY-MM-DDTHH:MM:SSZ" % name)
    return s.encode("ascii")


def checkpoint_fields(key_ref, chain_id, count, head_link, checkpoint_time,
                      profile="dps-anchoring", version="0.2.0", assertion="checkpoint"):
    """The eight fields of assertion type checkpoint, in order (README table)."""
    if count is not None and is_json_int(count) and not (1 <= count <= MAX_SAFE):
        raise CannotEncode("count %d is not from 1 to 2^53 - 1" % count)
    return [enc_text(profile, "profile"), enc_text(version, "profile_version"),
            enc_text(assertion, "assertion type"), enc_text(key_ref, "key_ref"),
            enc_text(chain_id, "chain_id"), enc_int(count, "count"),
            enc_digest_hex(head_link, "head_link"), enc_time(checkpoint_time, "checkpoint_time")]


def signed_bytes(fields):
    return DPS_SIG + b"".join(lp(f) for f in fields)


def checkpoint_signed_bytes(cp_like, key_ref):
    """Build a checkpoint's signed bytes from the fields the verifier checks, with the profile, version
    and assertion type it expects ('It never verifies a signature over bytes supplied with it')."""
    return signed_bytes(checkpoint_fields(key_ref, cp_like.get("chain_id"), cp_like.get("count"),
                                          cp_like.get("head_link"), cp_like.get("checkpoint_time")))


def parse_signed_bytes(b, nfields):
    """Read bytes made under the shared rule back into fields (used for a SCITT statement's payload)."""
    if not b.startswith(DPS_SIG):
        raise ValueError("does not start with DPS-SIG 00")
    i = len(DPS_SIG)
    out = []
    for _ in range(nfields):
        if i + 4 > len(b):
            raise ValueError("truncated length prefix")
        n = int.from_bytes(b[i:i + 4], "big")
        i += 4
        if i + n > len(b):
            raise ValueError("truncated field")
        out.append(b[i:i + n])
        i += n
    if i != len(b):
        raise ValueError("bytes after the last field")
    return out


# ---- the chain (portable verification 0.3.0, "Chains, checkpoints and time") ---------------------

def entry_digest(entry):
    """'digest(i) is the entry's seal, or its derived digest.'"""
    seal = entry.get("seal") if isinstance(entry, dict) else None
    if isinstance(seal, dict) and isinstance(seal.get("seal_hash"), str):
        return seal["seal_hash"]
    if isinstance(entry, dict) and isinstance(entry.get("derived_digest"), str):
        return entry["derived_digest"]
    return None


def links(export):
    """link(i) = SHA-256(link(i-1) || digest(i)), from 32 zero bytes. Returns a list of 32-byte links,
    stopping at the first entry whose digest cannot be read."""
    prev = b"\x00" * 32
    out = []
    for e in export.get("entries", []):
        d = entry_digest(e)
        if d is None or not re.fullmatch(r"[0-9a-f]{64}", d):
            break
        prev = sha256(prev + bytes.fromhex(d))
        out.append(prev)
    return out
