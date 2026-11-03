"""Issuer times compared as instants (action binding 0.3.0, the verifier: '09:12:00Z' and
'09:12:00+00:00' are the same time). A time the schema pattern accepts but that names
no instant (a date that does not exist, a leap second, an hour 24) gives None.
Instants are kept as integer microseconds from 0001-01-01T00:00:00Z on the proleptic
Gregorian calendar, so a real instant whose UTC date falls after the year 9999 still compares."""
import re, datetime

_RFC3339 = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$")
_UTC_Z = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$")

def instant(s):
    """RFC 3339 time with an offset -> microseconds, or None if it names no instant
    or has no offset."""
    if not isinstance(s, str):
        return None
    m = _RFC3339.match(s)
    if not m:
        return None
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    frac, off = m.group(7), m.group(8)
    try:
        day = datetime.date(y, mo, d)
    except ValueError:
        return None
    if not (0 <= h <= 23 and 0 <= mi <= 59 and 0 <= se <= 59):
        return None
    us = 0
    if frac:
        digits = frac[1:]
        us = int((digits + "000000")[:6])
    if off == "Z":
        offs = 0
    else:
        oh, om = int(off[1:3]), int(off[4:6])
        if oh > 23 or om > 59:
            return None
        offs = (oh * 3600 + om * 60) * (1 if off[0] == "+" else -1)
    secs = day.toordinal() * 86400 + h * 3600 + mi * 60 + se - offs
    return secs * 1_000_000 + us

def utc_signed_time_ok(s):
    """A signed time (signatures 0.2.0): exactly YYYY-MM-DDTHH:MM:SSZ, a real UTC time,
    no leap second."""
    if not isinstance(s, str) or not _UTC_Z.match(s):
        return False
    return instant(s) is not None

def utc_text(us):
    """Microsecond instant -> YYYY-MM-DDTHH:MM:SSZ (only for years 1..9999)."""
    secs = us // 1_000_000
    days, rem = divmod(secs, 86400)
    d = datetime.date.fromordinal(days)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (d.year, d.month, d.day, rem // 3600, rem % 3600 // 60, rem % 60)
