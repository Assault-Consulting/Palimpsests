# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Human names for the header enums a consumer has to render.

The codec owns the *values* (``pala.codec``, stdlib-only by design); this
module owns the *labels*, following the §10.5 rule already used for kind
names — the ints are imported, never re-typed.

It exists so that consumers do not carry their own copy of these tables. A
shell with its own mapping is one specification revision away from labelling
a record confidently and wrongly, and mislabelling the assurance tier of an
audit record is a claim about how far that record can be trusted.

Unknown values return ``None``, the same contract as ``DecodedRecord``'s
``type_name`` and ``kind_name`` (§7.6): unknown is reported, never rejected
and never guessed at. A consumer renders the number and says it does not know
it.
"""
from __future__ import annotations

from palimpsests.audit.pala.codec import (
    TIER_A,
    TIER_B,
    TIER_BPLUS,
    TIME_HW_RTC,
    TIME_NTP_SYNCED,
    TIME_UNKNOWN,
    TIME_UNSYNCED,
)

__all__ = ["assurance_tier_name", "time_trust_name"]

# §6: the platform-capability claim the writer made at write time.
#
# Tier C is deliberately absent, and must stay absent: a header cannot
# honestly claim to have been witnessed before the witness exists. Tier C is
# asserted post-hoc by an RT_WITNESS record covering a seq range. A name for
# it here would let a writer self-certify the one tier it cannot.
_TIER_NAMES = {
    TIER_A: "A",
    TIER_B: "B",
    TIER_BPLUS: "B+",
}

# §5: what the writer claimed about its own wall clock at write time. A
# claim, never a proof — which is why this label belongs beside
# wall_clock_ns everywhere that field is displayed.
_TIME_TRUST_NAMES = {
    TIME_UNKNOWN: "UNKNOWN",
    TIME_UNSYNCED: "UNSYNCED",
    TIME_HW_RTC: "HW_RTC",
    TIME_NTP_SYNCED: "NTP_SYNCED",
}


def assurance_tier_name(value: int) -> str | None:
    """Name for an ``assurance_tier`` header value, or ``None`` if unknown."""
    return _TIER_NAMES.get(value)


def time_trust_name(value: int) -> str | None:
    """Name for a ``time_trust`` header value, or ``None`` if unknown."""
    return _TIME_TRUST_NAMES.get(value)
