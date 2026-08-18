# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Names for the two header enums a consumer has to render.

These exist so that a shell does not re-type the tables. A consumer with its
own mapping is one spec revision away from labelling a record confidently and
wrongly — and mislabelling the assurance tier of an audit record is a claim
about how far that record can be trusted.
"""
from __future__ import annotations

import pytest
from palimpsests.audit.names import assurance_tier_name, time_trust_name
from palimpsests.audit.pala.codec import (
    TIER_A,
    TIER_B,
    TIER_BPLUS,
    TIME_HW_RTC,
    TIME_NTP_SYNCED,
    TIME_UNKNOWN,
    TIME_UNSYNCED,
)


@pytest.mark.parametrize(
    ("value", "name"),
    [(TIER_A, "A"), (TIER_B, "B"), (TIER_BPLUS, "B+")],
)
def test_tier_names(value: int, name: str) -> None:
    assert assurance_tier_name(value) == name


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (TIME_UNKNOWN, "UNKNOWN"),
        (TIME_UNSYNCED, "UNSYNCED"),
        (TIME_HW_RTC, "HW_RTC"),
        (TIME_NTP_SYNCED, "NTP_SYNCED"),
    ],
)
def test_time_trust_names(value: int, name: str) -> None:
    assert time_trust_name(value) == name


def test_there_is_no_tier_c_header_value() -> None:
    """Tier C is not a header value, and must never acquire a name here.

    A header cannot honestly claim to have been witnessed before the witness
    exists (§6). Tier C is asserted post-hoc by an RT_WITNESS record covering
    a seq range. If a future edit adds "C" to the table, this fails — which is
    the point: it would let a writer self-certify the one tier it cannot.
    """
    assert "C" not in {assurance_tier_name(v) for v in range(256)}


@pytest.mark.parametrize("unknown", [4, 7, 255])
def test_unknown_time_trust_is_none_not_a_guess(unknown: int) -> None:
    assert time_trust_name(unknown) is None


@pytest.mark.parametrize("unknown", [3, 9, 255])
def test_unknown_tier_is_none_not_a_guess(unknown: int) -> None:
    """Same contract as type_name and kind_name (§7.6, §10.5): unknown is
    reported, never rejected and never guessed at."""
    assert assurance_tier_name(unknown) is None


def test_every_defined_constant_has_a_name() -> None:
    """The tables must not fall behind the constants they name.

    Reads the constants out of the codec rather than repeating them, so a new
    tier or trust level added there without a name here fails this test rather
    than silently rendering as unknown in every consumer.
    """
    from palimpsests.audit.pala import codec

    tiers = {v for n, v in vars(codec).items() if n.startswith("TIER_")}
    trusts = {v for n, v in vars(codec).items() if n.startswith("TIME_")}
    assert all(assurance_tier_name(v) is not None for v in tiers)
    assert all(time_trust_name(v) is not None for v in trusts)
