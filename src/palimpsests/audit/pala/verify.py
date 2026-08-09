# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""PALA-1 chain verification — the three questions of §7, kept separate.

Verification answers three different questions with three different inputs,
and this module refuses to collapse them into one boolean:

1. *Is what I hold internally consistent?* — needs nothing (§7.1)
2. *Is what I hold all of it?* — needs an anchor from outside the log (§7.2)
3. *Did this history exist at time T?* — needs a witness receipt (§7.3;
   out of scope here, the receipt follows the witness's own protocol)

``chain_ok`` means **internally consistent, nothing more**: §7.1 cannot see
a truncated tail, because dropping the last N records leaves a perfectly
linked chain with a different head and no other trace. Completeness is a
separate field with a separate answer, including "not checked" — never
silently "passed".

The §7.1 per-record rules live in one place — ``IncrementalVerifier`` — so
that ``verify_headers`` (batch) and ``TailingReader`` (live) cannot drift
apart. This module drives that verifier over a whole sequence and then
applies the §7.2 anchor comparison.

Stdlib-only, header-only, key-free by design.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from palimpsests.audit.pala.codec import KNOWN_RECORD_TYPES
from palimpsests.audit.pala.incremental import IncrementalVerifier

__all__ = ["VerifyResult", "verify_headers"]


@dataclass
class VerifyResult:
    """The three answers, plus the diagnostics an auditor acts on."""

    #: True iff breaks, gaps and violations are all empty. Internal
    #: consistency only — see the module docstring.
    chain_ok: bool
    count: int
    head: bytes
    #: Seqs where prev_hash does not name the preceding record (§4.1).
    breaks: list[int] = field(default_factory=list)
    #: Seqs where the sequence number jumped. A gap is a break whether or
    #: not the hashes link (§4.1) — a keyholder can rebuild a shorter,
    #: perfectly linked chain, and only the gap betrays it.
    gaps: list[int] = field(default_factory=list)
    #: (seq, reason) for normative MUSTs violated on records we claim to
    #: understand (§7.4). Defective record, possibly sound chain around it.
    violations: list[tuple[int, str]] = field(default_factory=list)
    #: Seqs of records with an unknown format_version or record_type —
    #: chain-checked, reported, never rejected (§7.6).
    uninterpretable: list[int] = field(default_factory=list)
    #: None = no anchor supplied, completeness NOT checked (§7.2). This is
    #: reported as "not checked", never as passing.
    complete_to_anchor: bool | None = None
    #: When the anchor names a record inside the chain but not the head:
    #: how many records sit past the anchored head. An *unanchored tail*
    #: (a crash between write and anchoring, an anchor-store outage, or a
    #: writer without anchor access) — a different diagnosis from a
    #: replacement, and the difference is what the operator investigates.
    anchor_lag: int | None = None
    anchor_reason: str | None = None


def verify_headers(
    headers: Iterable[bytes],
    *,
    known_types: frozenset[int] = KNOWN_RECORD_TYPES,
    expected_head: bytes | None = None,
) -> VerifyResult:
    """Header-only verification per §7.1, with §7.2 when an anchor is given.

    ``expected_head`` is the anchor: the head this chain is supposed to
    have, obtained from **outside** the log — a local anchor store, or the
    head covered by the newest witness receipt. Without it, tail
    truncation is undetectable and ``complete_to_anchor`` stays ``None``;
    that is not a limitation of this function, it is why anchors exist.
    """
    verifier = IncrementalVerifier(known_types=known_types)
    for hb in headers:
        verifier.step(hb)
        if verifier.halted:
            break

    result = verifier.result()
    seen = verifier.seen
    head = verifier.head

    if expected_head is not None:
        result.complete_to_anchor = expected_head == head
        if not result.complete_to_anchor:
            if expected_head in seen:
                result.anchor_lag = len(seen) - seen.index(expected_head) - 1
                result.anchor_reason = (
                    f"chain extends {result.anchor_lag} record(s) beyond the anchored "
                    "head — an unanchored tail, not a replacement"
                )
            else:
                result.anchor_reason = (
                    "the anchored head names no record in this chain — the log was "
                    "replaced, rolled back, or truncated"
                )

    return result
