# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""A dry run of the ingestion path: the real parsing, nothing written (R1).

A check of an integration must not put a test call on the audit chain: the
chain is append-only, and a call nobody made would stay in it for good. A
request carrying ``X-Palimpsests-Dry-Run: 1`` passes the same bearer check
and the same ingestion code as a real one, against :class:`DryAudit` and a
copy of the pending calls — and the reply says what would have been
recorded. The chain, the pending calls and the accepted counters are left
exactly as they were.
"""
from __future__ import annotations

DRY_RUN_HEADER = "x-palimpsests-dry-run"

_OUTCOMES = {0: "ok", 1: "error", 2: "timeout", 3: "cancelled", 4: "unobserved"}
_SOURCES = {0: "parsed-from-wire", 1: "reported-by-client"}


def is_dry_run(request) -> bool:
    return request.headers.get(DRY_RUN_HEADER, "").strip() == "1"


class DryAudit:
    """Stands in for the audit: takes the calls the ingestion code makes,
    remembers what they would have written, and writes nothing."""

    def __init__(self) -> None:
        self.would_record: list[dict] = []

    def tool_called(self, name, args_digest, span_id, *, source=0, **_ignored):
        self.would_record.append({
            "record": "TOOL_CALL",
            "tool": name,
            "source": _SOURCES.get(source, source),
            "payload_digest": args_digest is not None,
        })
        # A reference the ingestion code can carry to the result and no
        # further: never a seq or a hash of this chain.
        return -len(self.would_record), bytes(32)

    def tool_result(self, call_seq, call_hash, outcome, result_digest, span_id,
                    *, source=0, **_ignored):
        self.would_record.append({
            "record": "TOOL_RESULT",
            "outcome": _OUTCOMES.get(outcome, outcome),
            "source": _SOURCES.get(source, source),
            "payload_digest": result_digest is not None,
        })
        return bytes(32)
