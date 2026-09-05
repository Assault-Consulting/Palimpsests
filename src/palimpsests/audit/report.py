# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U6 — the verification-report model: one owner for the schema.

Format id ``pala-verification-report/1``. The shape is the contract
drafted in Auditor's FUNCTIONALITY.md §15, built here so the JSON
schema has exactly one owner: the package's HTML/CLI report and
Auditor's PDF/JSON are two renderings of this one model and cannot
drift apart. The machine truth of the shape ships in the wheel:
``palimpsests/audit/_schemas/pala-verification-report-1.schema.json``.

Wording discipline, inherited from the contract: the report is an
attestation of a check — *this tool verified file X against an anchor
obtained from source Y at time Z, and these are the results.* It never
says "compliant", "certified", or "valid log".

Deterministic given the same inputs except ``checked_at``, which is
isolated by design so two reports of the same file diff to one line.
"""
from __future__ import annotations

import json
import palimpsests
import struct
import time
from dataclasses import dataclass, field
from hashlib import sha256
from palimpsests.audit.pala import MalformedRecord, body_digest_of, iter_records
from palimpsests.audit.pala.codec import RT_WITNESS
from palimpsests.audit.reader import AuditReader
from pathlib import Path

REPORT_FORMAT = "pala-verification-report/1"
SPEC_ID = "PALA-1 v1.0"
_ADVISORY_NOTE = "advisory items do not affect the verdict"


def derive_verdict(data: dict) -> str:
    """The one verdict rule, exported so every rendering calls it.

    "violation" — the chain broke, the container is malformed, a body
    does not match its header digest, or the head missed a supplied
    anchor. "partial" — sound as far as checked, but completeness was
    NOT checked (no anchor), so truncation or wholesale replacement
    would not have been detected. "sound" — everything checked, held.
    A renderer MUST NOT re-derive this rule; it calls this function or
    reads the report's ``verdict`` field, which was produced by it.
    """
    chain = data["chain"]
    container = data["container"]
    completeness = data["completeness"]
    broken = (
        not chain["chain_ok"]
        or not container["well_formed"]
        or bool(container["body_digest_mismatches"])
        or completeness["complete_to_anchor"] is False
    )
    if broken:
        return "violation"
    if completeness["complete_to_anchor"] is None:
        return "partial"
    return "sound"


@dataclass(frozen=True)
class VerificationReport:
    """The §15 model. ``data`` is the exact JSON-shaped dict."""

    data: dict = field(repr=False)

    def to_json_bytes(self) -> bytes:
        return (json.dumps(self.data, indent=2, sort_keys=True) + "\n").encode()


def _safety_section(reader) -> dict:
    """§15's ``safety`` block: every SAFETY record, and the r2 loop's
    positive count.

    ``unacknowledged_candidates`` was, before this, a straight seq-only
    match against every OVERSIGHT_ACK's ``EVT_REF_SEQ`` — the same
    overclaim ``reference_hash_mismatch`` exists to catch on the
    advisory side, just not caught here: an ack whose bound
    ``EVT_REF_HASH`` did not match the candidate at that seq still
    counted the candidate acknowledged. ``acknowledged_candidates()``
    is the reader's own hash-verified resolution — the same one
    ``_check_reference`` uses — so this number and the advisory items
    describing a broken reference cannot disagree about which
    candidates are actually acknowledged.
    """
    candidates: set[int] = set()
    items: list[dict] = []
    count = 0
    for rec in reader.safety_records():
        if rec.type_name != "SAFETY":
            continue
        count += 1
        items.append(
            {"seq": rec.seq, "kind": rec.kind, "kind_name": rec.kind_name}
        )
        if rec.kind_name == "INCIDENT_CANDIDATE":
            candidates.add(rec.seq)
    acknowledged = reader.acknowledged_candidates()
    return {
        "count": count,
        "unacknowledged_candidates": len(candidates - acknowledged),
        "items": items,
    }


def _structure(reader) -> tuple:
    """The reader-derived parts of the report, read from headers.

    ``seq`` is the u64 at header offset 12 and ``record_type`` the u16 at
    offset 8 (§2.1) — the same fields ``DecodedRecord`` exposes, taken
    from the header bytes the reader already holds instead of from a
    decoded record per line. Nothing here needs a body except the
    safety section, which decodes SAFETY records alone.
    """
    ver = reader.verify()
    boots = reader.boots()
    spans = reader.spans()
    safety = _safety_section(reader)
    headers = reader._headers
    witness_pins = [
        struct.unpack_from("<Q", hb, 12)[0]
        for hb in headers
        if struct.unpack_from("<H", hb, 8)[0] == RT_WITNESS
    ]
    first_seq = struct.unpack_from("<Q", headers[0], 12)[0] if headers else None
    last_seq = struct.unpack_from("<Q", headers[-1], 12)[0] if headers else None
    return ver, boots, spans, safety, witness_pins, first_seq, last_seq


def build_report(
    source: str | Path,
    *,
    anchor_source=None,
    tool: str | None = None,
    reader: AuditReader | None = None,
) -> VerificationReport:
    """Build the report for the chain at ``source``.

    ``tool`` lets a shell name itself ("palimpsests-auditor X.Y.Z");
    the default names this package. The file digest is taken over the
    bytes as opened, once, and carried into the subject block.

    ``reader``, when given, is used in place of opening a fresh one.
    Without it, this function always opened its own — even when the
    caller already held one open on the same file. A caller that had
    already paid to decode the chain (any prior ``verify()`` or
    ``records()`` call warms ``AuditReader``'s own cache; the structural
    views no longer do) paid that cost a second time here, for
    no reason but that this function had no way to be handed the first
    reader. On a million-record chain that second decode is the
    difference between finishing and being killed for memory.

    With ``reader`` given, the file is not read a second time: the
    subject digest and the container walk run over the bytes the reader
    already holds (its mapping, for ``open()``), so the only copy of the
    file in memory is the reader's. The walk itself stays: §2.4
    well-formedness and the body↔header digest binding are attested
    here, not assumed, and a header-only chain check cannot see a body
    swap. Measured, that walk is the cheap part of this function.

    What ``reader`` still does not do is reduce the peak of the reader
    it is handed. ``verify()`` today materialises the whole chain to
    resolve references; the structural views and the safety section no
    longer do (they read headers, and decode SAFETY records alone), so
    once ``verify()`` stops materialising, the report path is already
    ready for it.

    ``reader`` is used exactly as given — never closed here, and never
    re-opened. Closing what you did not open would surprise a caller
    who still wants to use it afterward; that stays their
    responsibility, the same as it always was for a reader they
    themselves opened. ``anchor_source`` is ignored when ``reader`` is
    given: the reader's own anchor, set at the time *it* was opened,
    is what a shared reader already answers with, and silently
    substituting a different one here would verify against an anchor
    the caller never asked this call to use.

    ``reader`` must be open on the same bytes as ``source`` names. This
    is not checked — the caller already holds both and is the only one
    in a position to know they agree; a report built from a mismatched
    pair would name one file's identity over another file's verdict.
    """
    path = Path(source)
    # With a reader supplied, the bytes it already holds (a mapping for
    # ``open()``, the object for ``from_bytes()``) are the bytes; reading
    # the file a second time doubled the resident set for nothing (U14).
    # ``sha256`` and the container walk below take a buffer, so the
    # digest and every count are byte-identical either way.
    raw = reader._data if reader is not None else path.read_bytes()

    # The report's own container walk (K2/K5): §2.4 well-formedness and
    # the body↔header digest binding are attested here, not assumed —
    # reader.verify() covers headers, and a body swap is invisible to a
    # header-only chain check.
    bytes_parsed = 0
    body_mismatches: list[int] = []
    malformed: str | None = None
    try:
        for hb, body in iter_records(raw):
            bytes_parsed += len(hb) + len(body)
            if body and body_digest_of(body) != hb[124:156]:
                (bad_seq,) = struct.unpack_from("<Q", hb, 12)
                body_mismatches.append(bad_seq)
    except MalformedRecord as e:
        malformed = str(e)

    if reader is not None:
        ver, boots, spans, safety, witness_pins, first_seq, last_seq = _structure(reader)
    else:
        with AuditReader.open(path, anchor=anchor_source) as opened:
            ver, boots, spans, safety, witness_pins, first_seq, last_seq = _structure(
                opened
            )

    chain = ver.chain
    version = palimpsests.__version__

    data = {
        "format": REPORT_FORMAT,
        "subject": {
            "filename": path.name,
            "sha256": sha256(raw).hexdigest(),
            "bytes": len(raw),
            "records": chain.count,
            "boots": len(boots),
            "spans": len(spans),
            "first_seq": first_seq,
            "last_seq": last_seq,
        },
        "verifier": {
            "tool": tool if tool is not None else f"palimpsests {version}",
            "package": f"palimpsests {version}",
            "spec": SPEC_ID,
        },
        "checked_at": {
            "wall_ns": time.time_ns(),
            "note": "the auditing machine's clock",
        },
        "container": {
            "well_formed": malformed is None,
            "malformed": malformed,
            "bytes_parsed": bytes_parsed,
            "bytes_total": len(raw),
            "body_digest_mismatches": body_mismatches,
        },
        "chain": {
            "chain_ok": chain.chain_ok,
            "head": chain.head.hex(),
            "breaks": list(chain.breaks),
            "gaps": list(chain.gaps),
            "violations": [list(v) for v in chain.violations],
            "uninterpretable": list(chain.uninterpretable),
        },
        "anchor": (
            {
                "head": ver.anchor.head.hex(),
                "source_kind": ver.anchor.source_kind,
                "source_detail": ver.anchor.source_detail,
                "observed_at_ns": None,
                "attempts": [
                    {
                        "source_kind": a.source_kind,
                        "outcome": a.outcome,
                        "error": a.error,
                    }
                    for a in ver.anchor_attempts
                ],
            }
            if ver.anchor is not None
            else None
        ),
        "completeness": {
            "complete_to_anchor": ver.complete_to_anchor,
            "anchor_lag": ver.anchor_lag,
            "anchor_reason": chain.anchor_reason,
        },
        "existence": {
            "external_pins": witness_pins,
            "note": (
                "witness records present; receipts are not verified by this tool"
                if witness_pins
                else "tier A: none available"
            ),
        },
        "diagnosis": (
            {
                "pattern": ver.diagnosis.pattern,
                "at_seq": ver.diagnosis.at_seq,
                "expected": ver.diagnosis.expected,
                "narrative": ver.diagnosis.narrative,
            }
            if ver.diagnosis is not None
            else None
        ),
        "advisory": {
            "count": len(ver.advisory.items),
            "items": [
                {"code": i.code, "at_seq": i.at_seq, "detail": i.detail}
                for i in ver.advisory.items
            ],
            "note": _ADVISORY_NOTE,
        },
        "safety": safety,
        "time_basis": {
            "axis": "proved-order",
            "wall_claims_qualified_by": "time_trust",
            "caveats": [],
        },
    }
    data["verdict"] = derive_verdict(data)
    return VerificationReport(data=data)
