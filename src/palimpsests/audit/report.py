# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U6 — the verification-report model: one owner for the schema.

Format id ``pala-verification-report/2`` (since 0.15). The shape is the
contract drafted in Auditor's FUNCTIONALITY.md §15, built here so the JSON
schema has exactly one owner: the package's HTML/CLI report and
Auditor's PDF/JSON are two renderings of this one model and cannot
drift apart. The machine truth of the shape ships in the wheel:
``palimpsests/audit/_schemas/pala-verification-report-2.schema.json``.

``/2`` differs from ``/1`` in five ways, all decided together so the id
moves once (``docs/specs/report/MIGRATING-1-TO-2.md``): a chain violation
carries its code (``chain.violation_codes``, ``diagnosis.code``); the
segments manifest a diagnosis rested on is named and hashed (``manifest``);
a container with no records has its own verdict, ``empty``; and the format
is open — a release may add a key, and none is removed, renamed or given
another meaning without a new id. ``/1`` is no longer written. A ``/1``
report already on disk stays readable: its schema still ships beside the
new one, and :func:`derive_verdict` and the HTML rendering take either.

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
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from palimpsests.audit.anchors import _portable_detail, _portable_error
from palimpsests.audit.pala.codec import RT_WITNESS
from palimpsests.audit.reader import AuditReader
from pathlib import Path
from types import MappingProxyType

__all__ = [
    "HEALTH_BASES",
    "NOTES",
    "REPORT_FORMAT",
    "REPORT_FORMAT_1",
    "VERDICTS",
    "VerificationReport",
    "build_report",
    "derive_verdict",
    "health_summary",
]

REPORT_FORMAT = "pala-verification-report/2"
#: The format written by 0.10 – 0.14. Not written any more; still read.
REPORT_FORMAT_1 = "pala-verification-report/1"
#: The verdicts of ``/2``, in the order a reader should think of them. The
#: set is closed: a fifth verdict would be a new format id.
VERDICTS = ("sound", "partial", "empty", "violation")
SPEC_ID = "PALA-1 v1.0"
#: The report's fixed sentences, by name. Each is the same text in every
#: report — it is about the report, not about any one chain — and appears
#: there beside its name (``note_id``). A consumer that shows the report in
#: another language translates a *name*; matching on the English would break
#: silently the day a word changes. The names are stable; the wording may be
#: corrected. Text without a name (a diagnosis narrative, a record's
#: detail) is about one chain and is shown as written.
NOTES: Mapping[str, str] = MappingProxyType({
    "advisory": "advisory items do not affect the verdict",
    "health": (
        "advisory: the record's own account of its clocks and its anchoring, taken from "
        "its headers; no figure is a threshold and none affects the verdict"
    ),
    "checked_at": "the auditing machine's clock",
    "existence_witness_present": (
        "witness records present; receipts are not verified by this tool"
    ),
    "existence_no_witness": (
        "no WITNESS record in this chain; receipts held outside the "
        "chain (for example SCITT) are not consulted by this report"
    ),
})

#: What each group of the ``health`` section is measured on, by name
#: (``basis_id`` in the report, beside ``basis``). The same rule as
#: :data:`NOTES`: the name is the contract, the sentence is its English.
HEALTH_BASES: Mapping[str, str] = MappingProxyType({
    "proved_order": "proved order",
    "monotonic_in_boot": "the monotonic clock, within one boot",
    "wall_against_monotonic": (
        "the writer's wall clock against its monotonic clock, within one boot"
    ),
})


def _note(name: str) -> dict[str, str]:
    return {"note": NOTES[name], "note_id": name}


def _basis(name: str) -> dict[str, str]:
    return {"basis": HEALTH_BASES[name], "basis_id": name}


def health_summary(reader: AuditReader) -> dict:
    """The report's ``health`` section for the chain ``reader`` holds.

    A summary of fixed size over the health channel
    (``boot_statistics``, ``step_catalog``, ``drift_series``): it does not
    grow with the chain, so a report stays a document. Every group names
    the clock its figures are measured on, because a figure on the
    writer's wall clock is a claim and one in proved order is not. There
    is no threshold and no word of judgement: what a gap of an hour or a
    step of a second means is the reader's to decide.
    """
    from palimpsests.audit.bootstats import boot_statistics
    from palimpsests.audit.timehealth import STEP_THRESHOLD_NS, drift_series, step_catalog

    boots = boot_statistics(reader)
    steps = step_catalog(reader)
    slopes = [d.slope_ppm for d in drift_series(reader) if d.slope_ppm is not None]

    anchored = [b for b in boots if b.anchors.widest_anchor_gap_ns is not None]
    widest = max(anchored, key=lambda b: b.anchors.widest_anchor_gap_ns, default=None)
    largest = max(steps, key=lambda s: abs(s.delta_ns), default=None)
    return {
        **_note("health"),
        "boots": {
            **_basis("proved_order"),
            "count": len(boots),
            "resumed_after_truncated_tail": sum(
                b.view.recovery_seq is not None for b in boots),
            "with_time_trust_change": sum(len(b.view.time_trust_values) > 1 for b in boots),
        },
        "anchors": {
            **_basis("monotonic_in_boot"),
            "count": sum(b.anchors.count for b in boots),
            "boots_without_anchor": sum(b.anchors.count == 0 for b in boots),
            # boot start to first anchor and last anchor to boot end count
            # as gaps: an existed-by bracket is never narrower than this
            "widest_gap_ns": widest.anchors.widest_anchor_gap_ns if widest else None,
            "widest_gap_boot_first_seq": widest.view.first_seq if widest else None,
        },
        "wall_clock": {
            **_basis("wall_against_monotonic"),
            "step_threshold_ns": STEP_THRESHOLD_NS,
            "steps": sum(s.kind == "step" for s in steps),
            "regressions": sum(s.kind == "regression" for s in steps),
            "slews": sum(s.kind == "slew" for s in steps),
            "largest_delta_ns": largest.delta_ns if largest else None,
            "largest_at_seq": largest.seq if largest else None,
            "drift_boots_measured": len(slopes),
            "drift_slope_ppm_min": round(min(slopes), 3) if slopes else None,
            "drift_slope_ppm_max": round(max(slopes), 3) if slopes else None,
        },
        "spans": {
            **_basis("proved_order"),
            "closed": sum(b.spans.closed for b in boots),
            "open": sum(b.spans.open for b in boots),
        },
    }


def derive_verdict(data: dict) -> str:
    """The one verdict rule, exported so every rendering calls it.

    "violation" — the chain broke, the container is malformed, a body
    does not match its header digest, or the head missed a supplied
    anchor. "empty" — nothing contradicts anything, because the container
    holds no records: nothing was checked, and nothing was found intact
    (clarification C-8). "partial" — sound as far as checked, but
    completeness was NOT checked (no anchor), so truncation or wholesale
    replacement would not have been detected. "sound" — everything
    checked, held.

    The order matters. An empty file where an anchor says a log should be
    is a violation — the anchor is missed — and is decided first; "empty"
    is what is left when nothing was supplied to contradict, or when the
    anchor supplied is itself the head of a chain with no records. In
    neither case is "sound" or "partial" true of a file with nothing in it.

    A ``/1`` report has no "empty": handed one, this function answers by
    the rule that report was written under, so a stored ``/1`` report
    re-derives to the verdict it carries.

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
    if data.get("format") != REPORT_FORMAT_1 and data["subject"]["records"] == 0:
        return "empty"
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
        "unacknowledged_candidates": len(candidates - acknowledged.keys()),
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
    boots, spans = reader.structure()
    safety = _safety_section(reader)
    headers = reader._headers
    n = len(headers)
    witness_pins = [
        headers.seq_at(i) for i in range(n) if headers.record_type_at(i) == RT_WITNESS
    ]
    first_seq = headers.seq_at(0) if n else None
    last_seq = headers.seq_at(n - 1) if n else None
    return ver, boots, spans, safety, witness_pins, first_seq, last_seq


def build_report(
    source: str | Path,
    *,
    anchor_source=None,
    tool: str | None = None,
    reader: AuditReader | None = None,
    health: bool = False,
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
    themselves opened. ``reader`` and ``anchor_source`` together raise
    ``ValueError``: a shared reader answers with the anchor it was opened
    with, so the one passed here could not be honoured — and it used to
    be dropped silently, handing back a report checked against a
    different anchor than the caller named. Pass the anchor when opening
    the reader, or pass no reader.

    ``health`` (since 0.15) fills the report's ``health`` section: a
    summary, of fixed size, of the record's own account of its clocks and
    its anchoring — boots, the widest gap between anchors, wall-clock
    steps, drift, open spans. It is advisory: no figure is a threshold and
    none enters the verdict. Without it the key is ``None``, and nothing
    is computed. See :func:`health_summary`.

    ``reader`` must be open on the same bytes as ``source`` names. This
    is not checked — the caller already holds both and is the only one
    in a position to know they agree; a report built from a mismatched
    pair would name one file's identity over another file's verdict.
    """
    if reader is not None and anchor_source is not None:
        raise ValueError(
            "build_report: pass anchor_source or reader, not both — a shared "
            "reader answers with the anchor it was opened with, so this "
            "anchor_source would be ignored; open the reader with it instead"
        )
    path = Path(source)
    # With a reader supplied, the bytes it already holds (a mapping for
    # ``open()``, the object for ``from_bytes()``) are the bytes; reading
    # the file a second time doubled the resident set for nothing (U14).
    # ``sha256`` and the container walk below take a buffer, so the
    # digest and every count are byte-identical either way.
    #
    # Without a reader the same holds: one is opened here, and the digest is
    # taken over the bytes it holds. The file used to be read whole into
    # memory first and then mapped as well — a second copy of the file for
    # every report made with an anchor.
    # The container walk (K2/K5): §2.4 well-formedness and the body↔header
    # digest binding are attested, not assumed — reader.verify() covers
    # headers, and a body swap is invisible to a header-only chain check.
    # It is the reader's own ``container_check()`` (U21), so a consumer
    # asking the reader and this report can never get two answers.
    if reader is not None:
        ver, boots, spans, safety, witness_pins, first_seq, last_seq = _structure(reader)
        container = reader.container_check()
        subject_sha256 = sha256(reader._data).hexdigest()
        subject_bytes = len(reader._data)
        health_section = health_summary(reader) if health else None
    else:
        with AuditReader.open(path, anchor=anchor_source) as opened:
            ver, boots, spans, safety, witness_pins, first_seq, last_seq = _structure(
                opened
            )
            container = opened.container_check()
            subject_sha256 = sha256(opened._data).hexdigest()
            subject_bytes = len(opened._data)
            health_section = health_summary(opened) if health else None

    chain = ver.chain
    version = palimpsests.__version__

    data = {
        "format": REPORT_FORMAT,
        "subject": {
            "filename": path.name,
            "sha256": subject_sha256,
            "bytes": subject_bytes,
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
            **_note("checked_at"),
        },
        "container": {
            "well_formed": container.well_formed,
            "malformed": container.malformed,
            "bytes_parsed": container.bytes_parsed,
            "bytes_total": container.bytes_total,
            "body_digest_mismatches": list(container.body_digest_mismatches),
        },
        "chain": {
            "chain_ok": chain.chain_ok,
            "head": chain.head.hex(),
            "breaks": list(chain.breaks),
            "gaps": list(chain.gaps),
            "violations": [list(v) for v in chain.violations],
            # Parallel to ``violations``, one entry each, same order: the
            # code is what a consumer branches on, the reason a sentence.
            "violation_codes": [list(v) for v in chain.violation_codes],
            "uninterpretable": list(chain.uninterpretable),
        },
        "anchor": (
            {
                "head": ver.anchor.head.hex(),
                "source_kind": ver.anchor.source_kind,
                # A file anchor is named, not located: the report holds no
                # path of the machine that ran the check (as for ``manifest``).
                "source_detail": _portable_detail(
                    ver.anchor.source_kind, ver.anchor.source_detail),
                "observed_at_ns": None,
                "attempts": [
                    {
                        "source_kind": a.source_kind,
                        "outcome": a.outcome,
                        "error": _portable_error(a.source_kind, a.source_detail, a.error),
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
            # What was checked, not what a tier allows: external_pins are
            # the WITNESS records in this chain, and the tier is never read
            # here — a tier-A head can be registered and receipted.
            **_note("existence_witness_present" if witness_pins else "existence_no_witness"),
        },
        "diagnosis": (
            {
                "pattern": ver.diagnosis.pattern,
                "at_seq": ver.diagnosis.at_seq,
                "expected": ver.diagnosis.expected,
                "narrative": ver.diagnosis.narrative,
                "code": ver.diagnosis.code,
                # Which question the diagnosis is about: a finding about the
                # anchor is not a finding about the chain (reader's
                # DIAGNOSIS_QUESTIONS).
                "question": ver.diagnosis.question,
            }
            if ver.diagnosis is not None
            else None
        ),
        # The second file a diagnosis rested on (U17): named, with the status
        # it decided and the digest of the bytes that were read. ``None``
        # means the verdict read no second file. The name alone, like the
        # subject's: the manifest sits beside the container, and a path
        # would put the auditing machine's directories into the report.
        "manifest": (
            {
                "filename": (
                    Path(ver.manifest.path).name if ver.manifest.path is not None else None
                ),
                "status": ver.manifest.status,
                "sha256": (
                    ver.manifest.sha256.hex() if ver.manifest.sha256 is not None else None
                ),
                "detail": ver.manifest.detail,
            }
            if ver.manifest is not None
            else None
        ),
        "advisory": {
            "count": len(ver.advisory.items),
            "items": [
                {"code": i.code, "at_seq": i.at_seq, "detail": i.detail}
                for i in ver.advisory.items
            ],
            **_note("advisory"),
        },
        "safety": safety,
        # Advisory, and only when asked for (``health=True``): ``None``
        # means it was not computed, never that the record is healthy.
        "health": health_section,
        "time_basis": {
            "axis": "proved-order",
            "wall_claims_qualified_by": "time_trust",
            "caveats": [],
        },
    }
    data["verdict"] = derive_verdict(data)
    return VerificationReport(data=data)
