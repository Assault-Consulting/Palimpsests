# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``pala2json`` — the inspectability converter the specification promises.

Core §1.1 rules JSON out of the *hashing contract* (a binary format has
no canonicalisation step; serialisation is canonicalisation) and
recovers inspectability "with a converter (``pala2json``), which is a
tool, not part of the hashing contract". This module is that tool.

Two properties are load-bearing:

- **Derived, never authoritative.** The export carries no signature and
  enters no hash. Every line names its record by ``seq`` *and*
  ``record_hash``, so any claim made about an exported line can be taken
  back to the binary record it came from and re-verified there. The
  summary line says this in words; the design says it in structure.
- **Deterministic.** Same container bytes → same export bytes: key order
  is fixed by construction, no timestamp of the export is embedded, and
  values render in one way only. A diff between two exports is a diff
  between two *logs*, never between two runs of the tool.

The exporter is a reader: it decodes with the same shared
:func:`~palimpsests.audit.reader.decode_record` the facade and the
tailing reader use, verifies with the same ``verify_headers`` any
auditor runs, and exports damaged chains as readily as green ones —
inspecting broken evidence is half the point. Unknown record types and
unknown kinds export as their numbers (§7.6: reported, never rejected).
"""
from __future__ import annotations

import json
from hashlib import sha256
from palimpsests import __version__
from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.codec import record_hash
from palimpsests.audit.reader import decode_record
from typing import TextIO

FORMAT = "pala-jsonl/1"

_AUTHORITATIVE_NOTE = (
    "derived output; the binary PALA-1 log is authoritative — "
    "re-verify any claim against it (core §1.1)"
)


def _hex_or_none(b: bytes) -> str | None:
    """Render an id field: hex, or ``None`` for the all-zero sentinel."""
    return b.hex() if any(b) else None


def _tlv_list(tlvs: list[tuple[int, bytes]]) -> list[dict[str, str]]:
    return [{"tag": f"0x{t:04x}", "value_hex": v.hex()} for t, v in tlvs]


def export_jsonl(
    data: bytes,
    out: TextIO,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
) -> int:
    """Write the JSONL export of one container; return the record count.

    One line per record, in chain order, then one summary line. Never
    raises on a damaged chain: the summary carries ``chain_ok`` and the
    per-record lines carry whatever decoded — the tool's job is to show
    the evidence, not to gate it.

    *from_seq* and *to_seq* are inclusive bounds: only records whose
    ``seq`` satisfies ``from_seq <= seq <= to_seq`` are emitted.  When
    omitted the full log is exported (the default).  The summary line is
    always emitted regardless of range filtering.
    """
    headers: list[bytes] = []
    decoded = []
    for index, (hb, body) in enumerate(iter_records(data)):
        headers.append(hb)
        decoded.append((decode_record(index, hb, body), hb, len(body)))

    exported = 0
    for dr, hb, body_len in decoded:
        if from_seq is not None and dr.seq < from_seq:
            continue
        if to_seq is not None and dr.seq > to_seq:
            continue
        line: dict[str, object] = {
            "seq": dr.seq,
            "record_hash": record_hash(hb).hex(),
            "record_type": f"0x{dr.record_type:04x}",
            "type_name": dr.type_name,
        }
        if dr.header is not None:
            h = dr.header
            line.update(
                {
                    "boot_id": h.boot_id.hex(),
                    "span_id": _hex_or_none(h.span_id),
                    "parent_span_id": _hex_or_none(h.parent_span_id),
                    "assurance_tier": h.assurance_tier,
                    "time_trust": h.time_trust,
                    "monotonic_ns": h.monotonic_ns,
                    "wall_clock_ns": h.wall_clock_ns,
                    "key_id": h.key_id,
                    "header_tlvs": _tlv_list(h.tlvs),
                }
            )
        else:
            line["header_undecoded"] = True
        line["kind"] = dr.kind
        line["kind_name"] = dr.kind_name
        if dr.source is not None:
            # r5 evidence mark on kinds 8/9; 0 is stated, not implied,
            # because "parsed from the wire" is itself a claim.
            line["source"] = dr.source
            line["source_name"] = dr.source_name
        line["body_len"] = body_len
        if body_len:
            if dr.body_tlvs is not None:
                line["body_tlvs"] = _tlv_list(dr.body_tlvs)
            else:
                # Encrypted (key_id != 0) or undecodable: present, opaque.
                line["body_opaque"] = True
        out.write(json.dumps(line, separators=(",", ":")) + "\n")
        exported += 1

    res = verify_headers(headers)
    summary: dict[str, object] = {
        "summary": True,
        "format": FORMAT,
        "records": res.count,
        "chain_head": res.head.hex(),
        "chain_ok": res.chain_ok,
        "breaks": res.breaks,
        "gaps": res.gaps,
        "violations": [[seq, reason] for seq, reason in res.violations],
        "source_sha256": sha256(data).hexdigest(),
        "tool": f"palimpsests {__version__}",
        "note": _AUTHORITATIVE_NOTE,
    }
    if from_seq is not None:
        summary["from_seq"] = from_seq
    if to_seq is not None:
        summary["to_seq"] = to_seq
    out.write(json.dumps(summary, separators=(",", ":")) + "\n")
    return exported
