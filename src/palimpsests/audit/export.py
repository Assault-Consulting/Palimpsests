# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``pala2json`` — the inspectability converter the specification promises.

Core §1.1 rules JSON out of the *hashing contract* (a binary format has
no canonicalisation step; serialisation is canonicalisation) and
recovers inspectability "with a converter (``pala2json``), which is a
tool, not part of the hashing contract". This module is that tool, and
``pala-jsonl/1`` is its format (``docs/specs/export/pala-jsonl-1.md``).

Three properties are load-bearing:

- **Derived, never authoritative.** The export carries no signature and
  enters no hash. Every line names its record by ``seq`` *and*
  ``record_hash``, so any claim made about an exported line can be taken
  back to the binary record it came from and re-verified there. The
  summary line says this in words; the design says it in structure.
- **What a line shows is what its hash covers — or the line says not.**
  ``record_hash`` is over the header, and the header binds the body by
  ``body_digest``. A body that no longer matches that digest is exported
  all the same — inspecting broken evidence is half the point — but its
  line carries ``body_digest_mismatch`` and the summary lists its seq.
  Before 0.15 such a body was printed without a word under a summary
  that said ``chain_ok``.
- **Deterministic for one version of the tool.** Same container bytes →
  same export bytes: key order is fixed by construction, no timestamp of
  the export is embedded, and values render in one way only. The
  summary's ``tool`` names the version, so two versions differ in that
  field; compare exports with it set aside.

The exporter is a reader: it decodes with the same shared
:func:`~palimpsests.audit.reader.decode_record` the facade and the
tailing reader use, and checks with the same §7.1 verifier and the same
body-digest rule ``pala verify`` applies — one record at a time, keeping
none, so its memory does not grow with the chain. It exports damaged
chains as readily as green ones, a container cut mid-record included:
the whole records before the cut are exported and the summary says where
the walk stopped. Unknown record types and unknown kinds export as their
numbers (§7.6: reported, never rejected).
"""
from __future__ import annotations

import json
from hashlib import sha256
from palimpsests import __version__
from palimpsests.audit.pala import KNOWN_RECORD_TYPES, MalformedRecord, body_digest_of, iter_records
from palimpsests.audit.pala.codec import record_hash
from palimpsests.audit.pala.incremental import IncrementalVerifier
from palimpsests.audit.reader import decode_record
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from mmap import mmap

    #: What ``export_jsonl`` reads: anything that slices to bytes. A consumer
    #: exporting a large file passes its mapping, not a copy of the file.
    Buffer = bytes | bytearray | memoryview | mmap

__all__ = ["FORMAT", "export_jsonl"]

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


def _line(dr, hb: bytes, body_len: int, body_matches: bool) -> dict[str, object]:
    """One record as its export line. Keys appear in a fixed order, and a
    key that says nothing for this record is left out rather than null —
    except the four every line carries after the header fields."""
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
    # What the reader decodes from the body, the line carries — so a consumer
    # of the export never has to read a TLV's hex to learn a tool's outcome.
    # Each group appears only where the record has it, as ``source`` does.
    if dr.source is not None:
        # r5 evidence mark on kinds 8/9; 0 is stated, not implied,
        # because "parsed from the wire" is itself a claim.
        line["source"] = dr.source
        line["source_name"] = dr.source_name
    if dr.outcome is not None:
        # r3/r6: "ok" is a return, never a success; "unobserved" is a return
        # whose failure the recording vantage could not see.
        line["outcome"] = dr.outcome
        line["outcome_name"] = dr.outcome_name
    if dr.disposition is not None:
        line["disposition"] = dr.disposition
        line["disposition_name"] = dr.disposition_name
    if dr.operator_id is not None:
        line["operator_id"] = dr.operator_id.hex()
    if dr.detail is not None:
        line["detail"] = dr.detail
    line["body_len"] = body_len
    if body_len:
        if dr.body_tlvs is not None:
            line["body_tlvs"] = _tlv_list(dr.body_tlvs)
        else:
            # Encrypted (key_id != 0) or undecodable: present, opaque.
            line["body_opaque"] = True
        if not body_matches:
            # The header's body_digest does not name these bytes: what this
            # line shows of the body is not what its record_hash covers.
            line["body_digest_mismatch"] = True
    return line


def export_jsonl(
    data: Buffer,
    out: TextIO,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
) -> int:
    """Write the JSONL export of one container; return the record count.

    One line per record, in chain order, then one summary line. Never
    raises on a damaged chain or a damaged container: the summary carries
    what the check found — ``chain_ok``, ``well_formed``,
    ``body_digest_mismatches`` and, in one word, ``consistent`` — and the
    per-record lines carry whatever decoded. The tool's job is to show
    the evidence, not to gate it. Completeness against an anchor is not
    checked here, and the summary says so.

    ``data`` is any bytes-like object: ``bytes``, or a file's ``mmap``.
    Records are read, written and forgotten one at a time.

    *from_seq* and *to_seq* are inclusive bounds: only records whose
    ``seq`` satisfies ``from_seq <= seq <= to_seq`` are emitted.  When
    omitted the full log is exported (the default).  The summary line is
    always emitted regardless of range filtering, and always describes
    the whole container.
    """
    verifier = IncrementalVerifier(known_types=KNOWN_RECORD_TYPES)
    exported = 0
    bytes_parsed = 0
    mismatches: list[int] = []
    malformed: str | None = None
    try:
        for index, (hb, body) in enumerate(iter_records(data)):
            verifier.step(hb)  # a no-op once the verifier has halted
            bytes_parsed += len(hb) + len(body)
            dr = decode_record(index, hb, body)
            # The same rule `pala verify` and the report apply: an empty body
            # has nothing to bind; the digest sits at a frozen offset (§2.1).
            body_matches = not body or body_digest_of(body) == hb[124:156]
            if not body_matches:
                mismatches.append(dr.seq)
            if from_seq is not None and dr.seq < from_seq:
                continue
            if to_seq is not None and dr.seq > to_seq:
                continue
            line = _line(dr, hb, len(body), body_matches)
            out.write(json.dumps(line, separators=(",", ":")) + "\n")
            exported += 1
    except MalformedRecord as e:
        # A container defect (§2.4): record boundaries cannot be trusted past
        # this point. Everything walked before it has been exported.
        malformed = str(e)

    res = verifier.result()
    summary: dict[str, object] = {
        "summary": True,
        "format": FORMAT,
        "records": res.count,
        "chain_head": res.head.hex(),
        "chain_ok": res.chain_ok,
        "breaks": res.breaks,
        "gaps": res.gaps,
        "violations": [[seq, reason] for seq, reason in res.violations],
        "violation_codes": [[seq, code] for seq, code in res.violation_codes],
        "well_formed": malformed is None,
        "malformed": malformed,
        "bytes_parsed": bytes_parsed,
        "bytes_total": len(data),
        "body_digest_mismatches": mismatches,
        # `pala verify`'s consistency, by the same rule — so the two tools
        # cannot give different answers about one file.
        "consistent": res.chain_ok and malformed is None and not mismatches,
        # No anchor is read here: truncation or wholesale replacement of the
        # log would not show in this export.
        "completeness_checked": False,
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
