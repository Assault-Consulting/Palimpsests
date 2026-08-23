# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""WS-R — ``pala segment``: retention needs a knife that keeps the proof.

Article 12 logging plus a six-month duty (docs/RETENTION.md) means
chains grow for months; retention means old bytes eventually leave.
Deleting a prefix of a monolithic file destroys verifiability of what
remains. Segmentation is the honest cut: split at record boundaries
into fixed-size segments plus one manifest, so that

- every segment verifies **alone**, seeded with its predecessor's head
  from the manifest (``verify_headers(..., start_prev=...)``) — the
  seam between segments is itself a checked link, not a convention;
- deleting expired segments keeps the rest verifiable: the manifest
  retains every head, so the surviving tail still proves it continues
  a specific, named history — "predecessor deleted under retention" is
  distinguishable from "predecessor missing";
- concatenating all segments reproduces the source byte-for-byte —
  the cut adds nothing, removes nothing, re-encodes nothing.

The manifest is derived and unsigned, like the export and the bundle:
the segments stay authoritative, and every claim in it re-verifies
from the bytes.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala.codec import ZERO32
from palimpsests.audit.pala.codec import record_hash as _record_hash
from pathlib import Path

SEGMENTS_FORMAT = "pala-segments/1"


@dataclass(frozen=True)
class SegmentInfo:
    file: str
    first_seq: int
    last_seq: int
    records: int
    head: str  # hex — this segment's last record hash
    prev_head: str  # hex — the predecessor's head; ZERO32 for the first


@dataclass(frozen=True)
class SegmentResult:
    manifest_path: Path
    segments: list[SegmentInfo]
    source_head: str


def segment_chain(
    source: str | Path,
    out_dir: str | Path,
    *,
    records_per_segment: int,
) -> SegmentResult:
    """Split ``source`` into segments of ``records_per_segment`` records.

    Cuts strictly at record boundaries; writes ``segment-*.pala`` files
    and ``segments.json`` into ``out_dir``. Deterministic: same source,
    same size, same tool version → identical files and manifest.
    """
    if records_per_segment < 1:
        raise ValueError("records_per_segment must be >= 1")
    src = Path(source)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()

    infos: list[SegmentInfo] = []
    buf: list[bytes] = []
    first_seq: int | None = None
    last_seq = 0
    prev_head = ZERO32.hex()
    head = ZERO32.hex()

    def _flush() -> None:
        nonlocal buf, first_seq, prev_head
        if not buf or first_seq is None:
            return
        name = f"segment-{len(infos):05d}-seq{first_seq}-{last_seq}.pala"
        (out / name).write_bytes(b"".join(buf))
        infos.append(
            SegmentInfo(
                file=name,
                first_seq=first_seq,
                last_seq=last_seq,
                records=len(buf),
                head=head,
                prev_head=prev_head,
            )
        )
        prev_head = head
        buf, first_seq = [], None

    for hb, body in iter_records(data):
        (seq,) = struct.unpack_from("<Q", hb, 12)
        if first_seq is None:
            first_seq = seq
        last_seq = seq
        buf.append(hb + body)
        head = _record_hash(hb).hex()
        if len(buf) >= records_per_segment:
            _flush()
    _flush()

    import palimpsests

    manifest = {
        "format": SEGMENTS_FORMAT,
        "tool": {"name": "palimpsests", "version": palimpsests.__version__},
        "source_head": infos[-1].head if infos else ZERO32.hex(),
        "records_per_segment": records_per_segment,
        "segments": [
            {
                "file": i.file,
                "first_seq": i.first_seq,
                "last_seq": i.last_seq,
                "records": i.records,
                "head": i.head,
                "prev_head": i.prev_head,
            }
            for i in infos
        ],
    }
    manifest_path = out / "segments.json"
    manifest_path.write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    )
    return SegmentResult(
        manifest_path=manifest_path,
        segments=infos,
        source_head=manifest["source_head"],
    )
