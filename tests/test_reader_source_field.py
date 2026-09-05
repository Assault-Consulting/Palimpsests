# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The r5 evidence mark, named on the decoded record and in the export.

``EVT_SOURCE`` on kinds 8/9: 0 parsed-from-wire, 1 reported-by-client,
absent means 0. The reader states the 0 explicitly on those two kinds —
"parsed from the wire" is a claim, not the absence of one — and leaves
the field ``None`` on every other kind, where the mark has no meaning.
Pinned on the companion vectors (seq 8/9 wire-parsed, seq 14/15
reported) and on writer output, and the export carries the same two
fields only where the record does.
"""
from __future__ import annotations

import io
import json
from palimpsests.audit.export import export_jsonl
from palimpsests.audit.pala_writer import (
    SOURCE_PARSED_FROM_WIRE,
    SOURCE_REPORTED_BY_CLIENT,
    PalaWriter,
)
from palimpsests.audit.reader import AuditReader
from pathlib import Path

VECTORS = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "specs"
    / "pala-1"
    / "profiles"
    / "inference-vectors.json"
)


def _vectors_blob() -> bytes:
    v = json.loads(VECTORS.read_text())
    return b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in v["records"]
    )


def test_vectors_decode_the_mark_and_the_default(tmp_path):
    r = AuditReader.from_bytes(_vectors_blob())
    by_seq = {dr.seq: dr for dr in r.records()}
    assert (by_seq[8].source, by_seq[8].source_name) == (0, "parsed-from-wire")
    assert (by_seq[9].source, by_seq[9].source_name) == (0, "parsed-from-wire")
    assert (by_seq[14].source, by_seq[14].source_name) == (1, "reported-by-client")
    assert (by_seq[15].source, by_seq[15].source_name) == (1, "reported-by-client")
    # no meaning outside kinds 8/9: None, not 0
    assert by_seq[12].source is None and by_seq[12].source_name is None  # kind 10
    assert by_seq[10].source is None  # SAFETY 104
    assert by_seq[4].source is None  # INCIDENT_CANDIDATE
    assert by_seq[3].source is None  # encrypted body


def test_writer_output_round_trips_both_sources(tmp_path):
    log = tmp_path / "s.pala"
    with PalaWriter(log) as w:
        w.genesis()
        w.boot()
        c1 = w.tool_call("fs.read", args_digest=b"\x01" * 32)
        w.tool_result(w.seq - 1, c1, 0, result_digest=b"\x02" * 32)
        c2 = w.tool_call("fs.read", args_digest=b"\x01" * 32, source=SOURCE_REPORTED_BY_CLIENT)
        w.tool_result(
            w.seq - 1, c2, 0, result_digest=b"\x02" * 32, source=SOURCE_REPORTED_BY_CLIENT
        )
    r = AuditReader.open(log)
    recs = list(r.records())[-4:]
    assert [d.source for d in recs] == [
        SOURCE_PARSED_FROM_WIRE,
        SOURCE_PARSED_FROM_WIRE,
        SOURCE_REPORTED_BY_CLIENT,
        SOURCE_REPORTED_BY_CLIENT,
    ]
    assert [d.source_name for d in recs] == [
        "parsed-from-wire",
        "parsed-from-wire",
        "reported-by-client",
        "reported-by-client",
    ]
    r.close()


def test_export_carries_source_only_where_the_record_does():
    out = io.StringIO()
    export_jsonl(_vectors_blob(), out)
    lines = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    by_seq = {ln["seq"]: ln for ln in lines if "seq" in ln}
    assert by_seq[8]["source"] == 0 and by_seq[8]["source_name"] == "parsed-from-wire"
    assert by_seq[14]["source"] == 1 and by_seq[14]["source_name"] == "reported-by-client"
    assert by_seq[15]["source"] == 1
    assert "source" not in by_seq[12] and "source" not in by_seq[4]
