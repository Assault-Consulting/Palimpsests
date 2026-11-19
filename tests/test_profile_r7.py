# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Inference profile r7: the telemetry source mark, and the open issues closed.

r7 adds one value — ``EVT_SOURCE = 2``, a pair written from an exported
telemetry span — and writes down what the writer already did, so that the
profile and the code say one thing: a ``MERKLE`` record is a checkpoint
whose leaves are record hashes (§10), where r1–r6 said an inference chain
should not emit one while the writer has since 0.10.
"""
from __future__ import annotations

import json
import pytest
import re
import struct
from palimpsests.audit.pala import iter_records, vectors
from palimpsests.audit.pala.checkpoints import merkle_checkpoint
from palimpsests.audit.pala.codec import (
    RT_MERKLE,
    TLV_MERKLE_LEAF_COUNT,
    TLV_MERKLE_TREE_HASH,
    Header,
    decode_tlvs,
    record_hash,
)
from palimpsests.audit.pala.merkle import merkle_root
from palimpsests.audit.pala_writer import (
    OUTCOME_ERROR,
    SOURCE_DERIVED_FROM_TELEMETRY,
    SOURCE_PARSED_FROM_WIRE,
    SOURCE_REPORTED_BY_CLIENT,
    PalaWriter,
    canonical_config_digest,
)
from palimpsests.audit.profiles.inference import EVT_KIND, EVT_SOURCE
from palimpsests.audit.reader import AuditReader
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILE = (ROOT / "docs" / "specs" / "pala-1" / "profiles" / "inference.md").read_text(
    encoding="utf-8")


# -- EVT_SOURCE = 2 -----------------------------------------------------------

def test_the_three_sources_are_0_1_2_and_only_the_default_is_absent(tmp_path):
    assert (SOURCE_PARSED_FROM_WIRE, SOURCE_REPORTED_BY_CLIENT,
            SOURCE_DERIVED_FROM_TELEMETRY) == (0, 1, 2)
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        for source in (0, 1, 2):
            seq, call = w.tool_call("t", source=source, return_seq=True)
            w.tool_result(seq, call, OUTCOME_ERROR, source=source)
        with pytest.raises(ValueError, match="source must be"):
            w.tool_call("t", source=3)
    bodies = [dict(decode_tlvs(body)) for _hb, body in iter_records(log.read_bytes()) if body]
    pairs = [t for t in bodies if struct.unpack("<H", t[EVT_KIND])[0] in (8, 9)]
    marks = [struct.unpack("<H", t[EVT_SOURCE])[0] if EVT_SOURCE in t else None for t in pairs]
    assert marks == [None, None, 1, 1, 2, 2]  # value 0 is written as absence
    with AuditReader.open(log) as reader:
        pairs = [d for d in reader.records() if d.source is not None]
    assert [d.source_name for d in pairs] == [
        "parsed-from-wire"] * 2 + ["reported-by-client"] * 2 + ["derived-from-telemetry"] * 2


def test_a_wire_parsed_record_is_the_same_bytes_as_before_r7(tmp_path):
    """Absent still means 0: adding a value did not move a byte of the default."""
    def body(source):
        log = tmp_path / f"{source}.pala"
        with PalaWriter(log, boot_id=b"\x07" * 16, lifecycle=False) as w:
            w.genesis()
            w.tool_call("t", args_digest=b"\x01" * 32, source=source)
        return [b for _h, b in iter_records(log.read_bytes())][-1]

    default, reported, telemetry = body(0), body(1), body(2)
    assert EVT_SOURCE not in dict(decode_tlvs(default))
    assert len(reported) == len(telemetry) == len(default) + 6  # one u16 TLV
    assert reported != telemetry


def test_the_vectors_carry_the_telemetry_pair_and_the_reader_decodes_it(tmp_path):
    doc = vectors.load("inference")
    assert doc["profile_revision"] in ("r7", "r8", "r9") and len(doc["records"]) >= 24
    call, result = doc["semantics"]["21"], doc["semantics"]["22"]
    assert (call["source"], call["source_name"]) == (2, "derived-from-telemetry")
    assert (result["source"], result["outcome_name"], result["ref_seq"]) == (2, "error", 21)
    labels = [r["label"] for r in doc["records"]]
    assert labels[21:24] == ["tool_call_from_telemetry", "tool_result_from_telemetry",
                             "anchor_r7"]
    assert doc["chain_head"] == doc["records"][-1]["record_hash"]


def test_every_record_before_r7_is_the_bytes_r6_published():
    """The r6 head is the hash the r6 anchor noted, and it is still there."""
    doc = vectors.load("inference")
    r6 = doc["records"][:21]
    assert r6[-1]["label"] == "anchor_r6"
    prev = None
    for rec in doc["records"]:
        header = bytes.fromhex(rec["header_hex"])
        assert record_hash(header).hex() == rec["record_hash"]
        if prev is not None:
            assert Header.decode(header).prev_hash.hex() == prev
        prev = rec["record_hash"]
    # pinned: the head of the 21-record r6 chain, as r6 published it
    assert r6[-1]["record_hash"] == Header.decode(
        bytes.fromhex(doc["records"][21]["header_hex"])).prev_hash.hex()


def test_the_telemetry_route_writes_value_2():
    source = (ROOT / "src" / "palimpsests" / "server" / "otel_traces.py").read_text(
        encoding="utf-8")
    assert "SOURCE_DERIVED_FROM_TELEMETRY" in source
    assert "SOURCE_REPORTED_BY_CLIENT" not in source


def test_the_doctor_accepts_either_mark_from_the_traces_route_and_one_from_the_rest():
    from palimpsests import doctor

    class Http:
        def __init__(self, source):
            self.source = source

        def post(self, route, headers=None, json=None, content=None):
            would = [{"record": "TOOL_CALL", "source": self.source},
                     {"record": "TOOL_RESULT", "source": self.source, "outcome": "ok"}]
            return type("R", (), {"status_code": 200,
                                  "json": lambda self: {"dry_run": True,
                                                        "would_record": would}})()

    def code(integration, source):
        return doctor._dry_run(Http(source), "k", integration)[0].code

    assert code("otel", "derived-from-telemetry") == "dry_run_ok"
    assert code("otel", "reported-by-client") == "dry_run_ok"  # a serve older than 0.15
    assert code("otel", "parsed-from-wire") == "dry_run_wrong_source"
    assert code("litellm", "reported-by-client") == "dry_run_ok"
    assert code("litellm", "derived-from-telemetry") == "dry_run_wrong_source"


# -- §10: a MERKLE record is a checkpoint over record hashes ------------------

def test_a_checkpoint_is_what_section_10_says(tmp_path):
    log = tmp_path / "w.pala"
    with PalaWriter(log) as w:
        w.genesis()
        for size in (3, 5, 1):
            for _ in range(size):
                w.prefix_warm(token_count=1)
            merkle_checkpoint(w)
        w.prefix_warm(token_count=1)  # a tail no checkpoint covers
    records = list(iter_records(log.read_bytes()))
    # GENESIS and the writer's WRITER_OPEN (r8) are leaves like any record
    hashes = [record_hash(hb) for hb, _ in records]
    types = [struct.unpack_from("<H", hb, 8)[0] for hb, _ in records]
    merkles = [i for i, t in enumerate(types) if t == RT_MERKLE]
    assert len(merkles) == 3

    start = 0  # the first window starts at seq 0
    for at in merkles:
        header, body = records[at]
        assert body == b"" and Header.decode(header).body_len == 0
        tlvs = dict(decode_tlvs(header[156:]))
        (count,) = struct.unpack("<I", tlvs[TLV_MERKLE_LEAF_COUNT])
        # every record after the previous checkpoint, that checkpoint included,
        # up to but not including this one
        assert count == at - start
        assert tlvs[TLV_MERKLE_TREE_HASH] == merkle_root(hashes[start:at])
        start = at  # each checkpoint is the first leaf of the next window
    assert start < len(records) - 1  # the tail is in no window


def test_the_profile_no_longer_says_not_to_emit_what_the_writer_emits():
    assert "SHOULD NOT emit" not in PROFILE.split("## 9. Revision history")[0].split(
        "## 6. Open issues")[0]
    section = PROFILE.split("## 10. `MERKLE`", 1)[1]
    for phrase in ("record hashes", "that record included", "`seq` 0",
                   "MERKLE_LEAF_COUNT", "`body_len = 0`"):
        assert phrase in section, phrase


# -- the issues, closed -------------------------------------------------------

def test_every_issue_of_section_6_is_closed_and_the_revision_is_r7():
    assert re.search(r"\| \*\*Revision\*\* \| \*\*r[789]\*\* \(", PROFILE)
    section = PROFILE.split("## 6. Open issues (profile)", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if re.match(r"\| \d \|", line)]
    assert [row[2] for row in rows] == list("12345")
    assert all(len(row.split("|")) == 5 and row.split("|")[3].strip() for row in rows)
    assert "None is open as of r7" in section
    assert re.search(r"^\| r7 \| 2026-11-19 \|", PROFILE, re.M)


def test_the_profile_names_the_canonical_form_and_both_digests_use_it():
    section = PROFILE.split("## 11. The canonical form of a JSON value", 1)[1]
    assert "RFC 8785" in section and "UTF-16 code unit" in section
    rows = PROFILE.split("## 6. Open issues (profile)", 1)[1].split("\n## ", 1)[0]
    assert rows.count("RFC 8785 (§11)") == 2  # issues 2 and 4
    from hashlib import sha256
    from palimpsests.audit.canonical_json import canonical_json
    from palimpsests.audit.pala_writer import canonical_tool_args_digest

    value = {"b": 1.0, "a": {"z": [1e21, None]}}
    form = canonical_json(value)
    assert form == b'{"a":{"z":[1e+21,null]},"b":1}'
    assert canonical_config_digest(value) == canonical_tool_args_digest(value) == sha256(
        form).digest()


def test_the_packaged_vectors_are_the_published_file():
    published = json.loads((ROOT / "docs" / "specs" / "pala-1" / "profiles" /
                            "inference-vectors.json").read_text(encoding="utf-8"))
    assert vectors.load("inference") == published
