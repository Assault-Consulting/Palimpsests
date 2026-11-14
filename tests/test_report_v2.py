# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``pala-verification-report/2``: what the format id moved for.

Five things changed together, so the id moves once: a chain violation
carries its code; the diagnosis of a record violation carries it too; the
segments manifest a diagnosis rested on is named and hashed; a container
with no records has its own verdict; and the format is open to added keys.
``/1`` is no longer written, and a ``/1`` report already on disk — the
repository holds real ones, in its run records — must stay readable.
"""
from __future__ import annotations

import json
import os
import pytest
import struct
import tomllib
from hashlib import sha256
from palimpsests.audit.anchors import ManualAnchor
from palimpsests.audit.pala_writer import PalaWriter, RotationPolicy
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.report import (
    REPORT_FORMAT,
    REPORT_FORMAT_1,
    VERDICTS,
    build_report,
    derive_verdict,
)
from palimpsests.audit.report_html import render_html
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "docs" / "specs" / "report"
STORED_V1 = sorted(
    (ROOT / "docs" / "specs" / "pala-1" / "independent-runs").rglob("*-report.json")
)
runner = CliRunner()


def _schema(n: int) -> dict:
    return json.loads(
        (SCHEMAS / f"pala-verification-report-{n}.schema.json").read_text(encoding="utf-8")
    )


def _validate(data: dict, n: int = 2) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(data, _schema(n))


def _chain(tmp_path, name="w.pala"):
    p = tmp_path / name
    with PalaWriter(p) as w:
        w.genesis()
        w.boot()
        w.boot()
    return p


def _head(p) -> str:
    with AuditReader.open(p) as r:
        return r.verify().chain.head.hex()


# ── the format ──────────────────────────────────────────────────────────────


def test_the_report_is_written_as_2_and_validates(tmp_path):
    data = build_report(_chain(tmp_path)).data
    assert data["format"] == REPORT_FORMAT == "pala-verification-report/2"
    _validate(data)


def test_a_2_report_is_not_a_1_report(tmp_path):
    """Why the id had to move: the ``/1`` schema is closed, so every added
    key fails a consumer that validates against the schema it holds."""
    jsonschema = pytest.importorskip("jsonschema")
    data = build_report(_chain(tmp_path)).data
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, _schema(1))


def test_the_format_is_open_to_added_keys_and_closed_on_what_it_names(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    data = build_report(_chain(tmp_path)).data
    grown = json.loads(json.dumps(data))
    grown["a_key_from_a_later_release"] = 1
    grown["chain"]["another"] = []
    _validate(grown)  # a key this schema does not name is not an error

    for damage in (
        lambda d: d.pop("manifest"),
        lambda d: d["chain"].pop("violation_codes"),
        lambda d: d.__setitem__("verdict", "fine"),
        lambda d: d.__setitem__("format", REPORT_FORMAT_1),
    ):
        broken = json.loads(json.dumps(data))
        damage(broken)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(broken, _schema(2))


def test_the_verdict_set_is_the_schemas(tmp_path):
    assert sorted(VERDICTS) == sorted(_schema(2)["properties"]["verdict"]["enum"])


def test_both_schemas_ship_in_the_wheel():
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    included = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for n in (1, 2):
        name = f"pala-verification-report-{n}.schema.json"
        assert included[f"docs/specs/report/{name}"] == f"palimpsests/audit/_schemas/{name}"
        assert (SCHEMAS / name).is_file()


# ── violation codes ─────────────────────────────────────────────────────────


def _violated(tmp_path):
    """The last record's time-trust byte set to an undefined value."""
    p = _chain(tmp_path, "before-damage.pala")
    raw = bytearray(p.read_bytes())
    with AuditReader.open(p) as r:
        n = r.record_count
        last = sum(len(r.record_bytes_at(i).header) + len(r.record_bytes_at(i).body)
                   for i in range(n - 1))
    struct.pack_into("B", raw, last + 11, 9)
    q = tmp_path / "violated.pala"
    q.write_bytes(bytes(raw))
    return q


def test_violations_carry_their_codes_in_parallel(tmp_path):
    data = build_report(_violated(tmp_path)).data
    chain = data["chain"]
    assert chain["violations"], "the fixture must violate something"
    assert len(chain["violation_codes"]) == len(chain["violations"])
    for (seq, reason), (cseq, code) in zip(
        chain["violations"], chain["violation_codes"], strict=True
    ):
        assert seq == cseq
        assert isinstance(reason, str) and " " in reason  # a sentence
        assert code == "time_trust_undefined"  # a code: what to branch on
    assert data["diagnosis"]["pattern"] == "record_violation"
    assert data["diagnosis"]["code"] == "time_trust_undefined"
    assert data["verdict"] == "violation"
    _validate(data)


def test_the_report_and_the_reader_name_the_same_codes(tmp_path):
    p = _violated(tmp_path)
    with AuditReader.open(p) as r:
        expected = [list(v) for v in r.verify().chain.violation_codes]
    assert build_report(p).data["chain"]["violation_codes"] == expected


def test_a_sound_chain_has_no_codes_and_no_diagnosis_code(tmp_path):
    data = build_report(_chain(tmp_path)).data
    assert data["chain"]["violation_codes"] == []
    assert data["diagnosis"] is None or data["diagnosis"]["code"] is None


# ── the manifest's identity ─────────────────────────────────────────────────


def _survivor(tmp_path):
    """A rotated chain with every segment but the last removed."""
    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=4, retention_s=15_552_000))
    w.genesis()
    for _ in range(13):
        w.prefix_warm(token_count=1)
    w.close()
    segs = [base] + sorted(tmp_path.glob("w.pala.0*"))
    for old in segs[:-1]:
        os.remove(old)
    return segs[-1], tmp_path / "w.pala.segments.json"


def test_the_manifest_a_diagnosis_rested_on_is_named_and_hashed(tmp_path):
    last, mf = _survivor(tmp_path)
    data = build_report(last).data
    assert data["diagnosis"]["pattern"] == "declared_continuation"
    assert data["manifest"] == {
        "filename": mf.name,
        "status": "matches",
        "sha256": sha256(mf.read_bytes()).hexdigest(),
        "detail": None,
    }
    _validate(data)


def test_the_manifest_block_agrees_with_the_reader(tmp_path):
    last, _mf = _survivor(tmp_path)
    with AuditReader.open(last) as r:
        m = r.verify().manifest
    block = build_report(last).data["manifest"]
    assert (block["status"], block["sha256"], block["detail"]) == (
        m.status, m.sha256.hex(), m.detail)
    assert block["filename"] == Path(m.path).name


def test_a_contradicting_manifest_is_named_with_the_bytes_that_contradicted(tmp_path):
    last, mf = _survivor(tmp_path)
    doc = json.loads(mf.read_text())
    doc["segments"][-1]["head"] = "ab" * 32
    mf.write_text(json.dumps(doc))
    data = build_report(last).data
    assert data["diagnosis"]["pattern"] == "continuation_contradicts_manifest"
    assert data["manifest"]["status"] == "contradicts"
    assert data["manifest"]["sha256"] == sha256(mf.read_bytes()).hexdigest()
    _validate(data)


def test_a_manifest_that_is_not_there_is_named_and_not_hashed(tmp_path):
    last, mf = _survivor(tmp_path)
    mf.unlink()
    block = build_report(last).data["manifest"]
    assert block["filename"] == mf.name and block["status"] == "declared_only"
    assert block["sha256"] is None and block["detail"]
    _validate(build_report(last).data)


def test_a_chain_that_reads_no_second_file_has_no_manifest_block(tmp_path):
    assert build_report(_chain(tmp_path)).data["manifest"] is None


def test_the_report_holds_no_directory_of_the_auditing_machine(tmp_path):
    last, _mf = _survivor(tmp_path)
    text = build_report(last).to_json_bytes().decode()
    assert str(tmp_path) not in text and tmp_path.name not in text


# ── the verdict ``empty`` ───────────────────────────────────────────────────


def _empty(tmp_path):
    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    return p


def test_an_empty_container_is_empty_not_partial_and_not_sound(tmp_path):
    data = build_report(_empty(tmp_path)).data
    assert data["verdict"] == "empty"
    assert data["subject"]["records"] == 0 and data["chain"]["chain_ok"] is True
    _validate(data)


def test_an_empty_file_where_an_anchor_says_a_log_should_be_is_a_violation(tmp_path):
    data = build_report(_empty(tmp_path), anchor_source=ManualAnchor("11" * 32)).data
    assert data["verdict"] == "violation"
    assert data["diagnosis"]["pattern"] == "replaced_or_rolled_back"


def test_an_empty_file_is_not_sound_even_against_the_head_of_no_records(tmp_path):
    """The head of a chain with no records is 32 zero bytes. Supplied as the
    anchor, it is matched — and under ``/1`` that made an empty file "sound":
    everything checked, held, with nothing checked."""
    p = _empty(tmp_path)
    data = build_report(p, anchor_source=ManualAnchor("00" * 32)).data
    assert data["completeness"]["complete_to_anchor"] is True  # the fact stays visible
    assert data["verdict"] == "empty"
    as_v1 = dict(data, format=REPORT_FORMAT_1)
    assert derive_verdict(as_v1) == "sound"  # what /1 said, and why /2 does not


def test_bytes_that_are_no_container_are_a_violation_not_empty(tmp_path):
    p = tmp_path / "garbage.pala"
    p.write_bytes(b"not a container at all")
    data = build_report(p).data
    assert data["subject"]["records"] == 0
    assert data["verdict"] == "violation"


def test_one_record_is_enough_to_not_be_empty(tmp_path):
    p = tmp_path / "g.pala"
    with PalaWriter(p) as w:
        w.genesis()
    assert build_report(p).data["verdict"] == "partial"
    assert build_report(p, anchor_source=ManualAnchor(_head(p))).data["verdict"] == "sound"


# ── `pala verify` and the report cannot disagree ────────────────────────────


def _cases(tmp_path):
    chain = _chain(tmp_path)
    raw = chain.read_bytes()
    torn = tmp_path / "torn.pala"
    torn.write_bytes(raw[:-9])
    empty = _empty(tmp_path)
    return [
        (empty, None, "empty", 2),
        (empty, "11" * 32, "violation", 1),
        (empty, "00" * 32, "empty", 2),
        (chain, None, "partial", 2),
        (chain, _head(chain), "sound", 0),
        (chain, "22" * 32, "violation", 1),
        (torn, None, "violation", 1),
        (_violated(tmp_path), None, "violation", 1),
    ]


def test_pala_verify_and_the_report_give_one_verdict(tmp_path):
    for path, anchor, verdict, exit_code in _cases(tmp_path):
        args = ["pala", "verify", str(path), "--json"] + (["--anchor", anchor] if anchor else [])
        res = runner.invoke(app, args)
        payload = json.loads(res.output)
        report = build_report(
            path, anchor_source=ManualAnchor(anchor) if anchor else None
        ).data
        where = f"{path.name} anchor={anchor and anchor[:4]}"
        assert payload["verdict"] == report["verdict"] == verdict, where
        assert res.exit_code == payload["exit_code"] == exit_code, where


def test_pala_verify_does_not_call_an_empty_file_intact(tmp_path):
    res = runner.invoke(app, ["pala", "verify", str(_empty(tmp_path)), "--anchor", "00" * 32])
    assert res.exit_code == 2  # it was 0, "verified", before /2's rule
    assert "holds no records" in res.output and "chain intact" not in res.output


# ── /1 stays readable ───────────────────────────────────────────────────────


def test_the_repository_holds_stored_v1_reports_to_read():
    assert STORED_V1, "the run records' reports are this section's fixtures"
    for p in STORED_V1:
        assert json.loads(p.read_text(encoding="utf-8"))["format"] == REPORT_FORMAT_1


@pytest.mark.parametrize("path", STORED_V1, ids=lambda p: p.name)
def test_a_stored_v1_report_validates_rederives_and_renders(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    _validate(data, 1)  # against the /1 schema, which still ships
    assert derive_verdict(data) == data["verdict"]  # by the rule it was written under
    page = render_html(data)
    assert data["verdict"].upper() in page and REPORT_FORMAT_1 in page
    assert REPORT_FORMAT not in page  # the page names the format it was given


def test_a_v1_report_of_an_empty_container_keeps_its_word_and_the_right_gloss(tmp_path):
    """Rebuilt as 0.14 wrote it: ``partial``, with ``empty_container`` in the
    diagnosis. Reading it must not rewrite its verdict, and the page must
    still not call an empty file sound as far as checked."""
    data = build_report(_empty(tmp_path)).data
    v1 = {k: v for k, v in data.items() if k != "manifest"}
    v1["format"] = REPORT_FORMAT_1
    v1["chain"] = {k: v for k, v in data["chain"].items() if k != "violation_codes"}
    v1["diagnosis"] = {k: v for k, v in data["diagnosis"].items() if k != "code"}
    v1["verdict"] = derive_verdict(v1)
    assert v1["verdict"] == "partial"
    _validate(v1, 1)
    page = render_html(v1)
    assert "PARTIAL" in page and "sound as far as checked" not in page
    assert "holds no records" in page


# ── the page ────────────────────────────────────────────────────────────────


def test_the_page_shows_the_code_the_manifest_and_the_empty_verdict(tmp_path):
    page = render_html(build_report(_violated(tmp_path)).data)
    assert "<code>time_trust_undefined</code>" in page

    last, mf = _survivor(tmp_path)
    page = render_html(build_report(last).data)
    assert "Segments manifest" in page and mf.name in page
    assert sha256(mf.read_bytes()).hexdigest() in page

    page = render_html(build_report(_empty(tmp_path)).data)
    assert 'class="verdict v-empty"' in page and ".v-empty{" in page
    assert "Segments manifest" not in page


def test_every_verdict_has_a_colour_and_a_sentence():
    import palimpsests.audit.report_html as rh

    for v in VERDICTS:
        assert f".v-{v}{{" in rh._CSS and rh._VERDICT_MEANING[v]
