# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The serve can cut its chain into segments, and finds its way back into one.

The writer has rotated since 0.11. The serve could not ask for it: its
chain was always the one file ``serve.pala``, kept whole or lost whole —
so the retention described for a chain that lives for months
(``docs/RETENTION.md``) was out of reach of the one program most likely
to write such a chain.

The part that needs the most care is the restart. Once a chain is cut,
``serve.pala`` is a closed segment; a serve that opened it again and
appended would fork the chain it is the recorder of.
"""
from __future__ import annotations

import json
import os
import pytest
import subprocess
import sys
from palimpsests.audit.pala_writer import RotationPolicy
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.segment_set import verify_segment_set
from palimpsests.server.chain_config import (
    RETENTION_VAR,
    ROTATE_AGE_VAR,
    ROTATE_BYTES_VAR,
    ROTATE_RECORDS_VAR,
    live_chain_path,
    rotation_from_env,
)

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.cli import app as cli  # noqa: E402
from palimpsests.server.openai_api import (  # noqa: E402
    ServeChainUnavailable,
    create_app,
    default_audit,
)
from typer.testing import CliRunner  # noqa: E402

ALL = (ROTATE_BYTES_VAR, ROTATE_RECORDS_VAR, ROTATE_AGE_VAR, RETENTION_VAR)


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    for name in ALL:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _run(calls: int = 5):
    """One life of a serve: open, record some pairs, close. Returns the
    name of the file it was writing when it stopped."""
    audit = default_audit()
    for _ in range(calls):
        seq, rh = audit.tool_called("t", None, None)
        audit.tool_result(seq, rh, 0, None, None)
    name = os.path.basename(audit.writer.path)
    audit.writer.close()
    return name


def _manifest(config):
    return config / "serve.pala.segments.json"


# -- reading the settings ------------------------------------------------------

@pytest.mark.parametrize("env, expected", [
    ({}, None),
    ({ROTATE_BYTES_VAR: "  "}, None),
    ({ROTATE_BYTES_VAR: "4096"}, RotationPolicy(max_bytes=4096)),
    ({ROTATE_BYTES_VAR: "16MiB"}, RotationPolicy(max_bytes=16 << 20)),
    ({ROTATE_BYTES_VAR: "2 gib"}, RotationPolicy(max_bytes=2 << 30)),
    ({ROTATE_BYTES_VAR: "512KiB"}, RotationPolicy(max_bytes=512 << 10)),
    ({ROTATE_RECORDS_VAR: "100000"}, RotationPolicy(max_records=100000)),
    ({ROTATE_AGE_VAR: "7d"}, RotationPolicy(max_age_s=604800.0)),
    ({ROTATE_AGE_VAR: "90"}, RotationPolicy(max_age_s=90.0)),
    ({ROTATE_AGE_VAR: "12h", RETENTION_VAR: "180d"},
     RotationPolicy(max_age_s=43200.0, retention_s=15552000)),
    ({ROTATE_BYTES_VAR: "1MiB", ROTATE_RECORDS_VAR: "5000", RETENTION_VAR: "0"},
     RotationPolicy(max_bytes=1 << 20, max_records=5000, retention_s=0)),
])
def test_the_policy_the_environment_asks_for(env, expected):
    assert rotation_from_env(env) == expected


@pytest.mark.parametrize("env, named", [
    ({ROTATE_BYTES_VAR: "sixteen"}, ROTATE_BYTES_VAR),
    ({ROTATE_BYTES_VAR: "16MB"}, ROTATE_BYTES_VAR),  # MiB is meant; MB is not guessed
    ({ROTATE_BYTES_VAR: "1.5GiB"}, ROTATE_BYTES_VAR),
    ({ROTATE_BYTES_VAR: "-1"}, ROTATE_BYTES_VAR),
    ({ROTATE_BYTES_VAR: "0"}, "max_bytes"),
    ({ROTATE_RECORDS_VAR: "1k"}, ROTATE_RECORDS_VAR),
    ({ROTATE_AGE_VAR: "1w"}, ROTATE_AGE_VAR),
    ({ROTATE_AGE_VAR: "0"}, "max_age_s"),
    ({ROTATE_BYTES_VAR: "1MiB", RETENTION_VAR: "six months"}, RETENTION_VAR),
    ({RETENTION_VAR: "180d"}, "never cut"),  # a floor for segments that are never made
])
def test_a_setting_that_cannot_be_read_is_an_error_that_names_it(env, named):
    with pytest.raises(ValueError, match=named):
        rotation_from_env(env)


def test_a_typo_stops_the_serve_and_does_not_become_no_rotation(config, monkeypatch):
    monkeypatch.setenv(ROTATE_BYTES_VAR, "16MB")
    with pytest.raises(ServeChainUnavailable, match=ROTATE_BYTES_VAR):
        default_audit()
    assert not (config / "serve.pala").exists()  # nothing was started


# -- one file, as before -------------------------------------------------------

def test_without_the_settings_the_chain_is_one_file(config):
    assert [_run() for _ in range(3)] == ["serve.pala"] * 3
    assert not _manifest(config).exists()
    assert sorted(p.name for p in config.iterdir() if p.suffix != ".lock") == ["serve.pala"]
    with AuditReader.open(config / "serve.pala") as r:
        assert r.verify().chain.chain_ok and len(r.boots()) == 3


# -- cut, and continued across restarts ----------------------------------------

def test_a_rotating_serve_continues_its_live_segment_across_restarts(config, monkeypatch):
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    monkeypatch.setenv(RETENTION_VAR, "30d")
    written = [_run() for _ in range(4)]
    assert written[0] != "serve.pala" and written == sorted(written)
    assert len(set(written)) == 4  # each life moved on to later segments
    result = verify_segment_set(_manifest(config))
    assert result.consistent and result.complete
    assert [c.file for c in result.segments][0] == "serve.pala"
    assert result.segments[-1].file == written[-1] and not result.segments[-1].listed
    # one chain: the seq runs on through every segment and every restart
    listed = [c for c in result.segments if c.listed]
    assert [c.declared_first_seq for c in listed[1:]] == [
        c.declared_last_seq + 1 for c in listed[:-1]]
    # the declared retention is in the chain, at every cut
    with AuditReader.open(config / written[-1]) as r:
        first = next(iter(r.records()))
        assert first.kind_name == "SEGMENT_CONTINUATION"
        assert first.header.seq == listed[-1].declared_last_seq + 1
    manifest = json.loads(_manifest(config).read_text())
    assert manifest["rotation"] == {"max_records": 6}


def test_the_first_file_is_never_reopened_once_the_chain_is_cut(config, monkeypatch):
    """The fork this is all about."""
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    _run()
    first = (config / "serve.pala").read_bytes()
    for _ in range(3):
        _run()
    assert (config / "serve.pala").read_bytes() == first


def test_removing_the_settings_stops_the_cuts_and_nothing_else(config, monkeypatch):
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    live = [_run() for _ in range(2)][-1]
    files = sorted(p.name for p in config.iterdir())
    first = (config / "serve.pala").read_bytes()
    monkeypatch.delenv(ROTATE_RECORDS_VAR)
    assert [_run(20) for _ in range(2)] == [live, live]  # the same segment, however long
    assert sorted(p.name for p in config.iterdir()) == files
    assert (config / "serve.pala").read_bytes() == first
    result = verify_segment_set(_manifest(config))
    assert result.consistent and result.complete
    # and asking again takes up where it left off
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    assert _run() > live
    assert verify_segment_set(_manifest(config)).complete


def test_a_segment_deleted_under_retention_leaves_the_serve_able_to_start(config,
                                                                          monkeypatch):
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    monkeypatch.setenv(RETENTION_VAR, "0")
    for _ in range(3):
        _run()
    # the operator deletes the two oldest segments — the first file among them
    (config / "serve.pala").unlink()
    (config / "serve.pala.00001").unlink()
    live = _run()
    assert live != "serve.pala" and not (config / "serve.pala").exists()
    result = verify_segment_set(_manifest(config))
    assert result.consistent and not result.complete
    assert result.absent == ["serve.pala", "serve.pala.00001"]


def test_a_manifest_without_a_segment_to_continue_stops_the_serve(config, monkeypatch):
    """The newest segments are gone — deleted, or not restored with the
    rest. Starting at serve.pala would append to a closed segment;
    starting a new serve.pala would be a second chain under the old one's
    manifest."""
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    live = [_run() for _ in range(2)][-1]
    last_closed = json.loads(_manifest(config).read_text())["segments"][-1]["file"]
    (config / live).unlink()
    (config / last_closed).unlink()
    before = {p.name: p.read_bytes() for p in config.iterdir() if p.is_file()}
    with pytest.raises(ServeChainUnavailable, match="second history"):
        default_audit()
    monkeypatch.delenv(ROTATE_RECORDS_VAR)
    with pytest.raises(ServeChainUnavailable, match="second history"):
        default_audit()
    assert {p.name: p.read_bytes() for p in config.iterdir() if p.is_file()} == before


def test_a_manifest_that_is_not_one_stops_the_serve(config):
    _run()
    _manifest(config).write_text("{not json")
    with pytest.raises(ServeChainUnavailable, match="cannot be read"):
        default_audit()
    _manifest(config).write_text(json.dumps({"format": "something-else/1", "segments": []}))
    with pytest.raises(ServeChainUnavailable, match="is not a pala-segments/1 manifest"):
        default_audit()


def test_with_no_live_segment_the_last_closed_one_is_continued(config, monkeypatch):
    """The manifest records the closed segment before the successor
    appears. A crash between the two leaves no live segment; the last
    listed file is the one to continue, and the writer undoes the cut.

    A live segment that existed and was deleted leaves the same files. The
    two cannot be told apart from the disk, and the second is a truncated
    tail — which, as for a chain in one file, only an anchor kept outside
    can show. The chain that results verifies; it is shorter than it was."""
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    live = _run()
    manifest = json.loads(_manifest(config).read_text())
    listed_last = manifest["segments"][-1]["file"]
    assert live != listed_last
    (config / live).unlink()
    assert live_chain_path(config / "serve.pala") == config / listed_last
    resumed = _run()
    assert resumed >= listed_last
    result = verify_segment_set(_manifest(config))
    assert result.consistent and result.complete


def test_live_chain_path_is_the_first_file_until_there_is_a_manifest(config):
    assert live_chain_path(config / "serve.pala") == config / "serve.pala"
    _manifest(config).write_text(json.dumps({"format": "pala-segments/1", "segments": []}))
    assert live_chain_path(config / "serve.pala") == config / "serve.pala"


# -- what the operator sees ----------------------------------------------------

def test_the_status_names_the_segment_and_the_policy(config, monkeypatch):
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    monkeypatch.setenv(ROTATE_BYTES_VAR, "1MiB")
    monkeypatch.setenv(RETENTION_VAR, "180d")
    audit = default_audit()
    client = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                   audit=audit))
    chain = client.get("/v1/pala/status").json()["chain"]
    assert chain["segment"] == "serve.pala"
    assert chain["rotation"] == {"max_bytes": 1 << 20, "max_records": 6,
                                 "retention_s": 15552000}
    for i in range(6):
        client.post("/v1/pala/events", json={"events": [
            {"type": "tool_call", "id": f"c{i}", "name": "t"}]})
    assert client.get("/v1/pala/status").json()["chain"]["segment"] != "serve.pala"
    audit.writer.close()
    assert verify_segment_set(_manifest(config)).complete


def test_the_entry_point_names_the_setting_and_exits_without_a_traceback(config):
    pytest.importorskip("uvicorn")  # the entry point imports it before it opens the chain
    env = {**os.environ, "PALIMPSESTS_CONFIG_DIR": str(config), ROTATE_BYTES_VAR: "16MB",
           "PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT": "1"}
    proc = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.argv = ['palimpsests-serve', '--port', '0']; "
         "from palimpsests.server.openai_api import main; main()"],
        capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 1 and ROTATE_BYTES_VAR in proc.stderr
    assert "Traceback" not in proc.stderr


# -- the command ---------------------------------------------------------------

def test_segment_verify_answers_complete_consistent_inconsistent_unreadable(config,
                                                                            monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv(ROTATE_RECORDS_VAR, "6")
    for _ in range(3):
        _run()
    manifest = str(_manifest(config))

    ok = runner.invoke(cli, ["pala", "segment-verify", manifest])
    assert ok.exit_code == 0 and "COMPLETE" in ok.output and "being written" in ok.output
    doc = json.loads(runner.invoke(cli, ["pala", "segment-verify", manifest,
                                         "--json"]).output)
    assert doc["format"] == "pala-segment-set-verification/1"
    assert doc["verdict"] == "complete" and doc["complete"] and doc["consistent"]
    assert doc["segments"][0]["file"] == "serve.pala" and not doc["segments"][-1]["listed"]
    assert len(doc["head"]) == 64 and len(doc["manifest_sha256"]) == 64

    (config / "serve.pala.00001").unlink()  # retention
    part = runner.invoke(cli, ["pala", "segment-verify", manifest])
    assert part.exit_code == 2 and "CONSISTENT, NOT COMPLETE" in part.output
    assert "absent" in part.output
    doc = json.loads(runner.invoke(cli, ["pala", "segment-verify", manifest,
                                         "--json"]).output)
    assert doc["verdict"] == "consistent" and doc["absent"] == ["serve.pala.00001"]

    target = config / "serve.pala.00002"
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    target.write_bytes(bytes(raw))
    bad = runner.invoke(cli, ["pala", "segment-verify", manifest])
    assert bad.exit_code == 1 and "INCONSISTENT" in bad.output and "FAILS" in bad.output

    junk = config / "junk.json"
    junk.write_text("{}")
    assert runner.invoke(cli, ["pala", "segment-verify", str(junk)]).exit_code == 3
    assert runner.invoke(cli, ["pala", "segment-verify",
                               str(config / "nothing.json")]).exit_code == 3


@pytest.mark.parametrize(("value", "printed"), [
    (16 << 20, "16777216"),
    (2 << 30, "2147483648"),
    (20, "20"),
    (604800.0, "604800"),
    (0.5, "0.5"),
])
def test_start_up_line_prints_a_threshold_in_full(value, printed) -> None:
    from palimpsests.server.openai_api import _threshold

    assert _threshold(value) == printed
