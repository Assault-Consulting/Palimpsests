# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Hardening of the audit stores against concurrency and leakage.

Two writers must not fork a chain; a writer closing must not roll an
anchor back; a serve must not start without its chain; credentials
must not reach a hash-chained field; the level-2 server must answer
only the process that launched it.
"""
from __future__ import annotations

import logging
import pytest
import subprocess
import sys
import textwrap

# ── child processes are separate interpreters running a short script.
# Not multiprocessing: its spawn start method re-imports the *test module*
# in every child, by the dotted name pytest gave it under importlib mode
# ("tests.test_…"). In CI, on Linux and Windows alike, that package is not
# on the children's path — they died with "No module named 'tests'" before
# writing a row, while the same test passed when run from the repository
# root. A plain script imports only the package, and its stderr is
# reported whole on failure.

_APPEND_SCRIPT = """
import sys, time
from pathlib import Path
from palimpsests.audit.log import AuditLog

db, n, go = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
log = AuditLog(Path(db), b"\\\\x01" * 32, allow_unencrypted=True)
deadline = time.monotonic() + 30
while not go.exists():  # released together, to make the race as likely as it gets
    if time.monotonic() > deadline:
        sys.exit("start signal never came")
    time.sleep(0.005)
for i in range(n):
    log.record(operation="op", tool_name=f"t{i}", outcome="success")
log.close()
"""


# ── 1. the operations log: several processes, one linear chain ─────────────


def test_processes_appending_to_one_log_keep_one_linear_chain(tmp_path):
    from palimpsests.audit.log import AuditLog

    db = tmp_path / "audit.db"
    AuditLog(db, b"\x01" * 32, allow_unencrypted=True).close()  # create schema
    go = tmp_path / "go"
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _APPEND_SCRIPT, str(db), "150", str(go)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(4)
    ]
    go.touch()
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, f"a writer process failed:\n{err}"
    log = AuditLog(db, b"\x01" * 32, allow_unencrypted=True)
    result = log.verify()
    log.close()
    assert result.ok, result
    assert result.rows_checked == 600


def test_closing_does_not_roll_the_anchor_back(tmp_path, monkeypatch):
    import palimpsests.audit.log as logmod

    anchors: list[str] = []
    monkeypatch.setattr(logmod, "store_head_anchor", lambda h, **k: anchors.append(h) or True)
    db = tmp_path / "audit.db"
    a = logmod.AuditLog(db, b"\x01" * 32, allow_unencrypted=True)
    b = logmod.AuditLog(db, b"\x01" * 32, allow_unencrypted=True)
    a.record(operation="op", tool_name="a1", outcome="success")
    b.record(operation="op", tool_name="b1", outcome="success")
    newest = anchors[-1]
    a.close()  # a's own row is no longer the head: it must not be re-anchored
    assert anchors[-1] == newest
    b.close()
    assert anchors[-1] == newest


# ── 2. the PALA-1 writer: one writer per chain ─────────────────────────────


def test_a_second_writer_on_a_chain_is_refused_until_the_first_closes(tmp_path):
    from palimpsests.audit.pala_writer import ChainLocked, PalaWriter

    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    with pytest.raises(ChainLocked, match="would fork it"):
        PalaWriter.open_existing(p)
    w.close()
    w2 = PalaWriter.open_existing(p)  # free again
    w2.boot()
    w2.close()


def test_the_lock_is_taken_before_a_torn_tail_is_truncated(tmp_path):
    from palimpsests.audit.pala_writer import ChainLocked, PalaWriter

    p = tmp_path / "c.pala"
    w = PalaWriter(p)
    w.genesis()
    with open(p, "ab") as fh:  # bytes another writer is in the middle of
        fh.write(b"PALA" + b"\x00" * 20)
    size = p.stat().st_size
    with pytest.raises(ChainLocked):
        PalaWriter.open_existing(p)
    assert p.stat().st_size == size  # nothing was truncated under the writer
    w.close()


def test_every_segment_of_a_rotated_chain_shares_one_lock(tmp_path):
    from palimpsests.audit.pala_writer import ChainLocked, PalaWriter, RotationPolicy

    base = tmp_path / "w.pala"
    w = PalaWriter(base, rotation=RotationPolicy(max_records=3))
    w.genesis()
    for _ in range(4):
        w.prefix_warm(token_count=1)
    segment = sorted(tmp_path.glob("w.pala.0*"))[-1]
    with pytest.raises(ChainLocked):
        PalaWriter.open_existing(segment)
    w.close()


def test_another_process_is_refused_and_named(tmp_path):
    from palimpsests.audit.pala_writer import ChainLocked, PalaWriter

    p = tmp_path / "c.pala"
    holder = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(f"""
            import sys, time
            from palimpsests.audit.pala_writer import PalaWriter
            w = PalaWriter({str(p)!r}); w.genesis()
            print("held", flush=True); time.sleep(30)
        """)],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(ChainLocked, match=rf"pid {holder.pid}"):
            PalaWriter.open_existing(p)
    finally:
        holder.kill()
        holder.wait()
    PalaWriter.open_existing(p).close()  # released when the holder died


# ── 3. the serve does not start without its chain ──────────────────────────


def test_a_second_serve_on_one_config_dir_refuses_and_says_what_to_do(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from palimpsests.server.openai_api import ServeChainUnavailable, default_audit

    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    first = default_audit()
    try:
        with pytest.raises(ServeChainUnavailable, match="PALIMPSESTS_CONFIG_DIR"):
            default_audit()
    finally:
        first.writer.close()


def test_a_damaged_serve_chain_refuses_rather_than_serving_without_it(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from palimpsests.server.openai_api import ServeChainUnavailable, default_audit

    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    (tmp_path / "serve.pala").write_bytes(b"not a chain at all")
    with pytest.raises(ServeChainUnavailable, match="pala verify"):
        default_audit()


# ── 4. credentials never reach a hash-chained field ────────────────────────


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("401 for url 'https://api.x.com/v1?api_key=S3CR3T&page=2'", "S3CR3T"),
        ("Authorization: Bearer sk-abcdefghijklmnop0123", "sk-abcdefghijklmnop0123"),
        ('{"token": "abc.def.ghi", "user": "bob"}', "abc.def.ghi"),
        ("connect postgres://admin:hunter2@db:5432/x failed", "hunter2"),
        ("password=hunter2; retry", "hunter2"),
        ("pushed with ghp_0123456789abcdefghijABCDEFGHIJ", "ghp_0123456789abcdefghijABCDEFGHIJ"),
        ("AKIAABCDEFGHIJKLMNOP denied", "AKIAABCDEFGHIJKLMNOP"),
    ],
)
def test_credentials_are_scrubbed(text, secret):
    from palimpsests.audit.redact import REDACTED, scrub_secrets

    out = scrub_secrets(text)
    assert secret not in out and REDACTED in out


@pytest.mark.parametrize(
    "text",
    ["model not found: qwen2.5:7b", "timeout talking to 127.0.0.1:11434",
     "KeyError: 'tokens_decode'", "context 8192 exceeds 4096"],
)
def test_ordinary_messages_are_left_alone(text):
    from palimpsests.audit.redact import scrub_secrets

    assert scrub_secrets(text) == text


def test_the_operations_log_stores_the_scrubbed_message(tmp_path):
    from palimpsests.audit.log import AuditLog

    log = AuditLog(tmp_path / "a.db", b"\x01" * 32, allow_unencrypted=True)
    # the credential sits past the first 30 chars and well inside the 200-char clip
    log.record(operation="op", tool_name="t", outcome="error",
               error_message="HTTPStatusError 401 Unauthorized for https://h/x?token=S3CR3T")
    stored = log._conn.execute("SELECT error_message FROM audit_events").fetchone()[0]
    log.close()
    assert "S3CR3T" not in stored and "[REDACTED]" in stored


def test_evt_detail_is_scrubbed_before_it_is_chained(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader

    p = tmp_path / "c.pala"
    with PalaWriter(p) as w:
        w.genesis()
        w.guard_state_reject(detail="restore failed: GET https://kv/x?token=S3CR3T -> 403")
    with AuditReader.open(p) as r:
        details = [d.detail for d in r.records() if d.detail]
    assert details and all("S3CR3T" not in d for d in details)


# ── 5. the level-2 server answers only its launcher ────────────────────────


def test_the_key_goes_through_the_environment_not_the_command_line(tmp_path, monkeypatch):
    import palimpsests.providers.process as procmod

    model = tmp_path / "m.gguf"
    model.write_bytes(b"x")
    seen: dict = {}

    class _Proc:
        returncode = None

        def poll(self):
            return None

    def fake_popen(argv, **kw):
        seen["argv"], seen["env"] = argv, kw.get("env") or {}
        return _Proc()

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    monkeypatch.setattr(procmod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(procmod.httpx, "get",
                        lambda url, **k: _Resp(401 if url.endswith("/v1/models") else 200))
    srv = procmod.LlamaServerProcess(binary="llama-server", model_path=str(model))
    srv.start()
    assert srv.api_key not in " ".join(seen["argv"])
    assert seen["env"]["LLAMA_API_KEY"] == srv.api_key
    assert srv.auth_enforced is True


def test_a_server_that_ignores_the_key_is_named_in_the_log(tmp_path, monkeypatch, caplog):
    import palimpsests.providers.process as procmod

    model = tmp_path / "m.gguf"
    model.write_bytes(b"x")

    class _Proc:
        returncode = None

        def poll(self):
            return None

    class _Resp:
        status_code = 200

    monkeypatch.setattr(procmod.subprocess, "Popen", lambda *a, **k: _Proc())
    monkeypatch.setattr(procmod.httpx, "get", lambda *a, **k: _Resp())
    srv = procmod.LlamaServerProcess(binary="llama-server", model_path=str(model))
    with caplog.at_level(logging.WARNING, logger="palimpsests.providers.process"):
        srv.start()
    assert srv.auth_enforced is False
    assert "LLAMA_API_KEY" in caplog.text


# ── 6. the audit key is the size it claims to be ───────────────────────────


def test_a_short_key_is_refused(tmp_path):
    from palimpsests.audit.log import AuditLog

    with pytest.raises(ValueError, match="32 bytes"):
        AuditLog(tmp_path / "a.db", b"\x01" * 16, allow_unencrypted=True)


@pytest.mark.parametrize("stored", ["00" * 16, "00" * 33, "zz" * 32])
def test_a_keychain_entry_of_the_wrong_size_is_refused(stored):
    from palimpsests.audit.key_manager import _key_from_hex

    with pytest.raises(ValueError):
        _key_from_hex(stored)
