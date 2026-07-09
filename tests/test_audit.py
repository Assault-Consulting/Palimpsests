"""Tests for the audit subsystem."""
from __future__ import annotations

import pytest
import sqlite3
from palimpsests.audit import (
    GENESIS,
    AuditDenied,
    AuditIntegrityError,
    AuditLog,
    audited,
    generate_key,
    get_audit_log,
    set_audit_log,
)
from pathlib import Path

# ─── key management ──────────────────────────────────────────────────────


def test_generate_key_is_256_bit() -> None:
    key = generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_generate_key_is_unique() -> None:
    """Two calls must not collide — this is the whole point of a key."""
    assert generate_key() != generate_key()


# ─── AuditLog basics ─────────────────────────────────────────────────────


def test_record_and_read_back(audit_log: AuditLog) -> None:
    audit_log.record(
        operation="model.call",
        tool_name="local_chat",
        outcome="success",
        engine_id="ollama",
        model_locality="local",
    )
    [event] = audit_log.recent()
    assert event.operation == "model.call"
    assert event.tool_name == "local_chat"
    assert event.outcome == "success"
    assert event.engine_id == "ollama"
    assert event.model_locality == "local"
    assert event.data_class == "internal"  # default
    assert event.error_message is None


def test_recent_is_newest_first(audit_log: AuditLog) -> None:
    for i in range(3):
        audit_log.record(
            operation="model.call",
            tool_name=f"call_{i}",
            outcome="success",
        )
    events = audit_log.recent()
    assert [e.tool_name for e in events] == ["call_2", "call_1", "call_0"]


def test_recent_respects_limit(audit_log: AuditLog) -> None:
    for i in range(5):
        audit_log.record(
            operation="model.call", tool_name=f"c{i}", outcome="success"
        )
    assert len(audit_log.recent(limit=2)) == 2


def test_engine_id_is_nullable(audit_log: AuditLog) -> None:
    """Non-engine operations leave engine_id None."""
    audit_log.record(
        operation="engine.select", tool_name="set_engine", outcome="success"
    )
    [event] = audit_log.recent()
    assert event.engine_id is None


def test_persists_across_reopen(tmp_path: Path) -> None:
    """A reopened log sees prior rows — it's a real durable store."""
    key = generate_key()
    db = tmp_path / "audit.db"

    log1 = AuditLog(db, key, allow_unencrypted=True)
    log1.record(operation="model.call", tool_name="x", outcome="success")
    log1.close()

    log2 = AuditLog(db, key, allow_unencrypted=True)
    try:
        [event] = log2.recent()
        assert event.tool_name == "x"
    finally:
        log2.close()


# ─── encryption is not optional by accident ──────────────────────────────


def test_refuses_plaintext_by_default(tmp_path: Path, monkeypatch) -> None:
    """Without SQLCipher the constructor must fail, not write plaintext.

    A silently-unencrypted audit log is the failure mode this guards: the
    old code accepted the key, ignored it, and carried on.
    """
    import builtins

    real_import = builtins.__import__

    def _no_sqlcipher(name, *args, **kwargs):
        if name == "sqlcipher3":
            raise ImportError("simulated: no native SQLCipher build")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_sqlcipher)

    with pytest.raises(AuditIntegrityError, match="encrypted at rest"):
        AuditLog(tmp_path / "audit.db", generate_key())


def test_plaintext_allowed_when_explicit(tmp_path: Path) -> None:
    """The escape hatch exists, but the caller must ask for it by name."""
    log = AuditLog(tmp_path / "audit.db", generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="model.call", tool_name="x", outcome="success")
        assert len(log.recent()) == 1
    finally:
        log.close()


def test_anchor_every_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AuditLog(
            tmp_path / "a.db", generate_key(), allow_unencrypted=True, anchor_every=0
        )


# ─── the hash chain ──────────────────────────────────────────────────────


def _raw_rows(db: Path) -> list[tuple]:
    """Read the chain columns directly, bypassing AuditLog entirely.

    Tests that tamper must act like an attacker: through the file, not
    through the class whose API deliberately offers no mutation.
    """
    conn = sqlite3.connect(str(db))
    try:
        return conn.execute(
            "SELECT id, prev_hash, row_hash FROM audit_events ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()


def test_first_row_chains_from_genesis(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.db", generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="model.call", tool_name="x", outcome="success")
        rows = _raw_rows(tmp_path / "a.db")
        assert rows[0][1] == GENESIS
    finally:
        log.close()


def test_each_row_links_to_its_predecessor(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.db", generate_key(), allow_unencrypted=True)
    try:
        for i in range(4):
            log.record(operation="model.call", tool_name=f"c{i}", outcome="success")
        rows = _raw_rows(tmp_path / "a.db")
        # Pairwise neighbours: the offset slice is deliberately one shorter,
        # so strict=False is the intent, not an oversight.
        for prev_row, row in zip(rows, rows[1:], strict=False):
            assert row[1] == prev_row[2]  # prev_hash == predecessor's row_hash
    finally:
        log.close()


def test_verify_passes_on_untouched_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.db", generate_key(), allow_unencrypted=True)
    try:
        for i in range(3):
            log.record(operation="model.call", tool_name=f"c{i}", outcome="success")
        result = log.verify()
        assert result.ok
        assert result.rows_checked == 3
        assert result.head_anchored  # the fixture's in-memory keychain answered
        assert result.first_bad_row is None
    finally:
        log.close()


def test_verify_passes_on_empty_log(tmp_path: Path) -> None:
    """An empty log is trivially consistent; nothing is anchored yet."""
    log = AuditLog(tmp_path / "a.db", generate_key(), allow_unencrypted=True)
    try:
        result = log.verify()
        assert result.ok
        assert result.rows_checked == 0
        assert not result.head_anchored
    finally:
        log.close()


# ─── verification must not disturb what it inspects ──────────────────────


def test_open_and_close_without_writing_leaves_anchor_alone(
    tmp_path: Path, _isolated_keychain
) -> None:
    """A read-only session must not move the anchor.

    Otherwise `audit verify` — which opens the log, checks it, and closes
    — would re-anchor whatever chain is on disk, blessing a forged history
    and destroying the very evidence it was asked to examine.
    """
    db = tmp_path / "a.db"
    writer = AuditLog(db, generate_key(), allow_unencrypted=True)
    writer.record(operation="model.call", tool_name="x", outcome="success")
    writer.close()
    anchored = _isolated_keychain["anchor"]
    assert anchored is not None

    # An attacker rewrites history. The anchor still names the real head.
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE audit_events SET outcome='denied' WHERE id=1")
    conn.commit()
    conn.close()

    reader = AuditLog(db, generate_key(), allow_unencrypted=True)
    assert not reader.verify().ok
    reader.close()

    # The evidence survives the inspection.
    assert _isolated_keychain["anchor"] == anchored


# ─── the chain actually catches tampering ────────────────────────────────


def test_verify_detects_modified_row(tmp_path: Path) -> None:
    """Rewriting a field must be evident — this is the core claim."""
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="model.call", tool_name="a", outcome="denied")
        log.record(operation="model.call", tool_name="b", outcome="success")
    finally:
        log.close()

    # The attacker: flip a refusal into a success, leaving hashes alone.
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE audit_events SET outcome='success' WHERE tool_name='a'")
    conn.commit()
    conn.close()

    log2 = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        result = log2.verify()
        assert not result.ok
        assert result.first_bad_row == 1
        assert result.reason and "hash" in result.reason
    finally:
        log2.close()


def test_verify_detects_deleted_row(tmp_path: Path) -> None:
    """Excising an inconvenient event must break the chain."""
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        for i in range(3):
            log.record(operation="model.call", tool_name=f"c{i}", outcome="success")
    finally:
        log.close()

    conn = sqlite3.connect(str(db))
    conn.execute("DELETE FROM audit_events WHERE tool_name='c1'")
    conn.commit()
    conn.close()

    log2 = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        result = log2.verify()
        assert not result.ok
        # c2's prev_hash now points at a row that is no longer there.
        assert result.reason and "preceding row" in result.reason
    finally:
        log2.close()


def test_verify_detects_null_field_forgery(tmp_path: Path) -> None:
    """None and "" must hash differently, or a null can be forged into text."""
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="engine.select", tool_name="x", outcome="success")
    finally:
        log.close()

    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE audit_events SET engine_id='' WHERE id=1")
    conn.commit()
    conn.close()

    log2 = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        assert not log2.verify().ok
    finally:
        log2.close()


def test_verify_detects_wholesale_replacement(
    tmp_path: Path, _isolated_keychain
) -> None:
    """A rebuilt-from-scratch chain is internally valid but not *ours*.

    This is what the head anchor exists for: the attacker drops the table
    and writes a fresh, perfectly-chained history. Only the out-of-band
    anchor reveals that the head moved to something we never wrote.

    The attacker is modelled as *not* holding keychain write access — the
    boundary stated in SECURITY.md — so after the forged writes we restore
    the anchor the legitimate process last stored.
    """
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="model.call", tool_name="incriminating", outcome="denied")
    finally:
        log.close()

    real_anchor = _isolated_keychain["anchor"]
    assert real_anchor is not None

    db.unlink()
    forged = AuditLog(db, generate_key(), allow_unencrypted=True)
    forged.record(operation="model.call", tool_name="innocuous", outcome="success")
    forged.close()
    _isolated_keychain["anchor"] = real_anchor  # attacker cannot reach the keychain

    log2 = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        result = log2.verify()
        assert not result.ok
        assert result.head_anchored
        assert result.reason and "replaced" in result.reason
    finally:
        log2.close()


def test_verify_reports_when_anchor_unavailable(tmp_path: Path, monkeypatch) -> None:
    """No keychain: the chain still verifies, but say so plainly.

    A passing verify() with head_anchored=False must never be read as the
    full guarantee — the flag is how an auditor can tell the difference.
    """
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True)
    try:
        log.record(operation="model.call", tool_name="x", outcome="success")
        monkeypatch.setattr("palimpsests.audit.log.load_head_anchor", lambda: None)
        result = log.verify()
        assert result.ok
        assert not result.head_anchored
        assert result.reason and "would not be detected" in result.reason
    finally:
        log.close()


def test_anchor_every_batches_updates(tmp_path: Path, _isolated_keychain) -> None:
    """With anchor_every=3 the anchor trails the chain until the batch closes."""
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True, anchor_every=3)
    try:
        log.record(operation="model.call", tool_name="a", outcome="success")
        assert _isolated_keychain["anchor"] is None  # not yet
        log.record(operation="model.call", tool_name="b", outcome="success")
        assert _isolated_keychain["anchor"] is None
        log.record(operation="model.call", tool_name="c", outcome="success")
        assert _isolated_keychain["anchor"] is not None  # batch closed
    finally:
        log.close()


def test_close_flushes_the_anchor(tmp_path: Path, _isolated_keychain) -> None:
    """A clean shutdown must not leave chained-but-unanchored rows."""
    db = tmp_path / "a.db"
    log = AuditLog(db, generate_key(), allow_unencrypted=True, anchor_every=100)
    log.record(operation="model.call", tool_name="a", outcome="success")
    assert _isolated_keychain["anchor"] is None
    log.close()
    assert _isolated_keychain["anchor"] is not None


# ─── @audited decorator ──────────────────────────────────────────────────


def test_audited_records_success(audit_log: AuditLog) -> None:
    @audited("model.call", model_locality="local")
    def do_work() -> dict:
        return {"status": "ok"}

    result = do_work()
    assert result == {"status": "ok"}

    [event] = audit_log.recent()
    assert event.tool_name == "do_work"
    assert event.operation == "model.call"
    assert event.outcome == "success"
    assert event.model_locality == "local"


def test_audited_records_denied_and_reraises(audit_log: AuditLog) -> None:
    @audited("model.call")
    def gated() -> dict:
        raise AuditDenied("capability disabled")

    with pytest.raises(AuditDenied):
        gated()

    [event] = audit_log.recent()
    assert event.outcome == "denied"
    assert event.error_message and "disabled" in event.error_message


def test_audited_records_error_and_reraises(audit_log: AuditLog) -> None:
    @audited("model.call")
    def broken() -> dict:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        broken()

    [event] = audit_log.recent()
    assert event.outcome == "error"
    # Concrete class name is captured for actionable review.
    assert event.error_message and "ValueError" in event.error_message


def test_audited_events_are_chained(audit_log: AuditLog) -> None:
    """Events written through the decorator join the same chain."""

    @audited("model.call")
    def work() -> dict:
        return {}

    work()
    work()
    result = audit_log.verify()
    assert result.ok
    assert result.rows_checked == 2


def test_audited_preserves_function_name(audit_log: AuditLog) -> None:
    """functools.wraps keeps __name__ so tool_name is stable."""

    @audited("model.call")
    def my_specific_name() -> dict:
        return {}

    assert my_specific_name.__name__ == "my_specific_name"
    my_specific_name()
    [event] = audit_log.recent()
    assert event.tool_name == "my_specific_name"


def test_audited_tolerates_missing_log() -> None:
    """No log installed -> the call still runs, nothing recorded."""
    set_audit_log(None)

    @audited("model.call")
    def work() -> dict:
        return {"status": "ok"}

    assert work() == {"status": "ok"}  # does not raise


def test_audited_missing_log_still_reraises_denied() -> None:
    """Even with no log, AuditDenied must propagate — the refusal is
    behavioral, not just a log entry."""
    set_audit_log(None)

    @audited("model.call")
    def gated() -> dict:
        raise AuditDenied("no")

    with pytest.raises(AuditDenied):
        gated()


# ─── singleton ───────────────────────────────────────────────────────────


def test_singleton_get_set(audit_log: AuditLog) -> None:
    assert get_audit_log() is audit_log


def test_singleton_defaults_none() -> None:
    set_audit_log(None)
    assert get_audit_log() is None
