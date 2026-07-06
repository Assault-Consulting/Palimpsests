"""Tests for the audit subsystem."""
from __future__ import annotations

from pathlib import Path

import pytest

from palimpsests.audit import (
    AuditDenied,
    AuditLog,
    audited,
    generate_key,
    get_audit_log,
    set_audit_log,
)


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

    log1 = AuditLog(db, key)
    log1.record(operation="model.call", tool_name="x", outcome="success")
    log1.close()

    log2 = AuditLog(db, key)
    try:
        [event] = log2.recent()
        assert event.tool_name == "x"
    finally:
        log2.close()


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
